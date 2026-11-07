"""Password verifier checks after NIST SP 800-63B-4.

Provides NIST SP 800-63B-4 compliant password validation: length calculated
by code points after NFKC normalization, blocklist and context-word matching,
repetition and sequence checks, and a k-anonymity breach lookup port compatible
with Have I Been Pwned range queries.

Threat Model Summary:
- Defended: full hash disclosure to the range service (only a 5-character hex
  prefix is ever transmitted via k-anonymity), password or hash leakage in
  repr(), logging, or event notifications, and NFKC expansion denial-of-service
  attacks (input over 4,096 code points rejected without normalization).
- Not defended: range service inferring prefix traffic patterns, password
  storage hashing (e.g. Argon2id / scrypt), online guessing / rate limiting,
  and side-channel traffic analysis.
"""

from __future__ import annotations

import hashlib
import logging
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "PasswordPolicy",
    "PolicyError",
    "RangeSource",
    "Verdict",
    "__version__",
    "check_password",
    "sha1_parts",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

MAX_INPUT_CODE_POINTS: int = 4_096
MAX_RANGE_REPLY_BYTES: int = 1_048_576


class PolicyError(Exception):
    """Raised when a PasswordPolicy configuration is invalid."""

    def __init__(self, message: str, *, code: str = "invalid_policy") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PasswordPolicy:
    """NIST SP 800-63B-4 password policy configuration.

    Attributes:
        min_length: Minimum character length (8 <= min_length <= max_length).
            Default is 15 (single-factor). Use 8 for multi-factor.
        max_length: Maximum character length (>= 64). Default is 128.
        blocklist: Set of forbidden passwords (dictionary, common, known compromised).
        check_repetition: Whether to check for repeated units (1-3 chars) or sequential runs.
        breach_threshold: Number of occurrences in breach database to consider breached (>= 1).
        on_breach_error: Action when range source fails: 'fail_closed' or 'fail_open'.
    """

    min_length: int = 15
    max_length: int = 128
    blocklist: frozenset[str] = frozenset()
    check_repetition: bool = True
    breach_threshold: int = 1
    on_breach_error: Literal["fail_closed", "fail_open"] = "fail_closed"

    def __post_init__(self) -> None:
        if self.min_length < 8:
            raise PolicyError("min_length must be at least 8", code="invalid_policy")
        if self.max_length < 64:
            raise PolicyError("max_length must be at least 64", code="invalid_policy")
        if self.min_length > self.max_length:
            raise PolicyError("min_length cannot exceed max_length", code="invalid_policy")
        if self.breach_threshold < 1:
            raise PolicyError("breach_threshold must be at least 1", code="invalid_policy")
        if self.on_breach_error not in ("fail_closed", "fail_open"):
            raise PolicyError(
                "on_breach_error must be 'fail_closed' or 'fail_open'", code="invalid_policy"
            )


@dataclass(frozen=True)
class Verdict:
    """Result of a password evaluation against policy."""

    ok: bool
    violations: tuple[str, ...]
    warnings: tuple[str, ...]
    length: int
    breach_count: int | None

    def __repr__(self) -> str:
        return (
            f"Verdict(ok={self.ok!r}, violations={self.violations!r}, "
            f"warnings={self.warnings!r}, length={self.length!r}, "
            f"breach_count={self.breach_count!r})"
        )


@runtime_checkable
class RangeSource(Protocol):
    """Port for fetching k-anonymity SHA-1 hash ranges."""

    def fetch_range(self, prefix: str) -> str:
        """Return lines of SUFFIX:COUNT separated by LF or CRLF for the 5-hex prefix."""
        ...


def sha1_parts(password: str) -> tuple[str, str]:
    """Compute SHA-1 over UTF-8 bytes of password and split into (prefix5, suffix35).

    Returns uppercase hex strings matching the Have I Been Pwned range API convention.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    return digest[:5], digest[5:]


def _is_repetitive(text: str) -> bool:
    """Check if text is repetitive or sequential (length >= 4).

    Checks:
    1. Repeated unit of 1, 2, or 3 characters (e.g. 'aaaa', 'abababab', 'abcabcabc').
    2. Sequential code points where every adjacent pair differs by +1 ('abcd') or -1 ('dcba').
    """
    if len(text) < 4:
        return False

    # Check repeated units of length 1, 2, 3
    for unit_len in (1, 2, 3):
        unit = text[:unit_len]
        repeats = len(text) // unit_len
        rem = len(text) % unit_len
        expected = unit * repeats + unit[:rem]
        if text == expected:
            return True

    # Check sequential runs of code points
    diffs = [ord(text[i + 1]) - ord(text[i]) for i in range(len(text) - 1)]
    if all(d == 1 for d in diffs):
        return True
    return bool(all(d == -1 for d in diffs))


def check_password(
    password: str,
    policy: PasswordPolicy,
    *,
    context: Sequence[str] = (),
    breach: RangeSource | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> Verdict:
    """Validate a password against a PasswordPolicy.

    Violation codes in fixed order:
    'too_short', 'too_long', 'blocklisted', 'context_word',
    'repetitive', 'breached', 'breach_check_unavailable'.
    """
    # Bound NFKC expansion DOS check
    raw_len = len(password)
    if raw_len > MAX_INPUT_CODE_POINTS:
        verdict = Verdict(
            ok=False,
            violations=("too_long",),
            warnings=(),
            length=raw_len,
            breach_count=None,
        )
        if on_event is not None:
            on_event(
                {
                    "event": "password_checked",
                    "ok": verdict.ok,
                    "violations": list(verdict.violations),
                    "breach_lookup": "skipped",
                }
            )
        return verdict

    norm_pwd = unicodedata.normalize("NFKC", password)
    norm_len = len(norm_pwd)
    cf_pwd = norm_pwd.casefold()

    violations_map: dict[str, bool] = {
        "too_short": False,
        "too_long": False,
        "blocklisted": False,
        "context_word": False,
        "repetitive": False,
        "breached": False,
        "breach_check_unavailable": False,
    }
    warnings: list[str] = []

    # 1. Length checks
    if norm_len < policy.min_length:
        violations_map["too_short"] = True
    if norm_len > policy.max_length:
        violations_map["too_long"] = True

    # 2. Blocklist check (casefolded comparison)
    for entry in policy.blocklist:
        norm_entry = unicodedata.normalize("NFKC", entry).casefold()
        if cf_pwd == norm_entry:
            violations_map["blocklisted"] = True
            break

    # 3. Context check (contains casefolded context word of length >= 4)
    for word in context:
        norm_word = unicodedata.normalize("NFKC", word).casefold()
        if len(norm_word) >= 4 and norm_word in cf_pwd:
            violations_map["context_word"] = True
            break

    # 4. Repetition check
    if policy.check_repetition and _is_repetitive(norm_pwd):
        violations_map["repetitive"] = True

    # 5. Breach check via RangeSource port
    breach_count: int | None = None
    breach_lookup_status: str = "skipped"

    if breach is not None:
        prefix, expected_suffix = sha1_parts(password)
        try:
            raw_reply = breach.fetch_range(prefix)
            if len(raw_reply.encode("utf-8")) > MAX_RANGE_REPLY_BYTES:
                raise ValueError("Range reply exceeded size limit")

            found_count: int | None = None
            for line in raw_reply.splitlines():
                line = line.strip()
                if not line:
                    continue
                if ":" not in line:
                    raise ValueError("Malformed range line without colon")
                suffix_part, count_str = line.split(":", 1)
                suffix_clean = suffix_part.strip().upper()
                try:
                    count_val = int(count_str.strip())
                except ValueError as err:
                    raise ValueError("Invalid count in range reply") from err

                if suffix_clean == expected_suffix:
                    found_count = count_val
                    break

            breach_count = found_count
            if found_count is not None and found_count >= policy.breach_threshold:
                violations_map["breached"] = True
                breach_lookup_status = "hit"
            else:
                breach_lookup_status = "miss"
        except Exception:
            if policy.on_breach_error == "fail_closed":
                violations_map["breach_check_unavailable"] = True
                breach_lookup_status = "unavailable"
            else:
                warnings.append("breach_check_skipped")
                breach_lookup_status = "unavailable"

    # Construct final fixed-order violation tuple
    order = (
        "too_short",
        "too_long",
        "blocklisted",
        "context_word",
        "repetitive",
        "breached",
        "breach_check_unavailable",
    )
    active_violations = tuple(v for v in order if violations_map[v])
    ok = len(active_violations) == 0

    verdict = Verdict(
        ok=ok,
        violations=active_violations,
        warnings=tuple(warnings),
        length=norm_len,
        breach_count=breach_count,
    )

    if on_event is not None:
        on_event(
            {
                "event": "password_checked",
                "ok": verdict.ok,
                "violations": list(verdict.violations),
                "breach_lookup": breach_lookup_status,
            }
        )

    return verdict
