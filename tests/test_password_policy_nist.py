"""Tests for trysac-password-policy-nist."""

from __future__ import annotations

from typing import Any

import pytest

from password_policy_nist import (
    PasswordPolicy,
    PolicyError,
    check_password,
    sha1_parts,
)


class FakeRangeSource:
    """Test double for RangeSource protocol."""

    def __init__(self, response: str | Exception) -> None:
        self.response = response
        self.received_prefixes: list[str] = []

    def fetch_range(self, prefix: str) -> str:
        self.received_prefixes.append(prefix)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def test_acceptance_basic_pass_and_short_and_min15() -> None:
    """Verbatim acceptance 1:
    check_password('correct horse battery staple', PasswordPolicy()) returns ok True with violations ();
    'a1b2c3d4e5f6g7' returns violations ('too_short',) and the 15-character 'a1b2c3d4e5f6g7h' returns ok True.
    """
    policy = PasswordPolicy()
    res1 = check_password("correct horse battery staple", policy)
    assert res1.ok is True
    assert res1.violations == ()

    res2 = check_password("a1b2c3d4e5f6g7", policy)
    assert res2.ok is False
    assert res2.violations == ("too_short",)

    res3 = check_password("a1b2c3d4e5f6g7h", policy)
    assert res3.ok is True
    assert res3.violations == ()


def test_acceptance_nfkc_normalization_and_too_long() -> None:
    """Verbatim acceptance 2:
    check_password('\ufb01' * 8, PasswordPolicy(check_repetition=False)).length == 16
    because length counts code points after NFKC; a 129-character password returns ('too_long',)
    with the default max_length 128.
    """
    policy_no_rep = PasswordPolicy(check_repetition=False)
    res = check_password("ﬁ" * 8, policy_no_rep)
    assert res.length == 16

    pwd_129 = "x" * 129
    res_long = check_password(pwd_129, PasswordPolicy(check_repetition=False))
    assert res_long.violations == ("too_long",)


def test_acceptance_invalid_policy() -> None:
    """Verbatim acceptance 3:
    PasswordPolicy(max_length=63), PasswordPolicy(min_length=7) and PasswordPolicy(min_length=20, max_length=19)
    raise PolicyError with code 'invalid_policy'.
    """
    for kwargs in (
        {"max_length": 63},
        {"min_length": 7},
        {"min_length": 20, "max_length": 19},
        {"breach_threshold": 0},
        {"on_breach_error": "invalid_mode"},
    ):
        with pytest.raises(PolicyError) as exc_info:
            PasswordPolicy(**kwargs)  # type: ignore[arg-type]
        assert exc_info.value.code == "invalid_policy"


def test_acceptance_blocklist_and_context() -> None:
    """Verbatim acceptance 4:
    With blocklist frozenset({'Password1234567'}), 'PASSWORD1234567' returns 'blocklisted';
    with context=('miguel',), 'miguel-likes-long-walks' returns 'context_word';
    context words shorter than 4 characters are ignored.
    """
    policy = PasswordPolicy(blocklist=frozenset({"Password1234567"}))
    v_block = check_password("PASSWORD1234567", policy)
    assert "blocklisted" in v_block.violations

    policy_clean = PasswordPolicy()
    v_context = check_password("miguel-likes-long-walks", policy_clean, context=("miguel",))
    assert "context_word" in v_context.violations

    # Context words shorter than 4 characters are ignored
    v_short_ctx = check_password("bob-likes-long-walks", policy_clean, context=("bob",))
    assert "context_word" not in v_short_ctx.violations


def test_acceptance_repetitive_and_sequences() -> None:
    """Verbatim acceptance 5:
    'aaaaaaaaaaaaaaaa', 'abcabcabcabcabcabc', 'abcdefghijklmnopq' and 'qponmlkjihgfedcba'
    each return 'repetitive', and none do with check_repetition=False.
    """
    samples = [
        "aaaaaaaaaaaaaaaa",
        "abcabcabcabcabcabc",
        "abcdefghijklmnopq",
        "qponmlkjihgfedcba",
    ]
    default_policy = PasswordPolicy()
    no_rep_policy = PasswordPolicy(check_repetition=False)

    for s in samples:
        v_def = check_password(s, default_policy)
        assert "repetitive" in v_def.violations, f"Expected repetitive for {s}"
        v_no_rep = check_password(s, no_rep_policy)
        assert "repetitive" not in v_no_rep.violations, f"Unexpected repetitive for {s}"


def test_acceptance_sha1_and_breach_lookup() -> None:
    """Verbatim acceptance 6:
    sha1_parts('password') == ('5BAA6', '1E4C9B93F3F0682250B6CF8331B7EE68FD8');
    for 'correct horse battery staple' the fake RangeSource receives exactly the one argument 'ABF7A',
    and the reply 'AD6438836DBE526AA231ABDE2D0EEF74D42:42\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0'
    gives violations ('breached',) and breach_count 42.
    """
    assert sha1_parts("password") == ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")

    fake_source = FakeRangeSource(
        "AD6438836DBE526AA231ABDE2D0EEF74D42:42\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0"
    )
    v = check_password("correct horse battery staple", PasswordPolicy(), breach=fake_source)
    assert fake_source.received_prefixes == ["ABF7A"]
    assert v.violations == ("breached",)
    assert v.breach_count == 42


def test_acceptance_breach_padding_and_errors() -> None:
    """Verbatim acceptance 7:
    A matching suffix with count 0 (padding) is not breached; a RangeSource raising OSError gives
    'breach_check_unavailable' with the default on_breach_error 'fail_closed', and ok True with warnings
    ('breach_check_skipped',) under 'fail_open'; a reply over 1_048_576 bytes or a line without ':' is
    treated as unavailable.
    """
    # 1. Matching suffix with count 0
    reply_zero = "AD6438836DBE526AA231ABDE2D0EEF74D42:0\r\nOTHER:5"
    v_zero = check_password(
        "correct horse battery staple", PasswordPolicy(), breach=FakeRangeSource(reply_zero)
    )
    assert "breached" not in v_zero.violations
    assert v_zero.breach_count == 0
    assert v_zero.ok is True

    # 2. OSError with fail_closed
    v_err_closed = check_password(
        "correct horse battery staple",
        PasswordPolicy(on_breach_error="fail_closed"),
        breach=FakeRangeSource(OSError("connection failed")),
    )
    assert "breach_check_unavailable" in v_err_closed.violations
    assert v_err_closed.ok is False

    # 3. OSError with fail_open
    v_err_open = check_password(
        "correct horse battery staple",
        PasswordPolicy(on_breach_error="fail_open"),
        breach=FakeRangeSource(OSError("connection failed")),
    )
    assert v_err_open.ok is True
    assert v_err_open.violations == ()
    assert v_err_open.warnings == ("breach_check_skipped",)

    # 4. Reply over 1_048_576 bytes
    big_reply = "A" * 1_048_577
    v_big = check_password(
        "correct horse battery staple",
        PasswordPolicy(on_breach_error="fail_closed"),
        breach=FakeRangeSource(big_reply),
    )
    assert "breach_check_unavailable" in v_big.violations

    # 5. Line without ':'
    malformed_reply = "INVALID_LINE_WITHOUT_COLON\r\nAD6438836DBE526AA231ABDE2D0EEF74D42:42"
    v_malformed = check_password(
        "correct horse battery staple",
        PasswordPolicy(on_breach_error="fail_closed"),
        breach=FakeRangeSource(malformed_reply),
    )
    assert "breach_check_unavailable" in v_malformed.violations


def test_acceptance_repr_and_event_hygiene() -> None:
    """Verbatim acceptance 8:
    repr(verdict) and every on_event payload contain neither the password, nor its SHA-1 hex,
    nor the suffix 'AD6438836DBE526AA231ABDE2D0EEF74D42'.
    """
    secret_pwd = "correct horse battery staple"
    forbidden_suffix = "AD6438836DBE526AA231ABDE2D0EEF74D42"
    events: list[dict[str, Any]] = []

    fake_source = FakeRangeSource(f"{forbidden_suffix}:42")
    verdict = check_password(
        secret_pwd,
        PasswordPolicy(),
        breach=fake_source,
        on_event=events.append,
    )

    verdict_repr = repr(verdict)
    assert secret_pwd not in verdict_repr
    assert forbidden_suffix not in verdict_repr
    full_hex = sha1_parts(secret_pwd)[0] + sha1_parts(secret_pwd)[1]
    assert full_hex not in verdict_repr

    assert len(events) == 1
    event_repr = repr(events[0])
    assert secret_pwd not in event_repr
    assert forbidden_suffix not in event_repr
    assert full_hex not in event_repr
    assert events[0] == {
        "event": "password_checked",
        "ok": False,
        "violations": ["breached"],
        "breach_lookup": "hit",
    }


def test_max_input_code_points_bounds_nfkc() -> None:
    """Check that input exceeding 4,096 code points returns too_long without normalizing."""
    events: list[dict[str, Any]] = []
    huge_pwd = "a" * 4_097
    v = check_password(huge_pwd, PasswordPolicy(), on_event=events.append)
    assert v.ok is False
    assert v.violations == ("too_long",)
    assert v.length == 4_097
    assert len(events) == 1
    assert events[0]["breach_lookup"] == "skipped"


def test_repetition_variants_and_adversarial_neighbors() -> None:
    """Test unit repeats of length 2 (abab...) and short texts (< 4) not marked repetitive."""
    policy = PasswordPolicy()
    assert "repetitive" in check_password("abababababab", policy).violations
    assert "repetitive" not in check_password("aba", PasswordPolicy(min_length=8)).violations
    assert "repetitive" not in check_password("random_pass_phrase_not_rep", policy).violations


def test_range_reply_with_invalid_int() -> None:
    """Range reply with non-integer count is treated as unavailable."""
    reply = "AD6438836DBE526AA231ABDE2D0EEF74D42:NOT_AN_INT"
    v = check_password(
        "correct horse battery staple",
        PasswordPolicy(on_breach_error="fail_closed"),
        breach=FakeRangeSource(reply),
    )
    assert "breach_check_unavailable" in v.violations


def test_breach_miss_event() -> None:
    """Test breach lookup miss produces 'miss' in on_event."""
    events: list[dict[str, Any]] = []
    reply = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:10"
    v = check_password(
        "correct horse battery staple",
        PasswordPolicy(),
        breach=FakeRangeSource(reply),
        on_event=events.append,
    )
    assert v.ok is True
    assert v.breach_count is None
    assert events[0]["breach_lookup"] == "miss"
