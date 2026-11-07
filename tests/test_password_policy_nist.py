"""Behavior tests for the public API of password_policy_nist."""

from __future__ import annotations

import pytest

import password_policy_nist


def test_normalize_trims_and_lowercases() -> None:
    assert password_policy_nist.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        password_policy_nist.normalize(value)


def test_version_is_semver() -> None:
    parts = password_policy_nist.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
