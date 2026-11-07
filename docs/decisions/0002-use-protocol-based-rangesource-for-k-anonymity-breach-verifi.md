# Use Protocol-based RangeSource for k-anonymity breach verification

Status: accepted (generated, pending human review)

## Context

NIST SP 800-63B-4 mandates checking new passwords against breached value lists. Directly sending passwords or full hashes over the network compromises user security. Including an HTTP client in the library adds unwanted dependencies and coupling.

## Decision

Define a lightweight `RangeSource` protocol accepting a 5-character hex prefix and returning range response text. Provide `sha1_parts()` to split the SHA-1 digest into prefix and suffix. Local validation matches the suffix and interprets padding lines (count 0).

## Consequences

The library remains dependency-free and runtime network agnostic while guaranteeing k-anonymity and preventing credential leakage across the trust boundary.
