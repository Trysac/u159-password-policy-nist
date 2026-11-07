# password-policy-nist

[![PyPI version](https://img.shields.io/pypi/v/trysac-password-policy-nist)](https://pypi.org/project/trysac-password-policy-nist/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-password-policy-nist)](LICENSE)
[![CI](https://github.com/Trysac/u159-password-policy-nist/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u159-password-policy-nist/actions/workflows/ci.yml)

Password verifier checks after NIST SP 800-63B-4: length by code points after NFKC, blocklist and context words, and a k-anonymity breach lookup through a port

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-password-policy-nist
# or
uv add trysac-password-policy-nist
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import password_policy_nist

# normalize() trims surrounding whitespace and lower-cases the text.
print(password_policy_nist.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    password_policy_nist.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
