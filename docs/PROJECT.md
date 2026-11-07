# Project record\n\n## Objective\nPassword verifier checks after NIST SP 800-63B-4: length by code points after NFKC, blocklist and context words, and a k-anonymity breach lookup through a port.\n\n## Scope\n\n- In scope: The public API documented in README.md, fully typed and tested.\n\n## Out of Scope\n\n- HTTP client libraries.\n- Password strength meters.\n- Password generation.\n\n## Effort metrics\n\n| Metric | Value |\n|---|---|\n| Tokens (input / output) | pending measurement |\n| Hours (human) | pending measurement |\n| Cost (USD) | pending measurement |

## Factory run u159 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4574 | 8531 | 0 | 0 | 0.0177 |
| fix-1 | gemini-3.8-flash | no | 11450 | 515 | 0 | 6869 | 0.0110 |
| audit | gemini-3.1-flash-lite | no | 30995 | 369 | 0 | 14211 | 0.0087 |
| docs | gemini-3.1-flash-lite | no | 187191 | 1762 | 0 | 0 | 0.0494 |

Total: $0.0868. Prices: Anthropic list prices.
