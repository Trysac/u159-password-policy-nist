# Architecture

`password-policy-nist` follows NIST SP 800-63B-4 (August 2025) section 3.1.1.2.

## Pipeline

1. **Normalization**: Inputs are normalized via `unicodedata.normalize('NFKC', password)`. To prevent NFKC expansion DoS, inputs > 4,096 code points are rejected immediately as `too_long`.
2. **Checks**: Runs all rules deterministically: length, blocklist, context-word, repetition, and breach status.
3. **Breach Lookup**: Triggered only if a `RangeSource` is provided. Splits password into 5-hex prefix and 35-hex suffix. Only the prefix is transmitted.
4. **Event Reporting**: `on_event` triggers at the end of the pipeline with a status payload indicating lookup status (hit/miss/unavailable/skipped).
