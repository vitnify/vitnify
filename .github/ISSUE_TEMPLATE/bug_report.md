---
name: Bug report
about: Something in the vitnify SDK behaves incorrectly
title: "[bug] "
labels: bug
---

<!--
SECURITY: if this is a verification bypass, a capability-containment escape, or a
hash/canonicalization collision, do NOT file it here. Email security@vitnify.com —
see SECURITY.md.
-->

## What happened

A clear description of the bug.

## Area

- [ ] Verification (level 1 / level 2)
- [ ] Certificate issuance / signing
- [ ] Capability Broker / containment
- [ ] Event log / canonical JSON / hashing
- [ ] Engine wiring (`vitni-receipt` backend)
- [ ] Adapter (`langgraph` / `mcp`)
- [ ] Other

## Reproduction

A minimal snippet or failing test. The fixtures in `tests/conftest.py` and the
attack-matrix tests are good starting points.

```python
# minimal repro
```

## Expected vs. actual

What you expected, and what happened instead. If a receipt verified when it should not
have (or vice versa), say so explicitly.

## Environment

- vitnify version / commit:
- Python version (`python -V`):
- Optional extras installed (`[langgraph]`, `[mcp]`):
- If L2 is involved: `VITNI_GGUF` model and `VITNI_RECEIPT_BIN` engine build:

## Additional context

Traceback, logs, or anything else that helps.
