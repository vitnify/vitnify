<!-- Thanks for contributing to the vitnify SDK. Please complete the checklist. -->

## What this changes

Briefly describe the change and the motivation.

## Determinism & compatibility

The reference digest is a published conformance anchor and must not change:

```
9c0754458633e863e0fb5bb2bd00df0d8b813934687b9a4097a1a9a4179f3b0f
```

- [ ] **The reference model-computation digest is unchanged.** (If it changes, this PR
      must be an explicit, agreed-upon versioned migration — link the issue.)
- [ ] I did not change how receipts/events are canonicalized, hashed, or signed
      (or, if I did, it is a versioned format change and existing receipts still verify).
- [ ] Ungranted tools remain structurally unreachable (capability containment intact).

## Checklist

- [ ] `python -m pytest` passes (L1 / unit / capability / attack-matrix suite)
- [ ] For model/digest-path changes: I ran the L2 suite locally
      (`VITNI_GGUF=… VITNI_RECEIPT_BIN=… python -m pytest -m l2`) and the reference
      digest still reproduces
- [ ] Tests added/updated for the change
- [ ] Commits are signed off (DCO): `git commit -s`

## Related issues

Closes #
