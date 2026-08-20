# Changelog

All notable changes to `vitnify` are documented here.
This project follows [Semantic Versioning](https://semver.org).

## [0.1.1] — 2026-08-19

### Security

`verify_certificate()` now **fails closed**. Verification of a receipt that could
not be cryptographically verified could previously return `ok=True`; it no longer
can. Found via an independent verification review.

- **Unsigned receipts are rejected.** `sig_valid` defaults to `False` and is set
  true only by a signature that was actually checked and passed, so a receipt
  with `sig_alg="none"` (or an unknown algorithm) can no longer verify.
- **HMAC receipts require the key at verification.** An HMAC-signed receipt
  handed to a verifier that holds no key now returns `ok=False` instead of
  silently skipping the signature check.
- **Capability containment is proven, not merely declared.** Every *allowed* tool
  call in the log must fall within the receipt's signed capability set; an
  allowed call to an undeclared tool now fails verification (`caps_consistent`).
- HMAC signature comparison is now constant-time.

### Added

- `verify_certificate(..., pinned_pubkeys=[...])` — optional signer pinning. When
  supplied, the embedded ed25519 key must be on the allow-list, closing the
  "any key can re-sign a transcript" gap in the open-source verifier with no
  managed service required.

Verification is stricter only: the receipt format, `body()`, and the published
conformance digest are unchanged, so every receipt issued under 0.1.0 remains
valid.

## [0.1.0] — 2026-08-19

Initial public release. `vitnify-receipt v1`: ed25519-signed, self-verifying
execution receipts for AI agents — capability containment, deterministic replay,
and offline verification, built on
[`vitni-tensor`](https://github.com/vitnify/vitni-tensor).
