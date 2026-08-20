# Changelog

All notable changes to `vitnify` are documented here.
This project follows [Semantic Versioning](https://semver.org).

## [0.2.0] — 2026-08-19

Hardens verification and evolves the receipt to **`vitnify-receipt v2`**, applying
every finding from an independent verification review. The `vitni-tensor`
model-computation digest and the published conformance anchor are unchanged.

### Security — verification now fails closed

`verify_certificate()` could previously return `ok=True` for a receipt it never
cryptographically verified. It now cannot.

- **Unsigned receipts are rejected.** `sig_valid` defaults to `False` and is set
  true only by a signature that was actually checked and passed, so a receipt with
  `sig_alg="none"` (or an unknown algorithm) can no longer verify.
- **HMAC receipts require the key at verification.** An HMAC-signed receipt handed
  to a verifier that holds no key now returns `ok=False`, not silent success.
- **Capability containment is proven, not merely declared.** Every *allowed* tool
  call must fall within the receipt's signed capability set (`caps_consistent`), so
  a receipt proves containment held rather than just carrying a list.
- HMAC signature comparison is now constant-time.

### Added

- **`vitnify-receipt v2`** — the signed body now carries `issued_at` (issuer-asserted
  UTC), `nonce`, and `run_id`, so receipts are time-placeable and unique: a receipt
  from one run can no longer be presented as evidence for another.
  `issue_certificate` populates them (pass `run_id=` to set your own).
  *`issued_at` is issuer-asserted; trusted timestamping — RFC 3161 or the
  Verification Authority countersignature — is the stronger form.*
- **Hosted-provider binding** — `EventLog.append_llm_call(..., provider={...})`
  records the model's `provider` / `model_version` / `system_fingerprint` /
  `response_id` and binds it into the receipt, so provider or version drift is
  distinguishable from tampering. Hosted receipts are integrity-only; do not replay
  them as a control (see the spec's hosted-model note).
- **`verify_certificate(..., pinned_pubkeys=[...])`** — optional signer pinning: the
  embedded ed25519 key must be on the allow-list, closing the "any key can re-sign a
  transcript" gap in the open-source verifier with no managed service required.

### Changed

- Receipt format `vitnify-receipt v1` → `vitnify-receipt v2`. The shape of a
  versioned receipt must never drift silently, so the added fields are a new
  version rather than a redefinition of v1.

## [0.1.0] — 2026-08-19

Initial public release. `vitnify-receipt v1`: ed25519-signed, self-verifying
execution receipts for AI agents — capability containment, deterministic replay,
and offline verification, built on
[`vitni-tensor`](https://github.com/vitnify/vitni-tensor).
