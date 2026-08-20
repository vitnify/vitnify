# Changelog

All notable changes to `vitnify` are documented here.
This project follows [Semantic Versioning](https://semver.org).

## [0.2.8] — 2026-08-20

Tighten the viewer's containment claim to its evidence — the last place the human page
said something stronger than the receipt supports. Viewer/presentation only; the
verifier, format, and spec are unchanged.

### Integrity
- **A failed certificate no longer yields a containment claim.** When `cert_ok` is
  false the event log is *unverified* — it may be the very forgery the certificate
  exists to catch — so the viewer no longer derives "contained" (in the headline or the
  badge) from it. It shows *Containment unverified — certificate failed* instead.
- **No vacuous containment.** A run with zero tool calls is `containment_enforced=True`
  at the API level (`all([])` is true), but the viewer no longer tells a human the run
  was "contained" when nothing was ever gated — it shows *No tool calls*.
- The headline reads "contained" only when the certificate verifies **and** a tool was
  actually gated.

### Tests
- `tests/test_viewer.py` covers both cases and adds a soundness invariant: the page
  reads "contained" only when the certificate verifies, a tool was gated, and the
  verifier's own predicate agrees.

## [0.2.7] — 2026-08-20

Make the human-facing receipt as honest as the machine-checkable one, and cover the
module that renders it.

### Integrity
- **The viewer headline no longer over-claims containment.** `render()` hardcoded an
  `<h1>` that asserted the run was "contained" regardless of the events, so an
  observe-only receipt showed a containment claim in the largest text on the page and
  retracted it in a badge below. The headline is now built from what actually holds —
  it drops "contained" for an observe-only run (and "cryptographically certified" when
  the certificate does not verify) instead of asserting and walking it back.
- **Containment is derived, not asserted.** Every containment signal the viewer shows
  (headline and badge) is now derived from the events, not read from the caller's
  `verdict["contained"]`. The badge distinguishes *Injection contained* (an ungranted
  call was refused) from *Containment enforced* (all calls gated) from
  *Containment observed — not proven*.
- **One rule, one place.** The gated-decision predicate now lives once in
  `certificate.decision_is_gated`; `verify_certificate` and the viewer both call it, so
  the dict a machine checks and the page a person reads can't drift.

### Tests
- Added `tests/test_viewer.py` — the viewer had **no** test coverage, which is why the
  headline survived a change that was specifically about it. Covers the headline and
  badges for enforced/observe-only/uncertified runs and asserts the viewer and verifier
  never disagree about containment.

### Docs
- `render()` no longer requires a `digest` key the certificate does not emit; the
  certificate-id/signature rows degrade gracefully. Signature row relabelled (was
  hardcoded "HMAC"; the path is ed25519).

## [0.2.6] — 2026-08-20

Post-audit cleanup: close the last two silent hash fallbacks and make the
containment distinction visible where people actually look.

### Integrity
- **Removed the last two silent blake3→blake2b fallbacks.** `_vendor/pck/cas.py`
  (the Merkle module — it computes the event root) and `engine.py` (the prompt hash)
  still degraded to `blake2b` under `--no-deps`, producing a forgery-indistinguishable
  digest under the same `hash_name`. Both are now hard `import blake3`, matching
  `events.py`/`certificate.py` — a missing blake3 fails loudly, never downgrades.
- **Merkle inclusion proofs honor `hash_name`.** `InclusionProof.verify` now rejects a
  proof committed under any hash suite other than the module's (`blake3`) instead of
  silently recomputing it under the wrong hash.

### Visibility
- **`containment_enforced` is now surfaced where receipts are read, not just in the
  API.** The HTML **viewer** renders a distinct badge — green *"Containment enforced"*
  for a gated run vs. amber *"Containment observed — not proven"* for an observe-only
  one — derived from the events the same way the verifier is, so a rendered receipt can
  no longer show a plain green "verified" for a run that proves no containment. The
  **README** quickstart and the **adversarial probe suite** now assert
  `containment_enforced` too (the probe suite gained an anti-laundering control).

### Docs
- Corrected a stale `certificate.py` comment implying a hash-free import path (there is
  none — blake3 is a hard dependency). Viewer certificate header rebranded
  VitniReplay → Vitnify.

## [0.2.5] — 2026-08-20

### Integrity
- **Observe-only receipts can no longer masquerade as containment proofs.** The
  record-only LangGraph callback records tool calls with an `observed` decision
  (watched, not gated), and its receipt was byte-shaped like an enforced one with no
  way to tell them apart. The verifier now reports **`containment_enforced`** — false
  when any tool decision is not a gated `allow`/`deny` — so a valid transcript still
  verifies (`ok=True`) but a containment *proof* requires `ok` **and**
  `containment_enforced`.
- **No silent hash fallback.** `blake3` is a hard dependency and defines the wire
  format; the stdlib `blake2b` fallback (reachable only via `--no-deps`/vendoring)
  produced different digests that were indistinguishable from forgery, and its code
  comment claiming the wire format was "identical either way" was wrong. Removed — a
  missing `blake3` now fails loudly.

### Docs
- Documented that `program_hash` is caller-asserted, and that an empty `model_digests`
  (hosted or non-deterministic backend) means an integrity-only receipt.

## [0.2.4] — 2026-08-19

### Security
- **Unrecognised event kinds are rejected — closing a whole class of bypass.** The
  semantic checks filter events by an exact `kind` match, so a forged log could hide
  an event from a check by relabelling its `kind` (`"TOOL_CALL"` escaped
  containment; `"LLM_CALL"` dropped a model step from `model_digests`). Verification
  now fails closed on any `kind` outside the known set (`llm_call`, `tool_call`,
  `entropy`, `agent_step`). Together with the fail-closed handling of an unknown
  `sig_alg` (0.2.0) and an unknown `decision` (0.2.3), this retires the entire
  "a self-declared label slips past a filter" family in one structural check.

## [0.2.3] — 2026-08-19

### Security
- **Capability containment can no longer be evaded via the decision string.** The
  check keyed off `decision == "allow"`, so a forged log could slip an ungranted,
  result-bearing tool call through by relabelling it (`"PERMIT"`, `" allow"`, an
  omitted field). Verification now fails closed: every `tool_call` must be within
  the declared capabilities **or** a clean denial (decision `deny`, no result), so
  a verifying receipt *proves* no ungranted tool executed — whatever string the
  decision carries. (Requires a compromised runtime or the signing key to reach;
  it hardens the guarantee that `verify_certificate()` makes to a downstream
  auditor.)

## [0.2.2] — 2026-08-19

### Fixed
- **A verified receipt can no longer carry unsigned data.** After the 0.2.1
  backward-compatibility fix, a v1 receipt still had the v2-only fields
  (`issued_at`, `nonce`, `run_id`) on the object even though v1 does not sign them
  — so a forged (e.g. backdated) `issued_at` could be attached to a v1 receipt and
  verification would still return `ok=True`. The verifier now rejects a v1 receipt
  that carries any v2-only field (`fields_match_version`), so `ok=True` never
  blesses a value outside the signature.

## [0.2.1] — 2026-08-19

Follow-up fixes from a post-remediation retest.

### Fixed
- **Backward-compatible verification.** `verify_certificate()` matched the format
  string exactly, so 0.2.0 rejected receipts validly signed under
  `vitnify-receipt v1` — contradicting the spec's promise that v1 stays valid. The
  verifier now accepts every published format and reconstructs each receipt's
  signed body from its own `v`, so a v1 receipt still verifies while tampering is
  still caught. (A published format must remain verifiable across verifier
  upgrades, or "verify it years later" fails.)

### Added
- **Provider binding on the agent path.** `Session.llm(..., provider=)`,
  `Session(..., provider=)`, and `record_run(..., provider=)` now record hosted
  provider identity on every model step, so the hosted-drift mitigation reaches the
  documented LangGraph/MCP path — not just manual `append_llm_call`.

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
