# Changelog

All notable changes to `vitnify` are documented here.
This project follows [Semantic Versioning](https://semver.org).

## [0.4.4] — 2026-08-24

### Fixed
- **Wording: level 2 reproduces the committed OUTPUT TOKENS, not "logits."** The viewer
  footer and the README said level-2 recompute reproduces the "committed logits" — an
  overclaim: the shipped binary commits `output_tokens` + `output_tokens_hash` with
  `n_ops = 0` (per-op / activation records, which would include logits, are an available
  mode it does not emit). Corrected to "committed output tokens," and guarded in
  `tests/test_viewer.py::test_footer_makes_no_unbacked_claims`. Committing logits would be
  a stronger claim than the engine makes — the one direction never to drift.

## [0.4.3] — 2026-08-24

Two more viewer surfaces the verdict split hadn't reached — both making claims the run
doesn't back.

### Fixed
- **Replay badge is now three-state.** It was `bool(v.get("replay_identical"))`, so
  *not run* (absent) and *ran and diverged* collapsed to the same red "Replay diverged" —
  the same false-negative the authority split removed, one variable over. Since level 2 is
  the dispute path, the common receipt carries no replay data, so every such page was
  asserting a divergence that never happened. Absent now renders neutral **"Replay not run —
  L1 verdict only"**; the headline claims "replayed bit-for-bit" only when it actually was.
- **The viewer footer no longer makes unbacked claims.** It hardcoded, under *every*
  receipt: "…bit-identical only because inference is **batch-invariant**. **HMAC** signing
  shown…" — both false (batch-invariance is not an engine property; it is precisely why
  level 2 is a single-request path — and the demo signs ed25519). The footer is now derived
  from the run: the actual `sig_alg`, and a statement of what the page proves, with no
  determinism claim the engine can't back.

## [0.4.2] — 2026-08-24

Carry the split verdict through to the human-facing viewer, and close a fail-open.

### Fixed
- **The forensic viewer (`vitnify.viewer`) now carries the split verdict.** It keyed the
  whole page on one caller-asserted `cert_ok`, so it couldn't tell "integrity verified,
  authority unestablished" from "signed by an approved runtime", and an honest receipt
  viewed with no trust root read "certificate failed" — reintroducing, on the page a
  compliance reviewer actually looks at, the exact conflation 0.4.1 removed from the
  verifier. The viewer now reads `integrity_ok` / `authority_ok` straight from the
  verifier's own dict and renders a **three-state authority badge** (verified / rejected /
  unestablished). The headline claims authority only when a trust root confirmed it.
- **`integrity_ok` fails CLOSED on a missing check.** It was `all(checks.get(k, True) …)`,
  which fails *open* — a check silently dropped in a refactor, or a typo in the key tuple,
  would pass. Mandatory keys now default to `False`, and their coverage is asserted in
  `tests/test_safe_defaults.py::test_integrity_tuple_is_fully_produced`.

## [0.4.1] — 2026-08-24

Split the verification verdict, and wire the public evidence artifacts into CI.

### Fixed
- **`verify_certificate` splits its verdict into `integrity_ok` + `authority_ok`.** A
  receipt answers two distinct questions, and collapsing them into one boolean was wrong
  either way: 0.3.x let a re-signed forgery read `ok=True`; 0.4.0 made an *honest* receipt
  read `ok=False` to a stranger with no trust root — indistinguishable from tampering.
  Now:
  - `integrity_ok` — internally consistent + validly signed by whoever signed it.
    **Anyone can compute it offline, no secret.** (This restores the "anyone verifies
    offline" property and resolves the spec conflict — signer pinning stays *optional*
    for integrity.)
  - `authority_ok` — `True` / `False` / `None`. `None` = **unestablished** (no anchor
    supplied), reported as such, not as a bare `False`.
  - `ok` = `integrity_ok` **and** an authorised signer (or just `integrity_ok` when
    `require_authority=False`). `signer_pinned` is kept as a back-compat alias.
- **The adversarial probe suite reported a false green after the 0.4.0 flip.** Its
  "blocked" predicate was `ok is False`, which an unpinned verify now returns for *every*
  receipt — so it printed "12 blocked" even for honest ones, while the controls read
  "verifier is broken." Each probe now keys on the field its attack actually breaks
  (`integrity_ok` for tamper/forge; `ok` with a pin for the re-sign case), so the count is
  real and non-vacuous.

### CI
- **`adversarial/probe_suite.py` and the model-free example scripts now run in CI.** The
  0.4.0 default flip left the public proof asserting the verifier was broken because
  nothing re-ran it; CI now fails if an artifact goes stale.

## [0.4.0] — 2026-08-24

**Safe by default (BREAKING).** The 0.3.x fixes added a safe path *beside* the unsafe
default; a reviewer's through-line was that "safe unless you opt out" vs "unsafe unless
you opt in" is the whole difference for a regulated buyer. The defaults now flip.

### Changed (breaking)
- **`Broker` redacts by default.** It commits *salted* hashes of tool args/results (on
  allow AND deny) and keeps the cleartext in an org-held `Vault` at `broker.vault`, so no
  payload enters the receipt. The old cleartext behaviour is `Broker(..., allow_cleartext=True)`
  (non-sensitive data only). `RedactingBroker` remains as an explicit alias.
- **`verify_certificate` requires signer authority by default** (`require_authority=True`).
  With no `pinned_pubkeys`, `signer_pinned` is `False` and `ok` fails closed — a receipt
  re-signed with an attacker's own key no longer verifies just because it's internally
  consistent. `verify_authorized(cert, log, pinned_pubkeys=…)` is the production entry
  point. Pass `require_authority=False` for an integrity-only verdict (continuity, not
  authority) — e.g. an offline consistency check with no trust root.

### Migration
- Recording non-sensitive payloads and want them readable? `Broker(..., allow_cleartext=True)`.
- Verifying without a trust anchor (integrity only)? `verify_certificate(..., require_authority=False)`.
- Production: pin your signer(s) — `verify_authorized(cert, log, pinned_pubkeys=[...])` — and
  bind the program with `derive_program_hash` + `verify_certificate(..., program=…)`.
- Guards in `tests/test_safe_defaults.py` fail the build if either default silently reverts.

## [0.3.1] — 2026-08-24

Fixes from a second review pass on 0.3.0.

### Security
- **`derive_program_hash` is now injective.** 0.3.0 concatenated `basename \0 data \0`,
  but content can contain `\0` — so two files collided with one crafted file, and the
  collision passed the new `program=` check end-to-end. Now each entry binds its
  **length-prefixed relative path** then **length-prefixed content** (the tier-1 digest
  discipline; a length prefix cannot be forged by embedding a delimiter). Entries sort by
  **relative path** — a total order, unlike basename, so a program with several
  `__init__.py` is argument-order-independent — and the relative path is bound, so moving
  a file between directories changes the hash. Add `root=` to control the base.
- **`verify_disclosure` no longer passes vacuously.** An event with no commitments plus a
  fabricated reveal returned `ok=True`; it now fails closed (`bound=False`, and a reveal
  that claims a field the event never committed fails) — the vacuity class closed in the
  viewer at 0.2.8.

### Docs
- **Corrected a dangerous claim.** The 0.3.0 README said "redaction by default"; it is
  **opt-in**. The README now says so plainly, adds a callout that the bare `Broker` /
  `verify_certificate` / caller-asserted `program_hash` are integrity-only and not safe
  for regulated data, and shows the opt-in production path (`RedactingBroker` +
  `verify_authorized` + `derive_program_hash`). (Safe-by-default is planned for 0.4.0.)

## [0.3.0] — 2026-08-24

Close the three open review findings: PHI in the receipt (A), signer authority (B),
and an unbound `program_hash` (C).

### Added
- **Redaction by default — `vitnify.redact`.** `RedactingBroker` commits a **salted**
  hash of each tool payload instead of the cleartext, on **allow AND deny**, keeping
  the cleartext in an org-held `Vault` inside the boundary. So a blocked exfiltration
  no longer writes an MRN into the permanent record, and no PHI enters the signed
  receipt. `disclose()` / `verify_disclosure()` reveal ONE event at a time with an
  inclusion proof against the receipt's `event_root`; a doctored disclosure fails the
  commitment, other events stay hidden. Salting is mandatory — an unsalted hash of a
  10-digit MRN is brute-forceable. See `examples/redact_demo.py`, `tests/test_redact.py`.
- **Signer authority — `verify_authorized(cert, log, pinned_pubkeys=…)`.** Fails
  closed unless the signer is on your allow-list, so a re-signed forgery (valid under
  an attacker's own key) never reports `ok` — and neither does a call that forgot to
  pin. `verify_certificate` still proves integrity + continuity from the embedded key;
  authority requires the pin (anchor it in a TPM/enclave for the strongest form).
- **Program binding — `derive_program_hash(paths_or_bytes)` + `verify_certificate(…,
  program=…)`.** Derive `program_hash` from the actual code so the receipt binds what
  ran; the verifier confirms it. `"literally anything I type here"` no longer verifies
  against real code. See `tests/test_authority_program.py`.

### Changed
- **README** reframes replay as the **dispute path**: level 1 (integrity) is the
  default; level 2 (recompute) is run on a contested subset, not inline, and is ~2
  orders of magnitude below native inference (~0.45 vs ~58 tok/s, Mistral-7B on Metal)
  — while fleet throughput still scales normally (L2 is parallel across receipts).

## [0.2.14] — 2026-08-24

**Security hotfix.** Revert the 0.2.13 verifier loosening, which was a containment
regression. Keep the 0.2.13 demo fix.

### Security
- **`_clean_denial` back to strict absence.** 0.2.13 accepted `result: None` (and
  `result_hash: None`) as a clean denial. An absent key and an explicit `None` are
  indistinguishable by value, so this let the single most dangerous shape through: an
  **ungranted, side-effecting tool that returns `None`** (`send_email`, `wire_transfer`,
  `delete_record`) which **actually executed** and was logged
  `{"decision":"deny","result":None}` verified as `ok=True, caps_consistent=True` —
  a real side effect masquerading as a block. The 0.2.13 rationale ("a real execution
  always carries a non-None result") holds through the Broker but is false for any
  hand-rolled wrapper around a `None`-returning tool, and catching exactly that is in
  scope per `SECURITY.md`. Every enforced deny site already omits the key, so the
  loosening bought nothing. A genuine block never writes a `result`; if the ergonomics
  are wanted later, the sound form is a positive Broker assertion (`executed: false`),
  never an indistinguishable absence.
- **New attack-matrix guard** `ungranted_none_returning_side_effect_logged_as_deny`
  (18 defended, 1 honest xfail) fails the build if this hole is ever reopened.

## [0.2.13] — 2026-08-24

Fix the flagship end-to-end demo, which printed `RESULT: PROBLEM` on a clean install,
and remove a verifier footgun that surfaced through it.

### Fixed
- **`examples/demo_receipt_e2e.py`** printed two failures on a clean run:
  - the `deny` event carried `{"result": None}`; `_clean_denial` required the key
    **absent**, so `caps_consistent` went `False`. The demo now omits `result` on a
    denial (a clean denial carries none).
  - it checked the bound tier-1 **v2** (regime-bound) `model_digest` against the old
    **v1** anchor `9c075445…`, printing `False` after the regime-2 upgrade. It now
    checks the regime-2 anchor `7a2e28c9…`. Also dropped a stale `v1` from the final
    line (the receipt issued is v2 format).

### Verification
- **`_clean_denial` now treats an explicit `result`/`result_hash` of `None` the same
  as an omitted key.** A null result reads as "no result" to every integration, and
  requiring strict omission silently failed adapters that set `result=None` on a
  block. This does **not** weaken containment: a real execution always carries a
  non-None result, so an ungranted call that actually ran still cannot pass as a
  clean denial. (118 pass / 3 skip / 1 xfail, unchanged.)

## [0.2.12] — 2026-08-20

Ship the level-2 verifier the spec specifies — so the diagnostics live in code, not only
in prose.

### Verification
- **`vitnify.engine.verify_level2(log, engine, steps)`** re-runs each bound model step
  and confirms its `model_digest` reproduces bit-for-bit, and when it does not, uses the
  now-readable `weights_hash` and `regime` to report **the cause** in the spec's order:
  `wrong_weights` → `regime_mismatch` → `digest_mismatch` (a genuine mismatch only when
  weights and regime both matched), plus `prompt_mismatch` when the supplied prompt is not
  the one the receipt bound. Previously L2 was a hand-rolled loop inside a test and nothing
  shipped read the fields those releases made readable.

### Tests
- `tests/test_level2_verify.py` — drives every diagnostic branch with a **stub engine**,
  so the ordering runs in CI without a GGUF (the real-weights reproduction stays in
  `test_l2_recompute.py`, which now records the current receipt shape — `regime` +
  `weights_hash` — and verifies through `verify_level2`).

## [0.2.11] — 2026-08-20

Follow-through on the same seam: make `weights_hash` readable like `regime`, stop
vendoring a spec copy that can drift, and make the seam fixture guard the class.

### Integrity
- **`weights_hash` is now carried into the receipt**, via `append_llm_call(...,
  weights_hash=...)` and readable through **`EventLog.model_weights_hashes()`**. It was
  already bound (folded into the engine's `model_digest`) but not readable — so an L2
  replay against the wrong GGUF produced a digest mismatch indistinguishable from
  tampering, the exact failure `regime` was made readable to cure. Which weights produced
  a run is arguably the most consequential thing a receipt asserts; now a verifier can
  report **wrong weights** instead of an opaque mismatch. `Engine.run()`, the demo, and
  the README thread it through.

### Anti-drift
- **Removed the vendored spec copies** (`vitnify-receipt-v1.md`, `-v2.md`). They had
  already fallen out of step — the code added `regime`, the local copy did not — so the
  format doc shipped with the SDK didn't describe the field the code emitted. The README
  now links the **canonical** [`vitnify-receipt-spec`](https://github.com/vitnify/vitnify-receipt-spec);
  one source of truth, no drift possible.

### Tests
- **`tests/test_engine_seam.py` now iterates the engine blob's keys**, requiring each to
  be either carried into the receipt or on an explicit, commented ignore-list. Adding an
  engine field forces a decision instead of allowing an omission — the fixture guards the
  class, not the three fields someone remembered. (`weights_hash` was the field it missed
  the same way the original bug missed `regime`.)

## [0.2.10] — 2026-08-20

Completes tier-1 v2: the numerical **regime is now carried into the receipt**, not just
bound in the engine's digest.

### Integrity
- **`append_llm_call(..., regime=...)` records the engine's numerical regime** in the
  `llm_call` payload — so it is bound (via the Merkle root) **and readable** in the
  receipt. Binding the regime into the digest is what makes the digest change when the
  regime changes; recording it here is what makes that change *diagnosable*: a level-2
  verifier can report "issued under regime-1, this engine is regime-2" instead of an
  opaque digest mismatch indistinguishable from tampering. Previously the engine emitted
  `regime` and the SDK dropped it — the fix landed in the engine but never reached the
  receipt.
- **`EventLog.model_regimes()`** — ordered regimes per bound model step (None for a
  hosted or pre-regime step), the accessor an L2 verifier reads.
- **`Engine.run()`** returns the engine JSON verbatim (now including `regime` and
  `model_digest_v1`); `demo_receipt_e2e.py` and the README quickstart thread `regime`
  through.

### Robustness / docs
- `issue_certificate` on an empty log now raises a clear `ValueError` at the API surface
  instead of a raw error out of the vendored Merkle module.
- Fixed a stale `events.py` doc that still called `model_digest` the "vitnify-receipt v1"
  digest (it is tier-1 **v2**).

### Tests
- `tests/test_engine_seam.py` — a canned engine-JSON blob asserting every field the
  engine binds survives into the signed receipt, and that a tampered regime breaks
  verification. This exercises the engine→SDK→receipt seam that the level-2 tests skip
  without a GGUF — the seam that had let the regime silently drop.

## [0.2.9] — 2026-08-20

### Integrity
- **The verifier fails closed on an empty event log instead of crashing.**
  `verify_certificate` built a `MerkleCAS` over the log's chunks unconditionally, and
  `MerkleCAS` raises `ValueError` on an empty chunk list — so a receipt presented with a
  zero-event log raised out of the verifier rather than returning a verdict. No
  legitimately issued receipt has an empty log (issuance commits ≥1 event), so an empty
  log is always malformed: it now returns `ok=False` (`root_matches=False`), never
  raises. A verifier must fail closed on hostile input, not throw.

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
