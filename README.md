<h1 align="center">Vitnify your agents</h1>
<p align="center"><strong>Logs tell you what your agent did. Vitnify makes that record tamper-evident</strong> — a
cryptographic, independently-verifiable receipt of what an agent computed, signed and checkable offline,
that can't be quietly edited or forged after the fact.</p>

<p align="center">
  <a href="https://pypi.org/project/vitnify/"><img src="https://img.shields.io/pypi/v/vitnify.svg" alt="PyPI"></a>
  <a href="https://github.com/vitnify/vitnify/actions/workflows/ci.yml"><img src="https://github.com/vitnify/vitnify/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/pypi/pyversions/vitnify.svg" alt="Python versions">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
</p>

Contain what an agent may do, deterministically reconstruct the model behind every
decision, and seal the whole run into one **bit-for-bit receipt** anyone can verify
offline — long after it happened.

> **vitnify** *(v.)*: to turn an agent run into a receipt anyone can reproduce and verify, offline. From Old Norse *vitni*, a sworn witness.

vitnify isn't detection. It gives you the primitives to make an agent run's record
tamper-evident and verifiable offline: a `vitnify-receipt v2` binds the model's computation,
the granted capabilities, every tool call and result, the entropy, and the order into a single
ed25519-signed, self-verifying object — so the record can't be altered or forged after the fact.
It does **not** prove the recorded actions reflect reality against a dishonest issuer — closing
that needs hardware-attested capture (see the trust boundary below).

## Install

```
pip install vitnify
```

## Quickstart

```python
from vitnify.events import EventLog, Kind
from vitnify.engine import Engine, prompt_hash
from vitnify.certificate import issue_certificate, verify_authorized, gen_ed25519

eng = Engine("model.gguf", model_id="my-model")        # deterministic backend
log = EventLog()

step = eng.run(prompt_tokens=[1, 2, 3], n_new=20)       # a model step
log.append_llm_call(prompt_hash([1, 2, 3]), step["tokens"], seed=0,
                    model_digest=step["model_digest"],       # bind the model computation
                    regime=step.get("regime"),               # + regime and weights_hash: bound in the
                    weights_hash=step.get("weights_hash"))   #   digest, now readable in the receipt too
log.append(Kind.TOOL_CALL, {"tool": "read_docs",  "decision": "allow"})
log.append(Kind.TOOL_CALL, {"tool": "send_email", "decision": "deny"})  # ungranted → blocked

priv, pub = gen_ed25519()
cert, _ = issue_certificate("program_hash", ["read_docs"], log, priv=priv)

checks = verify_authorized(cert, log, pinned_pubkeys=[pub])  # L1: offline, no model/secret; authorised signer
assert checks["ok"]                       # signed by a trusted key, unaltered, no ungranted tool ran
assert checks["containment_enforced"]     # every tool call was GATED, not merely observed
# A receipt can be ok=True yet containment_enforced=False — a valid transcript from a
# watch-only integration proves what ran, not that anything was contained. A containment
# claim requires BOTH. (level 2: re-run each step through the engine; every model_digest
# reproduces bit-for-bit.)
```

See the [receipt format spec](https://github.com/vitnify/vitnify-receipt-spec/blob/main/vitnify-receipt-v2.md)
(canonical — this repo does not vendor a copy, so the two can't drift), and
`examples/demo_receipt_e2e.py` for the full loop.

## Attack it yourself

`verify_certificate()` is the trust boundary of this project. Don't take our word that it
holds, attack it. The adversarial suite forges a receipt for every class of attack we know
and asserts the **shipped** verifier rejects each one. It imports whatever `vitnify` you
have installed, so you can point it at any release:

```sh
pip install vitnify
python adversarial/probe_suite.py
```

```
  12 attacks · 12 cleanly blocked · 0 accepted · 0 errored
  control: honest receipt verifies offline + proves containment · yes
```

Point it at an old release (`pip install vitnify==0.1.0`) to watch attacks land, and the
current one to watch them bounce. Find one that gets through and that is the finding we
care about most: security@vitnify.com.

## What you get

- **Capability containment** — ungranted tools are structurally unreachable.
- **Deterministic replay** — re-run a contested run and get the identical result, bit-for-bit.
- **Bit-for-bit receipts** — the model's exact computation, bound and signed.
- **Redaction by default** — the `Broker` commits *salted* hashes of tool payloads instead of cleartext, on allow **and** deny, so PHI/secrets never enter the receipt; cleartext stays in an org-held `Vault`, disclosed one event at a time with an inclusion proof (`vitnify.redact`). Pass `allow_cleartext=True` for the old behaviour (non-sensitive data only).
- **Offline verification** — anyone verifies a receipt's **integrity** (`integrity_ok`) with no model, network, or secret; **authority** (that an approved runtime signed it) is a separate verdict that needs a pinned trust root.
- **Drop-in** — wraps existing **LangGraph** and **MCP** agents (`pip install vitnify[langgraph]` / `[mcp]`).

**Two verification levels — and when to use each.** *Level 1 (integrity)* is offline,
instant, and needs no model — recompute the Merkle root and check the signature; this is
the default for every receipt, and it's what proves containment and tamper-evidence.
*Level 2 (recompute)* additionally re-runs the model to reproduce the committed output
tokens (per-op / activation records — a stronger commitment — are an available mode the
shipped binary does not emit).
It is the **dispute path** — run on a contested subset when someone challenges a specific
decision, **not** on every receipt inline. It is deliberately slow: the pinned-order
deterministic engine trades throughput for bit-exactness, roughly two orders of magnitude
below native inference (~0.45 tok/s vs ~58 for Mistral-7B Q4_K_M on the same Metal box).
Fleet throughput still scales the normal way — L2 is embarrassingly parallel across
receipts; a single recompute is simply not something you do on the hot path.

**The verdict is split** (0.4.1) — a receipt answers two different questions, and a
verifier reports them separately instead of collapsing them into one boolean:

- **`integrity_ok`** — is the transcript internally consistent and validly signed by
  *whoever* signed it? Answerable by **anyone, offline, no secret**. Tampering, a forged
  chain, an ungranted tool, a bad signature all set it `False`.
- **`authority_ok`** — was the signer an **approved runtime**? Needs a trust root, so it is
  `True` / `False` / `None` (unestablished when no anchor is supplied — a stranger offline
  can never answer it, and is *told so* rather than given a bare `False` that looks forged).
- **`ok`** = `integrity_ok` **and** an authorised signer. Pin the trusted key(s) —
  `verify_authorized(cert, log, pinned_pubkeys=…)` is the production entry point; anchor it
  in a TPM/enclave for the strongest form. Pass `require_authority=False` to make `ok` the
  integrity-only verdict (the answer a stranger *can* compute offline). To run your own
  hardware-anchored signer (key generated in a TEE/TPM, then pinned), see
  [Bring your own trust root](https://github.com/vitnify/vitnify-receipt-spec/blob/main/vitnify-receipt-v2.md#bring-your-own-trust-root-hardware-anchored-signer)
  in the receipt spec.

**Program binding.** `program_hash` is caller-asserted unless you bind it. Pass
`derive_program_hash(paths_or_bytes)` at issue time and `verify_certificate(..., program=…)`
at verify time to make the receipt bind the *actual* program, not a label.

> ### ✅ Safe by default (0.4.0)
>
> The `Broker` **redacts** (no tool payload enters the receipt) and `verify_certificate`
> **requires signer authority** (a re-signed forgery can't verify without a trusted pin).
> Relax either only where appropriate, and do it explicitly:
>
> ```python
> broker = Broker(caps, tools, log, allow_cleartext=True)   # record payloads in cleartext (non-sensitive only)
> verify_certificate(cert, log, require_authority=False)    # integrity-only verdict (continuity, not authority)
> ```
>
> The production verify pins the trusted signer(s) and can bind the program:
>
> ```python
> from vitnify.certificate import verify_authorized, derive_program_hash
> cert, _ = issue_certificate(derive_program_hash(SRC), caps, log, priv=priv)  # bind the real code
> checks  = verify_authorized(cert, log, pinned_pubkeys=[trusted_key], program=SRC)  # authority + binding
> ```

The deterministic engine is [`vitni-tensor`](https://github.com/vitnify/vitni-tensor);
the `vitni-receipt` binary is the model backend (point `VITNI_RECEIPT_BIN` at it).

## Cite

If you use vitnify or reference the method, cite the paper:

> J. N. Pijeau, "Reconstructable Execution Certificates for Tool-Using AI Agents," preprint, 2026. https://vitnify.com/Vitnify-Paper.pdf

A machine-readable [`CITATION.cff`](CITATION.cff) is in the repo, so GitHub shows a "Cite this repository" button with ready-made BibTeX.

## License

Apache-2.0. **"vitnify"** and **"vitnify-verified"** are trademarks — see
[TRADEMARKS.md](TRADEMARKS.md). A fork may use the code, but not the name or issue
vitnify-verified receipts.

## Part of Vitnify

This SDK is one of three open repos:

- **[vitni-tensor](https://github.com/vitnify/vitni-tensor)** — the deterministic,
  `no_std` engine that produces the bit-identical model-computation digest this SDK binds.
- **[vitnify-receipt-spec](https://github.com/vitnify/vitnify-receipt-spec)** — the
  canonical `vitnify-receipt v2` format the SDK implements.
- **[vitnify.com](https://vitnify.com)** — the project.
