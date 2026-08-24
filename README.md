<h1 align="center">Vitnify your agents</h1>
<p align="center"><strong>Logs tell you what your agent did. Vitnify proves it</strong> — a cryptographic,
independently-reconstructable record of what an agent computed and did.</p>

Contain what an agent may do, deterministically reconstruct the model behind every
decision, and seal the whole run into one **bit-for-bit receipt** anyone can verify
offline — long after it happened.

> **vitnify** *(v.)* — to turn an agent run into a receipt anyone can reproduce and verify, offline.

vitnify isn't detection. It gives you the primitives to prove exactly what an agent
did: a `vitnify-receipt v2` binds the model's computation, the granted capabilities,
every tool call and result, the entropy, and the order into a single ed25519-signed,
self-verifying object.

## Install

```
pip install vitnify
```

## Quickstart

```python
from vitnify.events import EventLog, Kind
from vitnify.engine import Engine, prompt_hash
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519

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

checks = verify_certificate(cert, log)   # level 1: offline integrity — no model, no secret
assert checks["ok"]                       # signed, unaltered, and no ungranted tool ran
assert checks["containment_enforced"]     # every tool call was GATED, not merely observed
# A receipt can be ok=True yet containment_enforced=False — a valid transcript from a
# watch-only integration proves what ran, not that anything was contained. A containment
# claim requires BOTH. (level 2: re-run each step through the engine; every model_digest
# reproduces bit-for-bit.)
```

See the [receipt format spec](https://github.com/vitnify/vitnify-receipt-spec/blob/main/vitnify-receipt-v2.md)
(canonical — this repo does not vendor a copy, so the two can't drift), and
`examples/demo_receipt_e2e.py` for the full loop.

## What you get

- **Capability containment** — ungranted tools are structurally unreachable.
- **Deterministic replay** — re-run a contested run and get the identical result, bit-for-bit.
- **Bit-for-bit receipts** — the model's exact computation, bound and signed.
- **Redaction by default** — commit salted hashes of tool payloads, not cleartext, so PHI/secrets never enter the receipt; disclose one event at a time with an inclusion proof (`vitnify.redact`).
- **Offline verification** — anyone verifies with no model, network, or secret.
- **Drop-in** — wraps existing **LangGraph** and **MCP** agents (`pip install vitnify[langgraph]` / `[mcp]`).

**Two verification levels — and when to use each.** *Level 1 (integrity)* is offline,
instant, and needs no model — recompute the Merkle root and check the signature; this is
the default for every receipt, and it's what proves containment and tamper-evidence.
*Level 2 (recompute)* additionally re-runs the model to reproduce the committed logits.
It is the **dispute path** — run on a contested subset when someone challenges a specific
decision, **not** on every receipt inline. It is deliberately slow: the pinned-order
deterministic engine trades throughput for bit-exactness, roughly two orders of magnitude
below native inference (~0.45 tok/s vs ~58 for Mistral-7B Q4_K_M on the same Metal box).
Fleet throughput still scales the normal way — L2 is embarrassingly parallel across
receipts; a single recompute is simply not something you do on the hot path.

**Signer authority.** `verify_certificate` proves integrity and signer *continuity* from a
receipt's own key. For *authority* (that an approved runtime signed it), use
`verify_authorized(cert, log, pinned_pubkeys=...)`, which fails closed unless the signer is
on your allow-list — a re-signed forgery then never verifies. Anchor the pinned key in a
TPM/enclave for the strongest form.

**Program binding.** `program_hash` is caller-asserted by default. Pass
`derive_program_hash(paths_or_bytes)` at issue time and `verify_certificate(..., program=…)`
at verify time to make the receipt bind the *actual* program, not a label.

The deterministic engine is [`vitni-tensor`](https://github.com/vitnify/vitni-tensor);
the `vitni-receipt` binary is the model backend (point `VITNI_RECEIPT_BIN` at it).

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
