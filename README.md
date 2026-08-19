<h1 align="center">Vitnify your agents</h1>
<p align="center"><strong>Logs tell you what your agent did. Vitnify proves it</strong> — a cryptographic,
independently-reconstructable record of what an agent computed and did.</p>

Contain what an agent may do, deterministically reconstruct the model behind every
decision, and seal the whole run into one **bit-for-bit receipt** anyone can verify
offline — long after it happened.

> **vitnify** *(v.)* — to turn an agent run into a receipt anyone can reproduce and verify, offline.

vitnify isn't detection. It gives you the primitives to prove exactly what an agent
did: a `vitnify-receipt v1` binds the model's computation, the granted capabilities,
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
                    model_digest=step["model_digest"])   # bind the model computation
log.append(Kind.TOOL_CALL, {"tool": "read_docs",  "decision": "allow"})
log.append(Kind.TOOL_CALL, {"tool": "send_email", "decision": "deny"})  # ungranted → blocked

priv, pub = gen_ed25519()
cert, _ = issue_certificate("program_hash", ["read_docs"], log, priv=priv)

verify_certificate(cert, log)   # level 1: offline integrity — no model, no secret
# level 2: re-run each step through the engine; every model_digest reproduces bit-for-bit
```

See [`vitnify-receipt-v1.md`](vitnify-receipt-v1.md) for the receipt format, and
`examples/demo_receipt_e2e.py` for the full loop.

## What you get

- **Capability containment** — ungranted tools are structurally unreachable.
- **Deterministic replay** — re-run any past run and get the identical result.
- **Bit-for-bit receipts** — the model's exact computation, bound and signed.
- **Offline verification** — anyone verifies with no model, network, or secret.
- **Drop-in** — wraps existing **LangGraph** and **MCP** agents (`pip install vitnify[langgraph]` / `[mcp]`).

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
  canonical `vitnify-receipt v1` format the SDK implements.
- **[vitnify.com](https://vitnify.com)** — the project.
