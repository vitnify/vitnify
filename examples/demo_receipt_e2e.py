"""End-to-end vitnify-receipt v1: a contained agent step whose receipt binds a REAL
vitni-tensor model-computation digest.

  1. run a model step through the engine (deterministic, cross-vendor digest)
  2. record it as an llm_call event, binding the engine's model_digest
  3. contain tool calls at the capability wall (allow read, deny send_email)
  4. issue an ed25519-signed vitnify-receipt
  5. level-1 verify (offline, no model)
  6. level-2 verify (re-run the engine; the bound digest must reproduce)

Env: VITNI_GGUF (model path), VITNI_RECEIPT_BIN (the vitni-receipt binary).
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from vitnify.events import EventLog, Kind
from vitnify.engine import Engine, prompt_hash
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519

GGUF = os.environ["VITNI_GGUF"]
eng = Engine(GGUF, model_id="tinyllama-1.1b-chat-Q4_K_M")

# --- run the model step through the engine ---
prompt = [1, 9038, 2501, 263, 931, 29892]   # "Once upon a time,"
step = eng.run(prompt, n_new=20)
print("model step: %d tokens generated, digest %s…" % (len(step["tokens"]), step["model_digest"][:12]))

# --- record the run: the model step + contained tool calls ---
log = EventLog()
log.append_llm_call(prompt_hash(prompt), step["tokens"], seed=0,
                    model_digest=step["model_digest"], regime=step.get("regime"),
                    weights_hash=step.get("weights_hash"))
log.append(Kind.TOOL_CALL, {"tool": "read_docs",  "decision": "allow", "result": "ticket #4f9c"})
log.append(Kind.TOOL_CALL, {"tool": "send_email", "decision": "deny"})  # ungranted → blocked (clean denial carries no result)

# --- issue the ed25519 receipt ---
priv, pub = gen_ed25519()
cert, _ = issue_certificate("program_hash_demo", ["read_docs"], log, priv=priv)
print("receipt digest : %s  (%s)" % (cert.digest()[:16] + "…", cert.sig_alg))
print("bound model_digest matches spec 7a2e28c9:", cert.model_digests[0].startswith("7a2e28c9"))

# --- level 1: offline integrity ---
v1 = verify_certificate(cert, log)
print("level-1 verify :", "OK" if v1["ok"] else "FAIL", v1)

# --- level 2: recompute the model; the bound digest must reproduce ---
step2 = eng.run(prompt, n_new=20)
l2 = step2["model_digest"] == cert.model_digests[0]
print("level-2 recompute: %s (model reproduced bit-for-bit)" % ("OK" if l2 else "FAIL"))

print("\nRESULT:", "vitnify-receipt END-TO-END OK" if (v1["ok"] and l2) else "PROBLEM")
