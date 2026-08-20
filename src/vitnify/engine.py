"""Bridge to the vitni-tensor engine.

Runs a model step through the deterministic engine and returns its tier-1
(`vitnify-receipt v2`) model-computation digest, so the SDK can bind what the model
actually computed into the signed execution receipt (`EventLog.append_llm_call`).
`verify_level2` re-runs the bound steps and confirms the digests reproduce.

The engine is the `vitni-receipt` binary (built from the vitni-tensor crate). Point
`VITNI_RECEIPT_BIN` at it, or put it on PATH.
"""
from __future__ import annotations
import os, json, subprocess

# BLAKE3 is a hard dependency and DEFINES the wire format (see events.py): the prompt
# hash bound into a receipt must be blake3, so there is no silent blake2b fallback -- a
# missing blake3 fails loudly rather than binding an incompatible digest.
import blake3 as _blake3
def _h32(b: bytes) -> str:
    return _blake3.blake3(b).hexdigest()

DEFAULT_BIN = os.environ.get("VITNI_RECEIPT_BIN", "vitni-receipt")


def prompt_hash(tokens: list[int]) -> str:
    return _h32(json.dumps(list(tokens), separators=(",", ":")).encode())


class Engine:
    """Deterministic model backend. Every `run` is reproducible bit-for-bit and yields
    a cross-vendor model-computation digest to bind into the receipt."""

    def __init__(self, gguf: str, model_id: str, binary: str = DEFAULT_BIN):
        self.gguf = gguf
        self.model_id = model_id
        self.binary = binary

    def run(self, prompt_tokens: list[int], n_new: int = 16) -> dict:
        """Run one model step. Returns the engine's JSON verbatim:
        {"tokens": [...], "model_digest": hex (tier-1 v2), "regime": str,
         "model_digest_v1": hex (frozen v1), "weights_hash": hex}.
        Pass `model_digest` AND `regime` to `EventLog.append_llm_call` so both are bound
        and readable in the receipt."""
        proc = subprocess.run(
            [self.binary, "--gguf", self.gguf,
             "--prompt", ",".join(str(t) for t in prompt_tokens),
             "--n", str(n_new), "--model-id", self.model_id],
            capture_output=True, text=True, check=True,
        )
        return json.loads(proc.stdout)


def verify_level2(log, engine, steps):
    """Level-2 verification: re-run each bound model step through `engine` and confirm its
    `model_digest` reproduces bit-for-bit -- and when it does not, use the receipt's
    readable `weights_hash` and `regime` to say WHY, in the spec's diagnostic order
    (wrong weights, then wrong regime, then a genuine digest mismatch), instead of a bare
    "digest mismatch" that a weights change, a regime change, and tampering all produce.

    This is the shipped implementation of the spec's Level-2 section: the fields
    `append_llm_call` now records are what let it distinguish those causes.

    `engine` is anything exposing `.run(prompt_tokens, n_new) -> {"model_digest", "regime",
    "weights_hash", ...}` -- normally a `vitnify.engine.Engine` loaded with the weights to
    check against. `steps` is one `(prompt_tokens, n_new)` per `llm_call` event, in order:
    the receipt binds the prompt HASH (not the tokens), so the caller supplies the prompts
    to re-run, and the supplied prompt is checked against that hash first.

    Returns one dict per `llm_call` step -- {"ok": bool, "reason": str, ...} -- where
    `reason` is "reproduced" | "prompt_mismatch" | "wrong_weights" | "regime_mismatch"
    | "digest_mismatch".
    """
    from .events import Kind
    llm = [e for e in log.events
           if e.kind == Kind.LLM_CALL.value and "model_digest" in e.payload]
    if len(steps) != len(llm):
        raise ValueError(f"{len(steps)} step(s) supplied for {len(llm)} llm_call event(s)")

    out = []
    for ev, (prompt_tokens, n_new) in zip(llm, steps):
        p = ev.payload
        if prompt_hash(prompt_tokens) != p.get("prompt_hash"):
            out.append({"ok": False, "reason": "prompt_mismatch"})
            continue
        run = engine.run(prompt_tokens, n_new=n_new)
        # Attribute the cause before calling it a digest mismatch: a wrong-weights or
        # wrong-regime recompute makes the digest differ too, so the readable fields are
        # checked first.
        if p.get("weights_hash") is not None and run.get("weights_hash") != p["weights_hash"]:
            out.append({"ok": False, "reason": "wrong_weights",
                        "receipt": p["weights_hash"], "engine": run.get("weights_hash")})
        elif p.get("regime") is not None and run.get("regime") != p["regime"]:
            out.append({"ok": False, "reason": "regime_mismatch",
                        "receipt": p["regime"], "engine": run.get("regime")})
        elif run.get("model_digest") != p["model_digest"]:
            out.append({"ok": False, "reason": "digest_mismatch",
                        "receipt": p["model_digest"], "engine": run.get("model_digest")})
        else:
            out.append({"ok": True, "reason": "reproduced"})
    return out
