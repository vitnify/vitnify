"""Bridge to the vitni-tensor engine.

Runs a model step through the deterministic engine and returns its
`vitnify-receipt v1` model-computation digest, so the SDK can bind what the model
actually computed into the signed execution receipt (`EventLog.append_llm_call`).

The engine is the `vitni-receipt` binary (built from the vitni-tensor crate). Point
`VITNI_RECEIPT_BIN` at it, or put it on PATH.
"""
from __future__ import annotations
import os, json, subprocess

try:
    import blake3 as _blake3
    def _h32(b: bytes) -> str:
        return _blake3.blake3(b).hexdigest()
except ImportError:
    import hashlib
    def _h32(b: bytes) -> str:
        return hashlib.blake2b(b, digest_size=32).hexdigest()

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
        """Return {"tokens": [...], "model_digest": hex, "weights_hash": hex}."""
        proc = subprocess.run(
            [self.binary, "--gguf", self.gguf,
             "--prompt", ",".join(str(t) for t in prompt_tokens),
             "--n", str(n_new), "--model-id", self.model_id],
            capture_output=True, text=True, check=True,
        )
        return json.loads(proc.stdout)
