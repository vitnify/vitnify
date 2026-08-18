"""Deterministic local inference -- the piece that makes a replay CERTIFIABLE.
Greedy decode over TinyLlama, with an optional batch-invariant linear (your bi_linear
work). The certificate commits to a hash of the LOGITS at each step, not just the token:
tokens rarely flip under batch load, but logits always shift -- so a bit-identical
certificate can only be reproduced when inference is batch-invariant.
"""
from __future__ import annotations
import hashlib
from contextlib import nullcontext
import torch, torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer

_ORIG_LINEAR = F.linear

def _bi_linear(x, w, b=None):
    """Fixed-chunk fp32 reduction -> output independent of batch size (bit-identical)."""
    d, CH = x.shape[-1], 128
    xf, wf, acc = x.float(), w.float(), None
    for c in range(0, d, CH):
        p = xf[..., c:c+CH] @ wf[:, c:c+CH].t()
        acc = p if acc is None else acc + p
    out = (acc + b.float()) if b is not None else acc
    return out.to(x.dtype)

class batch_invariant:
    def __enter__(self): F.linear = _bi_linear
    def __exit__(self, *a): F.linear = _ORIG_LINEAR

def hash_tensor(t: torch.Tensor) -> str:
    return hashlib.blake2b(t.detach().to("cpu").contiguous().numpy().tobytes(), digest_size=16).hexdigest()

class DeterministicLM:
    def __init__(self, name="TinyLlama/TinyLlama-1.1B-Chat-v1.0", device=None):
        self.dev = device or ("mps" if torch.backends.mps.is_available() else "cpu")
        self.tok = AutoTokenizer.from_pretrained(name, local_files_only=True)
        self.model = AutoModelForCausalLM.from_pretrained(
            name, torch_dtype=torch.float16, local_files_only=True).eval().to(self.dev)
        self.V = self.model.config.vocab_size

    def chat_prompt(self, messages) -> str:
        """Render messages with the model's own chat template (Qwen, Llama, etc.)."""
        return self.tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)

    @torch.no_grad()
    def generate(self, prompt: str, n_new=8, batch_load=0, invariant=False):
        """Greedy decode. batch_load simulates production co-batching (padded neighbors).
        Returns (tokens, per_step_logit_hashes). Our request is always row 0."""
        ids = self.tok(prompt, return_tensors="pt").input_ids.to(self.dev)
        ctx = batch_invariant() if invariant else nullcontext()
        toks, hashes = [], []
        with ctx:
            cur = ids
            for _ in range(n_new):
                if batch_load:
                    pad = torch.randint(0, self.V, (batch_load, cur.shape[1]), device=self.dev)
                    batch = torch.cat([cur, pad], 0)
                else:
                    batch = cur
                logits = self.model(batch).logits[0, -1]
                hashes.append(hash_tensor(logits))
                nxt = int(logits.argmax())
                toks.append(nxt)
                cur = torch.cat([cur, torch.tensor([[nxt]], device=self.dev)], 1)
        return toks, hashes
