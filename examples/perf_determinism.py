"""Is there a FAST batch-invariant linear on MPS? Compare three implementations for
(a) batch-invariance -- do logits match between running alone (load=0) and co-batched
(load=8)? -- and (b) speed. If a single fp32 matmul is already batch-invariant, the slow
Python-loop 'chunked' kernel is unnecessary and bigger models become practical.
"""
import time, hashlib
from contextlib import nullcontext, contextmanager
import torch, torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer

_ORIG = F.linear
def chunked(x, w, b=None):                       # current bi_linear: fp32, Python loop over 128-cols
    d, CH = x.shape[-1], 128; xf, wf, acc = x.float(), w.float(), None
    for c in range(0, d, CH):
        p = xf[..., c:c+CH] @ wf[:, c:c+CH].t(); acc = p if acc is None else acc + p
    return (acc + b.float() if b is not None else acc).to(x.dtype)
def fp32_single(x, w, b=None):                   # candidate: one fp32 matmul, no loop
    o = x.float() @ w.float().t()
    if b is not None: o = o + b.float()
    return o.to(x.dtype)
def chunked_vec(x, w, b=None):                   # same fixed-order chunking, vectorized (no Python loop)
    d, CH = x.shape[-1], 128
    xf, wf = x.float(), w.float()
    nc = d // CH; rem = d - nc * CH; o = None
    if nc:
        xc = xf[..., :nc*CH].reshape(*xf.shape[:-1], nc, CH)
        wc = wf[:, :nc*CH].reshape(wf.shape[0], nc, CH)
        o = torch.einsum('...kc,okc->...ko', xc, wc).sum(dim=-2)   # per-chunk, then fixed-order sum
    if rem:
        tail = xf[..., nc*CH:] @ wf[:, nc*CH:].t()
        o = tail if o is None else o + tail
    if b is not None: o = o + b.float()
    return o.to(x.dtype)

@contextmanager
def patch(fn):
    if fn is None: yield; return
    F.linear = fn
    try: yield
    finally: F.linear = _ORIG

dev = "mps" if torch.backends.mps.is_available() else "cpu"
NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
tok = AutoTokenizer.from_pretrained(NAME, local_files_only=True)
m = AutoModelForCausalLM.from_pretrained(NAME, torch_dtype=torch.float16, local_files_only=True).eval().to(dev)
V = m.config.vocab_size
prompt = "<|user|>\nName one primary color in one word.</s>\n<|assistant|>\n"

@torch.no_grad()
def gen(fn, load, n=8):
    ids = tok(prompt, return_tensors="pt").input_ids.to(dev); cur = ids; hs = []
    with patch(fn):
        for _ in range(n):
            batch = torch.cat([cur, torch.randint(0, V, (load, cur.shape[1]), device=dev)], 0) if load else cur
            lg = m(batch).logits[0, -1]
            hs.append(hashlib.blake2b(lg.detach().to("cpu").contiguous().numpy().tobytes(), digest_size=8).hexdigest())
            cur = torch.cat([cur, torch.tensor([[int(lg.argmax())]], device=dev)], 1)
    return hs

@torch.no_grad()
def timeit(fn, n=16):
    ids = tok(prompt, return_tensors="pt").input_ids.to(dev)
    with patch(fn):
        m(ids)  # warm up (kernel compile)
        t = time.time()
        for _ in range(n): m(ids)
    return (time.time() - t) / n * 1000  # ms/forward

print(f"device={dev}\n")
print(f"{'linear kernel':>16} | {'batch-invariant?':>16} | {'ms / forward':>12} | {'vs native':>9}")
print("-"*62)
native_ms = timeit(None)
for name, fn in (("native fp16", None), ("chunked fp32 (now)", chunked), ("single fp32", fp32_single), ("chunked-vec fp32", chunked_vec)):
    inv = gen(fn, 0) == gen(fn, 8)
    ms = timeit(fn)
    print(f"{name:>16} | {str(inv):>16} | {ms:>10.1f}   | {ms/native_ms:>7.1f}x")
print("\nif 'single fp32' is batch-invariant AND ~native speed -> that's the fast kernel; bigger models become practical.")
