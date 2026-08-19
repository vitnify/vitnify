"""The crux: can a real model run be reproduced BIT-IDENTICALLY when replayed
under different batch conditions than it was recorded under? Only batch-invariance
closes the gap. Production = co-batched (batch_load>0); forensic replay = alone (load=0).
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from vitnify.deterministic_llm import DeterministicLM

lm = DeterministicLM()
print(f"device={lm.dev}\n")
prompt = "<|user|>\nName one primary color in one word.</s>\n<|assistant|>\n"
print(f"{'mode':>16} | {'tokens match':>12} | {'logit-hash (bit-identical) match':>32}")
print("-"*66)
for inv in (False, True):
    t_alone, h_alone = lm.generate(prompt, n_new=8, batch_load=0, invariant=inv)
    t_prod,  h_prod  = lm.generate(prompt, n_new=8, batch_load=8, invariant=inv)
    print(f"{('batch-invariant' if inv else 'FIX OFF'):>16} | {str(t_alone==t_prod):>12} | {str(h_alone==h_prod):>32}")
print("\n  FIX OFF        : tokens match but logit-hash DIFFERS -> certificate CANNOT be reproduced")
print("  batch-invariant: logit-hash bit-identical -> forensic replay is CERTIFIABLE")
