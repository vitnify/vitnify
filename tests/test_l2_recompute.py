"""Level-2 verification: re-run each bound model step through the vitni-tensor engine
and confirm the model_digest reproduces bit-for-bit.

Requires the deterministic engine + weights, so the whole module skips unless both
VITNI_GGUF (weights) and VITNI_RECEIPT_BIN (the vitni-receipt binary) are set.
"""
from __future__ import annotations

import os

import pytest

GGUF = os.environ.get("VITNI_GGUF")
BIN = os.environ.get("VITNI_RECEIPT_BIN")

pytestmark = [
    pytest.mark.l2,
    pytest.mark.skipif(
        not (GGUF and BIN),
        reason="set VITNI_GGUF and VITNI_RECEIPT_BIN to run level-2 recomputation"),
]

# Fixed model step from examples/demo_receipt_e2e.py ("Once upon a time,").
PROMPT = [1, 9038, 2501, 263, 931, 29892]
N_NEW = 20
MODEL_ID = "tinyllama-1.1b-chat-Q4_K_M"


@pytest.fixture(scope="module")
def engine():
    from vitnify.engine import Engine
    return Engine(GGUF, model_id=MODEL_ID, binary=BIN)


def test_engine_run_is_deterministic(engine):
    a = engine.run(PROMPT, n_new=N_NEW)
    b = engine.run(PROMPT, n_new=N_NEW)
    assert a["model_digest"] == b["model_digest"]
    assert a["tokens"] == b["tokens"]


def test_receipt_binds_model_digest_and_level2_reproduces(engine):
    from vitnify.events import EventLog
    from vitnify.engine import prompt_hash
    from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519

    step = engine.run(PROMPT, n_new=N_NEW)
    log = EventLog()
    log.append_llm_call(prompt_hash(PROMPT), step["tokens"], seed=0,
                        model_digest=step["model_digest"])

    priv, _ = gen_ed25519()
    cert, _ = issue_certificate("program_hash_demo", ["read_docs"], log, priv=priv)

    # level 1: offline integrity
    assert verify_certificate(cert, log)["ok"] is True

    # level 2: recompute -> the bound digest must reproduce bit-for-bit
    recompute = engine.run(PROMPT, n_new=N_NEW)
    assert recompute["model_digest"] == cert.model_digests[0]
