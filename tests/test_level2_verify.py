"""Level-2 diagnostics — `verify_level2` recomputes each bound model step and, using the
receipt's readable `regime`/`weights_hash`, reports WHY a mismatch happened rather than an
opaque "digest mismatch".

Driven by a stub engine so the diagnostic ordering runs in CI without a GGUF; the
real-weights reproduction is in `test_l2_recompute.py`. (The spec specifies this ordering;
this asserts the shipped code implements it.)
"""
import pytest

from vitnify.events import EventLog
from vitnify.engine import prompt_hash, verify_level2

PROMPT = [1, 2, 3]
OUT = [4, 5, 6]
D = "d" * 64          # bound model_digest
W = "w" * 64          # bound weights_hash
R = "vitni-regime-1"  # bound regime


class StubEngine:
    """Returns a canned engine JSON, letting each test drive one diagnostic branch."""
    def __init__(self, model_digest, regime, weights_hash):
        self._j = {"model_digest": model_digest, "regime": regime,
                   "weights_hash": weights_hash, "tokens": OUT}

    def run(self, prompt_tokens, n_new=16):
        return dict(self._j)


def _log(regime=R, weights=W, digest=D):
    log = EventLog()
    log.append_llm_call(prompt_hash(PROMPT), OUT, seed=0,
                        model_digest=digest, regime=regime, weights_hash=weights)
    return log


def test_reproduced_when_engine_matches():
    r = verify_level2(_log(), StubEngine(D, R, W), [(PROMPT, 3)])
    assert r == [{"ok": True, "reason": "reproduced"}]


def test_wrong_weights_diagnosed_before_digest():
    # different weights (and therefore a different digest): must read "wrong_weights".
    r = verify_level2(_log(), StubEngine("z" * 64, R, "a" * 64), [(PROMPT, 3)])
    assert r[0]["ok"] is False and r[0]["reason"] == "wrong_weights"


def test_regime_mismatch_diagnosed_before_digest():
    # same weights, different regime (and digest): must read "regime_mismatch".
    r = verify_level2(_log(), StubEngine("z" * 64, "vitni-regime-2", W), [(PROMPT, 3)])
    assert r[0]["reason"] == "regime_mismatch"


def test_digest_mismatch_only_when_weights_and_regime_match():
    # same weights AND regime but a different digest -> tampering / a real reproduction
    # failure, reported as "digest_mismatch" and nothing softer.
    r = verify_level2(_log(), StubEngine("z" * 64, R, W), [(PROMPT, 3)])
    assert r[0]["reason"] == "digest_mismatch"


def test_prompt_mismatch_when_wrong_prompt_supplied():
    # the supplied prompt is not the one the receipt bound -> caught before recompute.
    r = verify_level2(_log(), StubEngine(D, R, W), [([9, 9, 9], 3)])
    assert r[0]["reason"] == "prompt_mismatch"


def test_step_count_must_match_llm_events():
    with pytest.raises(ValueError):
        verify_level2(_log(), StubEngine(D, R, W), [])
