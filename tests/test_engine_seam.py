"""Engine <-> SDK seam.

A canned engine-JSON blob (exactly what the `vitni-receipt` binary prints), fed through
the SDK path, guarding that every field the engine emits is a DELIBERATE decision --
carried into the signed receipt (bound + readable) or on an explicit, commented
ignore-list. Adding an engine field forces a choice here instead of silently dropping it.

This exists because a fix landed on one side of the engine<->SDK seam and stopped: the
tier-1 v2 regime was bound in the engine's digest but the SDK dropped it, so it never
reached the receipt. The level-2 recompute tests skip without a GGUF, so nothing
exercised engine JSON -> SDK event -> signed receipt. The first version of this fixture
checked the fields someone remembered (model_digest, tokens, regime) and missed
weights_hash the same way the bug missed regime; it now iterates the blob's keys instead.
"""
import json
from vitnify.events import EventLog
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519

# Exactly the shape `vitni-receipt` (vitni-tensor >= 0.2.0) prints on stdout.
ENGINE_JSON = json.dumps({
    "model_digest": "a" * 64,          # tier-1 v2 digest
    "regime": "vitni-regime-1",        # the numerical regime it was produced under
    "model_digest_v1": "b" * 64,       # frozen v1 digest of the same run
    "weights_hash": "c" * 64,          # BLAKE3 of the model weights
    "tokens": [7, 8, 9],
})

# Every engine field must be exactly one of these. A NEW engine field breaks
# `test_every_engine_field_is_carried_or_ignored` until it is triaged into one.
CARRIED = {          # folded into the digest AND recorded in the llm_call payload (bound + readable)
    "model_digest", "tokens", "regime", "weights_hash",
}
IGNORED = {          # deliberately not carried -- with the reason
    "model_digest_v1": "the frozen v1 digest of the SAME run; the receipt binds the v2 "
                       "digest as model_digest and a v1-only verifier recomputes this "
                       "from the same inputs, so carrying it would duplicate, not add.",
}


def _receipt():
    step = json.loads(ENGINE_JSON)
    log = EventLog()
    log.append_llm_call("ph", step["tokens"], seed=0,
                        model_digest=step["model_digest"], regime=step.get("regime"),
                        weights_hash=step.get("weights_hash"))
    priv, _ = gen_ed25519()
    cert, _ = issue_certificate("prog", [], log, priv=priv)
    return step, log, cert


def test_every_engine_field_is_carried_or_ignored():
    # The class guard: force a decision on every field the engine emits, so a field can
    # never be silently dropped the way regime was.
    for field in json.loads(ENGINE_JSON):
        assert field in CARRIED or field in IGNORED, (
            f"engine emits {field!r} but it is neither carried into the receipt (CARRIED) "
            f"nor on the explicit ignore-list (IGNORED). Decide which and say why -- "
            f"silently dropping it is the bug this test exists to catch.")


def test_carried_fields_reach_the_receipt_and_accessors():
    step, log, cert = _receipt()
    payload = log.events[0].payload
    for field in CARRIED:
        if field in step:
            assert payload.get(field) == step[field], f"{field!r} did not survive into the payload"
    assert log.model_digests() == [step["model_digest"]]
    assert log.model_regimes() == [step["regime"]]
    assert log.model_weights_hashes() == [step["weights_hash"]]
    assert verify_certificate(cert, log)["ok"] is True


def test_carried_fields_are_bound_not_just_recorded():
    # Binding is the point: tampering a carried field must break the receipt, so no one is
    # handed a receipt whose regime/weights say one thing and whose digest was made under another.
    for field, forged in (("regime", "vitni-regime-2"), ("weights_hash", "0" * 64)):
        _step, log, cert = _receipt()
        log.events[0].payload[field] = forged
        assert verify_certificate(cert, log)["ok"] is False, f"tampering {field!r} did not break the receipt"


def test_absent_regime_and_weights_record_none_explicitly():
    # A hosted or pre-v2 step carries neither; the accessors report None so the absence is
    # explicit, never silently gated.
    log = EventLog()
    log.append_llm_call("ph", [1, 2], seed=0, model_digest="d" * 64)
    priv, _ = gen_ed25519()
    cert, _ = issue_certificate("prog", [], log, priv=priv)
    assert log.model_regimes() == [None]
    assert log.model_weights_hashes() == [None]
    assert verify_certificate(cert, log)["ok"] is True
