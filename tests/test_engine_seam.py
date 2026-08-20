"""Engine <-> SDK seam.

A canned engine-JSON blob (exactly what the `vitni-receipt` binary prints), fed through
the SDK path, asserting every field the engine binds actually survives into the signed
receipt. This is the test the boundary lacked: after the tier-1 v2 change both repos were
individually correct, yet the regime the engine bound in its digest was dropped by the
SDK and never reached the receipt. The level-2 recompute tests skip without a GGUF and
the engine's inference_cert tests skip for the same reason, so nothing exercised
engine JSON -> SDK event -> signed receipt. A canned blob does, with no model required.
"""
import json
from vitnify.events import EventLog, Kind
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519

# Exactly the shape `vitni-receipt` (vitni-tensor >= 0.2.0) prints on stdout.
ENGINE_JSON = json.dumps({
    "model_digest": "a" * 64,          # tier-1 v2 digest
    "regime": "vitni-regime-1",        # the numerical regime it was produced under
    "model_digest_v1": "b" * 64,       # frozen v1 digest, for pre-regime receipts
    "weights_hash": "c" * 64,
    "tokens": [7, 8, 9],
})


def _receipt_from_engine_json(blob):
    """The documented flow: engine JSON -> append_llm_call -> issue_certificate."""
    step = json.loads(blob)
    log = EventLog()
    log.append_llm_call("ph", step["tokens"], seed=0,
                        model_digest=step["model_digest"], regime=step.get("regime"))
    priv, _ = gen_ed25519()
    cert, _ = issue_certificate("prog", [], log, priv=priv)
    return step, log, cert


def test_engine_fields_survive_into_the_receipt():
    step, log, cert = _receipt_from_engine_json(ENGINE_JSON)
    payload = log.events[0].payload
    assert payload["model_digest"] == step["model_digest"]
    assert payload["tokens"] == step["tokens"]
    # the seam bug: `regime` used to be dropped here and never reach the receipt.
    assert payload["regime"] == step["regime"] == "vitni-regime-1"
    # readable through the accessors a level-2 verifier uses
    assert log.model_digests() == [step["model_digest"]]
    assert log.model_regimes() == [step["regime"]]
    assert verify_certificate(cert, log)["ok"] is True


def test_regime_is_bound_not_just_recorded():
    # Binding is the point: tampering the regime must break the receipt, so no one can be
    # handed a receipt whose regime says one thing and whose digest was made under another.
    _step, log, cert = _receipt_from_engine_json(ENGINE_JSON)
    log.events[0].payload["regime"] = "vitni-regime-2"      # forge the recorded regime
    assert verify_certificate(cert, log)["ok"] is False     # Merkle root no longer matches


def test_regime_optional_for_hosted_or_pre_regime():
    # A step with no regime (hosted, or a pre-v2 engine) still records + verifies, and
    # model_regimes reports None for it — the absence is explicit, never silently gated.
    log = EventLog()
    log.append_llm_call("ph", [1, 2], seed=0, model_digest="d" * 64)   # no regime
    priv, _ = gen_ed25519()
    cert, _ = issue_certificate("prog", [], log, priv=priv)
    assert "regime" not in log.events[0].payload
    assert log.model_regimes() == [None]
    assert verify_certificate(cert, log)["ok"] is True
