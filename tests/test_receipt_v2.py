"""vitnify-receipt v2 -- issuance identity (F4) and hosted-provider binding (F7).

v2 adds `issued_at`, `nonce`, and `run_id` to the signed body so a receipt can be
placed in time and one run's receipt can't stand in for another's, and supports
recording hosted-provider identity on the model step so provider drift is
distinguishable from tampering.
"""
import copy

from vitnify.events import EventLog, Kind
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519, FORMAT


def _run():
    log = EventLog()
    log.append(Kind.TOOL_CALL, {"tool": "read_docs", "decision": "allow"})
    return log


def test_receipt_is_v2_and_carries_time_nonce_runid():
    priv, _ = gen_ed25519()
    log = _run()
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=priv)
    assert cert.v == FORMAT == "vitnify-receipt v2"
    assert cert.issued_at and cert.issued_at.endswith("Z")
    assert cert.nonce and cert.run_id
    body = cert.body()  # all three are inside the SIGNED body
    assert body["issued_at"] == cert.issued_at
    assert body["nonce"] == cert.nonce
    assert body["run_id"] == cert.run_id
    assert verify_certificate(cert, log)["ok"] is True


def test_run_id_is_honoured_when_supplied():
    priv, _ = gen_ed25519()
    cert, _ = issue_certificate("prog", ["read_docs"], _run(), priv=priv, run_id="case-42")
    assert cert.run_id == "case-42"


def test_tampering_time_nonce_or_runid_breaks_the_signature():
    priv, _ = gen_ed25519()
    log = _run()
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=priv)
    for f in ("issued_at", "nonce", "run_id"):
        forged = copy.deepcopy(cert)
        setattr(forged, f, "tampered")
        assert verify_certificate(forged, log)["ok"] is False


def test_hosted_provider_identity_is_bound_and_drift_is_detectable():
    # F7: recording provider identity binds it into the receipt's event root, so a
    # later check can tell a provider change apart from tampering.
    priv, _ = gen_ed25519()
    log = EventLog()
    log.append_llm_call("ph", [1, 2], seed=0, model_digest="",
                        provider={"provider": "openai", "model_version": "gpt-x-2026-01",
                                  "system_fingerprint": "fp_abc", "response_id": "resp_1"})
    cert, _ = issue_certificate("prog", [], log, priv=priv)
    assert verify_certificate(cert, log)["ok"] is True

    # A different provider fingerprint yields a different event root, so the original
    # receipt no longer matches -- drift is detected, and the bound provider fields
    # make it attributable to the backend rather than to forgery.
    drifted = EventLog()
    drifted.append_llm_call("ph", [1, 2], seed=0, model_digest="",
                            provider={"provider": "openai", "model_version": "gpt-x-2026-02",
                                      "system_fingerprint": "fp_XYZ", "response_id": "resp_2"})
    assert verify_certificate(cert, drifted)["ok"] is False
