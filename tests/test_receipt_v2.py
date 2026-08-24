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
    assert verify_certificate(cert, log, require_authority=False)["ok"] is True


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
        assert verify_certificate(forged, log, require_authority=False)["ok"] is False


def test_hosted_provider_identity_is_bound_and_drift_is_detectable():
    # F7: recording provider identity binds it into the receipt's event root, so a
    # later check can tell a provider change apart from tampering.
    priv, _ = gen_ed25519()
    log = EventLog()
    log.append_llm_call("ph", [1, 2], seed=0, model_digest="",
                        provider={"provider": "openai", "model_version": "gpt-x-2026-01",
                                  "system_fingerprint": "fp_abc", "response_id": "resp_1"})
    cert, _ = issue_certificate("prog", [], log, priv=priv)
    assert verify_certificate(cert, log, require_authority=False)["ok"] is True

    # A different provider fingerprint yields a different event root, so the original
    # receipt no longer matches -- drift is detected, and the bound provider fields
    # make it attributable to the backend rather than to forgery.
    drifted = EventLog()
    drifted.append_llm_call("ph", [1, 2], seed=0, model_digest="",
                            provider={"provider": "openai", "model_version": "gpt-x-2026-02",
                                      "system_fingerprint": "fp_XYZ", "response_id": "resp_2"})
    assert verify_certificate(cert, drifted, require_authority=False)["ok"] is False


def test_v1_receipt_still_verifies_under_the_v2_verifier():
    # F8: a receipt validly signed under v1 (7-field body) must still verify -- a
    # published format is frozen and the product's premise is verify-years-later.
    from vitnify.certificate import ExecutionCertificate, _canon, _digest32
    from vitnify._vendor.pck.cas import MerkleCAS
    import copy
    priv, pub = gen_ed25519()
    log = _run()
    cas = MerkleCAS(log.chunks())
    v1_body = {"v": "vitnify-receipt v1", "program_hash": "prog",
               "capabilities": ["read_docs"], "event_root": cas.root,
               "n_events": len(log), "head_hash": log.head(),
               "model_digests": log.model_digests()}
    sig = priv.sign(bytes.fromhex(_digest32(_canon(v1_body).encode()))).hex()
    cert = ExecutionCertificate("prog", ["read_docs"], cas.root, len(log), log.head(),
                                model_digests=log.model_digests())
    cert.v, cert.sig, cert.sig_alg, cert.pubkey = "vitnify-receipt v1", sig, "ed25519", pub
    r = verify_certificate(cert, log, require_authority=False)
    assert r["format"] and r["sig_valid"] and r["ok"]          # v1 fully verifies
    bad = copy.deepcopy(cert); bad.program_hash = "evil"        # ...but tampering is caught
    assert verify_certificate(bad, log, require_authority=False)["ok"] is False


def test_f9_session_llm_records_provider():
    from vitnify.replayer import Session

    class _Tok:
        def decode(self, toks, skip_special_tokens=True):
            return "text"

    class _LM:
        tok = _Tok()
        def generate(self, prompt, n_new, batch_load, invariant):
            return [1, 2], ["h1", "h2"]

    s = Session(_LM(), caps=[], tools={}, invariant=True,
                provider={"provider": "openai", "model_version": "gpt-x"})
    s.llm("hi", n_new=2, provider={"response_id": "resp_1"})    # per-call merges with session default
    ev = next(e for e in s.log.events if e.kind == Kind.LLM_CALL.value)
    assert ev.payload["provider"] == {
        "provider": "openai", "model_version": "gpt-x", "response_id": "resp_1"}


def test_f10_v1_receipt_carrying_v2_fields_is_rejected():
    # F10: v1 does not sign issued_at/nonce/run_id, so a v1 receipt that CARRIES them
    # is carrying unsigned, forgeable data (e.g. a backdated timestamp) -- it must not
    # verify, or ok=True would bless a value outside the signature.
    from vitnify.certificate import ExecutionCertificate, _canon, _digest32
    from vitnify._vendor.pck.cas import MerkleCAS
    priv, pub = gen_ed25519()
    log = _run(); cas = MerkleCAS(log.chunks())
    b1 = {"v": "vitnify-receipt v1", "program_hash": "p", "capabilities": ["read_docs"],
          "event_root": cas.root, "n_events": len(log), "head_hash": log.head(),
          "model_digests": log.model_digests()}
    sig = priv.sign(bytes.fromhex(_digest32(_canon(b1).encode()))).hex()
    cert = ExecutionCertificate("p", ["read_docs"], cas.root, len(log), log.head(),
                                model_digests=log.model_digests())
    cert.v, cert.sig, cert.sig_alg, cert.pubkey = "vitnify-receipt v1", sig, "ed25519", pub
    assert verify_certificate(cert, log, require_authority=False)["ok"] is True            # genuine v1 still verifies
    cert.issued_at = "2019-01-01T00:00:00Z"                       # forge a backdated timestamp
    r = verify_certificate(cert, log, require_authority=False)
    assert r["fields_match_version"] is False and r["ok"] is False
