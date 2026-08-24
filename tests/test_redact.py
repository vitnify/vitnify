"""Redaction-by-default: PHI never enters the receipt (allow AND deny), disclosure is
selective and forgery-proof, and salting makes a low-entropy commitment unguessable."""
import os
from vitnify.events import EventLog
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519
from vitnify.redact import (RedactingBroker, Vault, disclose, verify_disclosure,
                            cleartext_leak, recorded_tool_results, _commit)

SECRET = "44-19-8823"   # a low-entropy MRN -- brute-forceable from a bare hash


def _run():
    log, vault = EventLog(), Vault()
    b = RedactingBroker(["read"], {"read": lambda x: {"mrn": x, "ok": True}}, log, vault)
    b.call("read", SECRET)                 # ALLOW: PHI in arg AND result
    b.call("send_ext", SECRET, "evil@x")   # DENY: PHI in the blocked call's args
    return log, vault


def _cert(log):
    priv, _ = gen_ed25519()
    return issue_certificate("sha256:p", ["read"], log, priv=priv)[0]


def test_no_cleartext_in_receipt_allow_or_deny():
    log, _ = _run()
    # the exact bytes the receipt binds carry no PHI -- including the blocked exfil call.
    assert cleartext_leak(log, [SECRET, "evil@x"]) == []


def test_receipt_still_verifies_and_contains():
    log, _ = _run()
    v = verify_certificate(_cert(log), log)
    assert v["ok"] and v["containment_enforced"] and v["caps_consistent"]


def test_selective_disclosure_verifies():
    log, vault = _run()
    cert = _cert(log)
    d = disclose(log, vault, 0)
    r = verify_disclosure(d, cert.event_root)
    assert r["ok"] and r["in_root"] and r["args_bind"] and r["result_bind"]
    assert d["reveal"]["args"] == [SECRET]


def test_doctored_value_disclosure_caught():
    log, vault = _run()
    cert = _cert(log)
    d = disclose(log, vault, 0)
    d["reveal"]["args"] = ["99-99-9999"]        # lie about the argument
    assert verify_disclosure(d, cert.event_root)["ok"] is False


def test_swapped_event_disclosure_caught():
    log, vault = _run()
    cert = _cert(log)
    d0, d1 = disclose(log, vault, 0), disclose(log, vault, 1)
    d0["event"] = d1["event"]                    # claim event-1 content under event-0 proof
    assert verify_disclosure(d0, cert.event_root)["ok"] is False


def test_denied_call_is_a_clean_denial_and_redacted():
    log, vault = _run()
    deny = [e for e in log.events if e.payload.get("decision") == "DENY"][0]
    # redacted: commitment present, NO cleartext, NO result key (so it is a clean denial)
    assert "args_commit" in deny.payload and "args" not in deny.payload
    assert "result" not in deny.payload and "result_hash" not in deny.payload


def test_salting_makes_commit_unguessable():
    a, b = os.urandom(16), os.urandom(16)
    assert _commit(a, [SECRET]) != _commit(b, [SECRET])   # same value, salt-dependent


def test_replay_reads_results_from_vault():
    log, vault = _run()
    assert recorded_tool_results(log, vault) == [{"mrn": SECRET, "ok": True}]
