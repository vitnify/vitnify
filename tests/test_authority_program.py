"""Finding C (program_hash actually binds) and finding B (signer authority via pinning)."""
import copy
from vitnify.events import EventLog, Kind
from vitnify.certificate import (issue_certificate, verify_certificate, verify_authorized,
                                  derive_program_hash, gen_ed25519)


def _log():
    log = EventLog()
    log.append(Kind.TOOL_CALL,
               {"tool": "read", "decision": "allow", "result": "ok", "result_hash": "x"})
    return log


# ---------------- C: program_hash binds the ACTUAL program ----------------
def test_derive_program_hash_is_deterministic_and_content_sensitive():
    a = derive_program_hash(b"agent code v1")
    assert a.startswith("sha256:")
    assert a == derive_program_hash(b"agent code v1")
    assert a != derive_program_hash(b"agent code v2")


def test_program_matches_when_receipt_names_real_code():
    log, (priv, _) = _log(), gen_ed25519()
    code = b"def agent(): ..."
    cert, _ = issue_certificate(derive_program_hash(code), ["read"], log, priv=priv)
    r = verify_certificate(cert, log, program=code)
    assert r["program_matches"] is True and r["ok"] is True


def test_wrong_program_fails_closed():
    log, (priv, _) = _log(), gen_ed25519()
    cert, _ = issue_certificate(derive_program_hash(b"real"), ["read"], log, priv=priv)
    r = verify_certificate(cert, log, program=b"different")
    assert r["program_matches"] is False and r["ok"] is False


def test_arbitrary_program_hash_does_not_bind_real_code():
    # finding C: a caller-asserted "literally anything I type here" verifies -- UNTIL a
    # verifier checks it against the actual program.
    log, (priv, _) = _log(), gen_ed25519()
    cert, _ = issue_certificate("literally anything I type here", ["read"], log, priv=priv)
    assert verify_certificate(cert, log)["ok"] is True                        # unbound: passes
    assert verify_certificate(cert, log, program=b"real code")["ok"] is False  # bound: caught


# ---------------- B: signer authority requires a pinned anchor ----------------
def test_authorized_accepts_pinned_signer():
    log, (priv, pub) = _log(), gen_ed25519()
    cert, _ = issue_certificate("p", ["read"], log, priv=priv)
    assert verify_authorized(cert, log, [pub])["ok"] is True


def test_authorized_rejects_resigned_forgery():
    log, (priv, pub) = _log(), gen_ed25519()
    cert, _ = issue_certificate("p", ["read"], log, priv=priv)
    priv2, _ = gen_ed25519()
    forged = copy.deepcopy(cert)
    forged.sign_ed25519(priv2)                                   # re-sign with attacker key
    assert verify_certificate(forged, log)["ok"] is True          # self-verifies (the limitation)
    assert verify_authorized(forged, log, [pub])["ok"] is False   # not on the pinned allow-list


def test_authorized_fails_closed_without_a_pin():
    log, (priv, _) = _log(), gen_ed25519()
    cert, _ = issue_certificate("p", ["read"], log, priv=priv)
    assert verify_authorized(cert, log, [])["ok"] is False
    assert verify_authorized(cert, log, None)["ok"] is False
