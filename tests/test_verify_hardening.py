"""Verifier hardening -- fail-closed regression tests.

These lock in that `verify_certificate` never returns ok=True for a receipt it
did not cryptographically verify, and that it proves capability containment
rather than merely carrying a capability list. Each test corresponds to a
verification-bypass that must stay closed:

  F1  an unsigned receipt must not verify
  F2  an HMAC receipt must not verify when the verifier holds no key
  F3  an ALLOWED tool call outside the declared capabilities must not verify
  F5  optional key pinning rejects an unpinned (but otherwise valid) signer
"""
from vitnify.events import EventLog, Kind
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519


def _log(tool, decision):
    log = EventLog()
    log.append(Kind.TOOL_CALL, {"tool": tool, "decision": decision})
    return log


def test_honest_signed_receipt_verifies():
    priv, _ = gen_ed25519()
    log = _log("read_docs", "allow")
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=priv)
    assert verify_certificate(cert, log)["ok"] is True


def test_f1_unsigned_receipt_is_rejected():
    # A fabricated run with an approved wire_transfer and NO signature.
    log = _log("wire_transfer", "allow")
    cert, _ = issue_certificate("prog", ["wire_transfer"], log)  # no priv/key -> unsigned
    assert cert.sig_alg == "none"
    result = verify_certificate(cert, log)
    assert result["sig_valid"] is False
    assert result["ok"] is False


def test_f2_hmac_without_key_is_rejected():
    log = _log("read_docs", "allow")
    cert, _ = issue_certificate("prog", ["read_docs"], log, key=b"shared-secret")
    # verifier holds no key -> cannot check -> must not report success
    assert verify_certificate(cert, log)["ok"] is False
    # with the key it verifies
    assert verify_certificate(cert, log, key=b"shared-secret")["ok"] is True


def test_f3_allowed_tool_outside_caps_is_rejected():
    priv, _ = gen_ed25519()
    # properly signed, but declares only read_docs while ALLOWING wire_transfer
    log = _log("wire_transfer", "allow")
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=priv)
    result = verify_certificate(cert, log)
    assert result["sig_valid"] is True          # signature is fine...
    assert result["caps_consistent"] is False   # ...but containment is not proven
    assert result["ok"] is False


def test_denied_ungranted_tool_still_verifies():
    # A blocked call to an ungranted tool is the SYSTEM WORKING -- must verify.
    priv, _ = gen_ed25519()
    log = _log("send_email", "deny")
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=priv)
    assert verify_certificate(cert, log)["ok"] is True


def test_f5_signer_pinning():
    priv, pub = gen_ed25519()
    log = _log("read_docs", "allow")
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=priv)
    _, other_pub = gen_ed25519()
    assert verify_certificate(cert, log, pinned_pubkeys=[other_pub])["ok"] is False
    assert verify_certificate(cert, log, pinned_pubkeys=[pub])["ok"] is True
    # unpinned verification (no allow-list) still succeeds on integrity + self-sig
    assert verify_certificate(cert, log)["ok"] is True
