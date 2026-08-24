"""0.4.0 safe-by-default guards. If either default silently reverts to the unsafe
behaviour, one of these fails: the plain Broker must redact, and verify must require
signer authority."""
from vitnify.events import EventLog
from vitnify.capability import Broker
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519
from vitnify.redact import cleartext_leak

SSN = "SSN-123-45-6789"


def test_broker_redacts_by_default():
    log = EventLog()
    b = Broker(["read"], {"read": lambda x: x}, log)   # no allow_cleartext -> must redact
    b.call("read", SSN)                                # ALLOW
    b.call("send_ext", SSN)                            # DENY (blocked) -- args also redacted
    assert cleartext_leak(log, [SSN]) == []            # nothing in the receipt bytes
    assert b.vault is not None                         # cleartext went to the vault


def test_broker_cleartext_is_opt_in_only():
    log = EventLog()
    b = Broker(["read"], {"read": lambda x: x}, log, allow_cleartext=True)
    b.call("read", SSN)
    assert cleartext_leak(log, [SSN]) != []            # opt-out records cleartext


def test_verify_requires_authority_by_default():
    log = EventLog()
    Broker(["read"], {"read": lambda x: x}, log, allow_cleartext=True).call("read", "x")
    priv, pub = gen_ed25519()
    cert, _ = issue_certificate("p", ["read"], log, priv=priv)
    # default: no trust anchor -> fails closed on authority (a re-signed forgery can't pass)
    default = verify_certificate(cert, log)
    assert default["ok"] is False and default["signer_pinned"] is False
    # opt in to authority with a pin, or explicitly ask for integrity-only
    assert verify_certificate(cert, log, pinned_pubkeys=[pub])["ok"] is True
    assert verify_certificate(cert, log, require_authority=False)["ok"] is True


def test_verdict_split_distinguishes_unestablished_from_forged():
    """The verdict is SPLIT: a stranger with no trust root must tell an honest,
    integrity-verified receipt (authority unestablished) from a tampered or re-signed
    one -- a bare ok=False is indistinguishable from 'forged', which is the failure mode
    both 0.3.x and 0.4.0-pre-split fell into (opposite directions)."""
    import copy
    log = EventLog()
    Broker(["read"], {"read": lambda x: x}, log, allow_cleartext=True).call("read", "x")
    priv, pub = gen_ed25519()
    cert, _ = issue_certificate("p", ["read"], log, priv=priv)

    # HONEST, no pin: integrity holds; authority UNESTABLISHED (not False); ok=False.
    r = verify_certificate(cert, log)
    assert r["integrity_ok"] is True                       # a stranger CAN verify this offline
    assert r["authority_ok"] is None and "unestablished" in r["authority"]
    assert r["ok"] is False

    # FORGERY re-signed with an attacker key: integrity still self-consistent, but a
    # pinned verifier REJECTS the signer -> distinguishable from the honest case.
    forged = copy.deepcopy(cert)
    forged.sign_ed25519(gen_ed25519()[0])
    f = verify_certificate(forged, log, pinned_pubkeys=[pub])
    assert f["authority_ok"] is False and "rejected" in f["authority"] and f["ok"] is False

    # TAMPERED body: integrity itself breaks -- caught by anyone, no anchor needed.
    t = copy.deepcopy(cert)
    t.capabilities = list(t.capabilities) + ["send_ext"]
    assert verify_certificate(t, log)["integrity_ok"] is False


def test_integrity_tuple_is_fully_produced():
    """Every mandatory key folded into integrity_ok must actually be produced by the
    verifier. `integrity_ok` now fails CLOSED on a missing key, but assert coverage
    explicitly too so a dropped/typo'd check is a named failure, not a silent hole."""
    from vitnify.certificate import _INTEGRITY_KEYS
    log = EventLog()
    Broker(["read"], {"read": lambda x: x}, log, allow_cleartext=True).call("read", "x")
    priv, _ = gen_ed25519()
    cert, _ = issue_certificate("p", ["read"], log, priv=priv)
    result = verify_certificate(cert, log, require_authority=False)
    for k in _INTEGRITY_KEYS:
        assert k in result, f"integrity check {k!r} not produced by verify_certificate"
        assert result[k] is True
