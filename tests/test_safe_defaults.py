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
