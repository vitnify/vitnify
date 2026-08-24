"""ed25519 signing: self-verifiable round-trip, wrong-key / pinned-anchor rejection,
signature tamper rejection, and the HMAC fallback path."""
from __future__ import annotations

import copy

import pytest

from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519

from conftest import CAPS


def test_sign_verify_round_trip(signed):
    cert, log, priv, pub, _ = signed
    assert cert.sig_alg == "ed25519"
    assert cert.pubkey == pub          # the verifier's own key is embedded
    checks = verify_certificate(cert, log, require_authority=False)
    assert checks["sig_valid"] is True
    assert checks["ok"] is True


def test_signature_verifies_against_the_embedded_public_key_only(signed):
    # No secret and no external key are passed to verify_certificate.
    cert, log = signed[0], signed[1]
    assert verify_certificate(cert, log, require_authority=False)["sig_valid"] is True


def test_corrupted_signature_is_rejected(signed):
    cert, log = signed[0], signed[1]
    forged = copy.deepcopy(cert)
    forged.sig = "0" * len(cert.sig)
    assert verify_certificate(forged, log, require_authority=False)["sig_valid"] is False


def test_resigned_with_a_different_key_fails_a_pinned_anchor(signed):
    cert, log, priv, pub, _ = signed
    priv2, pub2 = gen_ed25519()
    resigned = copy.deepcopy(cert)
    resigned.sign_ed25519(priv2)
    # Internally consistent (integrity + signer continuity)...
    assert verify_certificate(resigned, log, require_authority=False)["sig_valid"] is True
    # ...but a verifier that PINS the expected key rejects the new signer.
    assert resigned.pubkey != pub
    assert resigned.pubkey == pub2


def test_wrong_public_key_does_not_validate_the_signature(signed):
    cert, log = signed[0], signed[1]
    _, pub2 = gen_ed25519()
    forged = copy.deepcopy(cert)
    forged.pubkey = pub2               # keep the original signature, swap the key
    assert verify_certificate(forged, log, require_authority=False)["sig_valid"] is False


def test_hmac_fallback_round_trip_and_wrong_key(agent_log):
    key = b"demo-signing-key"
    cert, _ = issue_certificate("prog", CAPS, agent_log, key=key)
    assert cert.sig_alg == "hmac-blake2b"
    assert verify_certificate(cert, agent_log, key=key, require_authority=False)["sig_valid"] is True
    assert verify_certificate(cert, agent_log, key=b"wrong-key", require_authority=False)["sig_valid"] is False
