"""Level-1 integrity verification.

A pristine receipt verifies. Every mutation of the log or the receipt -- editing,
reordering, truncating, forging an event; swapping a bound model_digest; flipping a
byte of the signature -- must be REJECTED. Verification recomputes everything from the
raw events and trusts nothing.
"""
from __future__ import annotations

import copy

import pytest

from vitnium.events import EventLog, Event, Kind
from vitnium.certificate import issue_certificate, verify_certificate

from conftest import CAPS, clone, tool_idx


def test_pristine_receipt_verifies(signed):
    cert, log = signed[0], signed[1]
    checks = verify_certificate(cert, log)
    assert checks["ok"] is True
    assert all(checks.values())
    for k in ("format", "root_matches", "head_matches", "count_matches",
              "model_digests_match", "sig_valid"):
        assert checks[k] is True, k


# ---- log mutations: verify the ORIGINAL cert against the tampered log ----
_LOG_MUTATIONS = {
    "edit_an_event":
        lambda log: log.events[0].payload.__setitem__("prompt_hash", "deadbeef"),
    "reorder_events":
        lambda log: log.events.__setitem__(slice(1, 3), log.events[1:3][::-1]),
    "truncate_the_log":
        lambda log: log.events.pop(),
    "delete_a_middle_event":
        lambda log: log.events.pop(1),
    "forge_an_appended_event":
        lambda log: log.events.append(
            Event(len(log.events), Kind.TOOL_CALL.value,
                  {"tool": "send_external", "decision": "ALLOW", "result": "SENT"},
                  log.events[-1].hash)),
    "edit_a_tool_argument":
        lambda log: log.events[tool_idx(log, "read_public", "ALLOW")]
        .payload.__setitem__("args", ["forged"]),
    "edit_a_tool_result":
        lambda log: log.events[tool_idx(log, "read_public", "ALLOW")]
        .payload.__setitem__("result", "forged"),
    "flip_deny_to_allow":
        lambda log: log.events[tool_idx(log, "read_secret", "DENY")]
        .payload.__setitem__("decision", "ALLOW"),
    "edit_committed_logit_hashes":
        lambda log: log.events[0].payload.__setitem__("logit_hashes", ["x", "y", "z"]),
    "edit_an_entropy_event":
        lambda log: log.events[-1].payload.__setitem__("value", "0x9999"),
}


@pytest.mark.parametrize("mutate", list(_LOG_MUTATIONS.values()), ids=list(_LOG_MUTATIONS))
def test_every_log_mutation_is_rejected(signed, mutate):
    cert, log = signed[0], signed[1]
    tampered = clone(log)
    mutate(tampered)
    assert verify_certificate(cert, tampered)["ok"] is False


def test_model_digest_swap_is_rejected(ed_keys):
    priv, _ = ed_keys
    log = EventLog()
    log.append_llm_call("ph0", [1, 2, 3], seed=0, model_digest="d_real")
    cert, _ = issue_certificate("prog", CAPS, log, priv=priv)
    assert verify_certificate(cert, log)["ok"] is True

    forged = clone(log)
    forged.events[0].payload["model_digest"] = "d_swapped"
    checks = verify_certificate(cert, forged)
    assert checks["model_digests_match"] is False
    assert checks["ok"] is False


def test_flipping_a_signature_byte_is_rejected(signed):
    cert, log = signed[0], signed[1]
    forged = copy.deepcopy(cert)
    # flip the first hex nibble of the signature
    forged.sig = ("1" if cert.sig[0] == "0" else "0") + cert.sig[1:]
    checks = verify_certificate(forged, log)
    assert checks["sig_valid"] is False
    assert checks["ok"] is False


def test_tampering_capabilities_in_the_receipt_is_rejected(signed):
    cert, log = signed[0], signed[1]
    forged = copy.deepcopy(cert)
    forged.capabilities = list(cert.capabilities) + ["send_external"]
    # digest now differs from what was signed -> signature no longer matches
    checks = verify_certificate(forged, log)
    assert checks["sig_valid"] is False
    assert checks["ok"] is False


def test_wrong_format_string_is_rejected(signed):
    cert, log = signed[0], signed[1]
    forged = copy.deepcopy(cert)
    forged.v = "vitnium-receipt v2"
    assert verify_certificate(forged, log)["ok"] is False
