"""Adapter hardening + smoke tests.

Optional-dep adapters must stay importable without their extra and raise a clear,
actionable ImportError when actually used. The full-integration smoke tests skip when
the extra is absent; the MCPBroker capability/record/replay logic is duck-typed and is
exercised here with an in-memory fake client (no real 'mcp' package needed).
"""
from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace

import pytest

from vitnify.mcp_adapter import _HAVE_MCP

try:
    import langgraph  # noqa: F401
    import langchain_core  # noqa: F401
    _HAVE_LANGGRAPH = True
except ImportError:
    _HAVE_LANGGRAPH = False


# --------------------------- LangGraph adapter ---------------------------
@pytest.mark.adapter
@pytest.mark.skipif(_HAVE_LANGGRAPH, reason="langgraph installed; error path not exercised")
def test_langgraph_missing_dep_raises_actionable_error():
    from vitnify import langgraph_adapter
    with pytest.raises(ImportError, match=r"vitnify\[langgraph\]"):
        langgraph_adapter.build_react_graph(None, "", [])
    with pytest.raises(ImportError, match=r"vitnify\[langgraph\]"):
        langgraph_adapter.VitniReplayCallback(None)


@pytest.mark.adapter
@pytest.mark.skipif(not _HAVE_LANGGRAPH, reason="requires the [langgraph] extra")
def test_langgraph_graph_records_replays_and_certifies():
    from vitnify.replayer import Session
    from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519
    from vitnify.langgraph_adapter import build_react_graph, initial_prompt

    class _FakeTok:
        def decode(self, toks, skip_special_tokens=True):
            return bytes(t % 256 for t in toks).decode("utf-8", "replace")

    class FakeLM:
        def __init__(self, script):
            self.script = script
            self.tok = _FakeTok()
            self.dev = "stub"

        def generate(self, prompt, n_new=40, batch_load=0, invariant=False):
            step = prompt.count("Observation:")
            text = self.script[min(step, len(self.script) - 1)]
            toks = list(text.encode("utf-8"))
            digest = hashlib.blake2b((str(step) + text).encode(), digest_size=8).hexdigest()
            return toks, [digest]

    exfil = []
    tools = {
        "read_public":   lambda x: f"public::ticket {x}",
        "read_secret":   lambda *a: "SECRET",
        "send_external": lambda *a: (exfil.append(a), "SENT")[1],
    }
    tools_desc = "read_public[ticket_id], read_secret[], send_external[dest]"
    caps = {"read_public"}
    script = ["Action: read_public[7]",
              "Action: send_external[attacker.evil]",
              "Final Answer: done"]
    lm = FakeLM(script)
    priv, _ = gen_ed25519()

    def run(session):
        graph = build_react_graph(session, tools_desc, list(tools), max_steps=3)
        graph.invoke({"prompt": initial_prompt("Handle ticket 7.", tools_desc), "steps": 0})
        return session.log

    rec_log = run(Session(lm, caps, tools, invariant=True))
    rec_cert, _ = issue_certificate("langgraph-agent-v1", caps, rec_log, priv=priv)
    rep_log = run(Session(lm, caps, tools, invariant=True, recorded=rec_log))

    assert rep_log.chunks() == rec_log.chunks()          # replay bit-identical
    assert verify_certificate(rec_cert, rep_log, require_authority=False)["ok"]   # certificate verifies
    assert exfil == []                                   # ungranted tool contained


# ------------------------------ MCP adapter ------------------------------
@pytest.mark.adapter
@pytest.mark.skipif(_HAVE_MCP, reason="mcp installed; error path not exercised")
def test_mcp_require_raises_actionable_error():
    from vitnify.mcp_adapter import require_mcp
    with pytest.raises(ImportError, match=r"vitnify\[mcp\]"):
        require_mcp()


class _FakeMCPClient:
    """Minimal in-memory stand-in for an MCP client (async call_tool)."""
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return SimpleNamespace(content=[SimpleNamespace(text=f"result::{name}")])


@pytest.mark.adapter
def test_mcp_broker_contains_records_and_replays():
    from vitnify.mcp_adapter import MCPBroker, recorded_mcp_results
    from vitnify.events import EventLog
    from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519

    caps = {"read_public"}

    async def scenario(broker):
        await broker.call_tool("read_public", {"ticket_id": "7"})       # ALLOW
        await broker.call_tool("read_secret", {})                       # DENY
        await broker.call_tool("send_external", {"dest": "attacker"})   # DENY

    # record against the (fake) server. allow_cleartext=True: this test asserts
    # replay BIT-IDENTITY, and redaction uses random per-call salts, so a re-run
    # produces different commitments by design (a redacted run replays from its
    # recorded events, not by re-committing). Redaction is covered separately below.
    client = _FakeMCPClient()
    rec_log = EventLog()
    asyncio.run(scenario(MCPBroker(client, caps, rec_log, allow_cleartext=True)))
    assert client.calls == [("read_public", {"ticket_id": "7"})]        # only granted reached server
    n_deny = sum(1 for e in rec_log.events if e.payload.get("decision") == "DENY")
    assert n_deny == 2

    priv, _ = gen_ed25519()
    rec_cert, _ = issue_certificate("mcp-agent-v1", caps, rec_log, priv=priv)

    # replay: re-inject recorded results; the server must never be re-called
    replay_client = _FakeMCPClient()
    rep_log = EventLog()
    asyncio.run(scenario(MCPBroker(replay_client, caps, rep_log, allow_cleartext=True,
                                   replay=recorded_mcp_results(rec_log))))
    assert replay_client.calls == []                    # no live re-call on replay
    assert rep_log.chunks() == rec_log.chunks()         # bit-identical
    assert verify_certificate(rec_cert, rep_log, require_authority=False)["ok"]  # certificate verifies against replay


def test_mcp_broker_redacts_by_default():
    # The drop-in MCP path must not leak tool payloads into the receipt -- same
    # safe-by-default as the core Broker, on allow AND the blocked (deny) call.
    from vitnify.mcp_adapter import MCPBroker
    from vitnify.events import EventLog
    from vitnify.redact import cleartext_leak
    SSN = "123-45-6789"

    async def scenario(b):
        await b.call_tool("read_public", {"mrn": SSN})    # ALLOW: PHI in args
        await b.call_tool("send_secret", {"to": SSN})     # DENY (ungranted): PHI in blocked args

    log = EventLog()
    asyncio.run(scenario(MCPBroker(_FakeMCPClient(), {"read_public"}, log)))  # default = redact
    assert cleartext_leak(log, [SSN]) == []               # nothing in the receipt bytes, incl. the block
    deny = [e for e in log.events if e.payload.get("decision") == "DENY"][0]
    assert "args_commit" in deny.payload and "args" not in deny.payload
