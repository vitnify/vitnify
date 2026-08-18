"""MCP adapter — route Model Context Protocol tool calls through a VitniReplay
capability broker + event log, so an MCP-based agent gets containment, recording,
deterministic replay, and a certificate. Works with ANY MCP Client (in-memory, or a
real MCP server over stdio/HTTP): you wrap client.call_tool().

This is the natural deployment shape for VitniReplay — an MCP gateway: agents point at
it, and every tool call is capability-checked, recorded, and certified before (if ever)
reaching the real MCP server.
"""
from __future__ import annotations
import hashlib
from .events import EventLog, Kind


def _rh(x) -> str:
    return hashlib.blake2b(repr(x).encode(), digest_size=16).hexdigest()


def _extract(result) -> str:
    """MCP call_tool result -> plain string (best-effort across content shapes)."""
    try:
        content = getattr(result, "content", result)
        if isinstance(content, list) and content:
            text = getattr(content[0], "text", None)
            if text is not None:
                return text
        sc = getattr(result, "structured_content", None)
        return str(sc) if sc is not None else str(content)
    except Exception:
        return str(result)


class MCPBroker:
    """Capability wall + record/replay around an MCP client's tool calls."""
    def __init__(self, client, capabilities, log: EventLog, replay=None):
        self.client = client                 # an MCP Client
        self.caps = set(capabilities)
        self.log = log
        self.replay = replay                 # list of recorded ALLOW results, for replay

    async def call_tool(self, name: str, arguments: dict | None = None):
        args = arguments or {}
        if name not in self.caps:            # ungranted MCP tool is unreachable
            self.log.append(Kind.TOOL_CALL, {"tool": name, "args": [args], "decision": "DENY"})
            return None
        if self.replay is not None:          # replay: re-inject, never re-call the server
            result = self.replay.pop(0)
        else:
            result = _extract(await self.client.call_tool(name, args))
        self.log.append(Kind.TOOL_CALL,
            {"tool": name, "args": [args], "decision": "ALLOW", "result": result, "result_hash": _rh(result)})
        return result


def recorded_mcp_results(log: EventLog):
    """Ordered ALLOW results, to feed a replay MCPBroker."""
    return [e.payload["result"] for e in log.events
            if e.kind == Kind.TOOL_CALL.value and e.payload.get("decision") == "ALLOW"]
