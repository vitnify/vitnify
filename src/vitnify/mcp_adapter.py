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
import os
from .events import EventLog, Kind

try:  # optional dependency: needed only to talk to a REAL MCP client/server
    import mcp as _mcp  # noqa: F401
    _HAVE_MCP = True
    _IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    _HAVE_MCP = False
    _IMPORT_ERROR = exc


def require_mcp() -> None:
    """Raise a clear, actionable error if the 'mcp' package is not installed.

    ``MCPBroker`` is duck-typed -- it wraps any object exposing an async
    ``call_tool`` (a real ``mcp`` client or an in-memory fake), so it does not force
    this import. Call this when you specifically need the 'mcp' package present.
    """
    if not _HAVE_MCP:
        raise ImportError(
            "vitnify's MCP adapter needs the 'mcp' package for a real MCP "
            'client/server. Install it with:  pip install "vitnify[mcp]"'
        ) from _IMPORT_ERROR


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
    """Capability wall + record/replay around an MCP client's tool calls.

    SAFE BY DEFAULT: like the core :class:`~vitnify.capability.Broker`, this REDACTS --
    it commits SALTED hashes of args/results into the receipt and keeps the cleartext in
    an org-held :class:`~vitnify.redact.Vault` (``broker.vault``), so an MCP agent handling
    PHI/secrets never writes them into the signed record, on allow AND deny. Pass
    ``allow_cleartext=True`` to record payloads in cleartext (non-sensitive data only).
    """
    def __init__(self, client, capabilities, log: EventLog, *, vault=None,
                 allow_cleartext: bool = False, replay=None):
        self.client = client                 # an MCP Client
        self.caps = set(capabilities)
        self.log = log
        self.replay = replay                 # list of recorded ALLOW results, for replay
        self.allow_cleartext = allow_cleartext
        if allow_cleartext:
            self.vault = None
        else:
            from .redact import Vault        # lazy: keeps the optional-dependency import graph clean
            self.vault = vault if vault is not None else Vault()

    async def call_tool(self, name: str, arguments: dict | None = None):
        args = arguments or {}
        idx = len(self.log)

        if self.allow_cleartext:
            if name not in self.caps:        # ungranted MCP tool is unreachable
                self.log.append(Kind.TOOL_CALL, {"tool": name, "args": [args], "decision": "DENY"})
                return None
            result = self.replay.pop(0) if self.replay is not None \
                else _extract(await self.client.call_tool(name, args))
            self.log.append(Kind.TOOL_CALL, {"tool": name, "args": [args], "decision": "ALLOW",
                                             "result": result, "result_hash": _rh(result)})
            return result

        # SAFE DEFAULT: commit SALTED hashes; cleartext goes to the vault, not the receipt.
        from .redact import _commit
        asalt = os.urandom(16)
        if name not in self.caps:            # ungranted MCP tool is unreachable
            self.log.append(Kind.TOOL_CALL,
                            {"tool": name, "args_commit": _commit(asalt, [args]), "decision": "DENY"})
            self.vault.put(idx, args_salt=asalt, args=[args])
            return None
        result = self.replay.pop(0) if self.replay is not None \
            else _extract(await self.client.call_tool(name, args))
        rsalt = os.urandom(16)
        self.log.append(Kind.TOOL_CALL,
                        {"tool": name, "args_commit": _commit(asalt, [args]),
                         "decision": "ALLOW", "result_commit": _commit(rsalt, result)})
        self.vault.put(idx, args_salt=asalt, args=[args], result_salt=rsalt, result=result)
        return result


def recorded_mcp_results(log: EventLog, vault=None):
    """Ordered ALLOW results, to feed a replay MCPBroker. For a redacted log the cleartext
    results are in the vault -- pass it; a cleartext log reads them straight from the events."""
    out = []
    for e in log.events:
        if e.kind == Kind.TOOL_CALL.value and e.payload.get("decision") == "ALLOW":
            if "result" in e.payload:
                out.append(e.payload["result"])
            elif vault is not None:
                out.append(vault.get(e.i)["result"])
    return out
