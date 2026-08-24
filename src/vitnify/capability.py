"""Userspace, kernel-free capability broker. Containment by construction: every
side-effecting tool call routes through here, and a tool the run wasn't granted is
simply unreachable -- a jailbreak that reaches an ungranted tool hits a wall, not a
classifier. Every call (allow or deny) is recorded to the event log.

SAFE BY DEFAULT (0.4.0). The broker **redacts**: it commits a SALTED hash of each
tool's args/results into the receipt and keeps the cleartext in an org-held
:class:`~vitnify.redact.Vault` (``broker.vault``), so PHI/secrets never enter the
signed record -- on allow AND deny. Disclose one event at a time with an inclusion
proof (see :mod:`vitnify.redact`).

Pass ``allow_cleartext=True`` to record payloads in cleartext instead (the pre-0.4.0
behaviour) -- ONLY where the arguments and results are not sensitive; a redacted log
is the safe choice for regulated data.
"""
from __future__ import annotations
import hashlib
import os
from .events import EventLog, Kind


def _rh(x) -> str:
    return hashlib.blake2b(repr(x).encode(), digest_size=16).hexdigest()


class Broker:
    def __init__(self, capabilities, tools: dict, log: EventLog, *, vault=None,
                 allow_cleartext: bool = False, replay=None):
        self.caps = set(capabilities)
        self.tools = tools
        self.log = log
        self.replay = replay            # if set: recorded ALLOW results to re-inject
        self.allow_cleartext = allow_cleartext
        if allow_cleartext:
            self.vault = None
        else:
            from .redact import Vault   # lazy: avoids an import cycle (redact imports Broker)
            self.vault = vault if vault is not None else Vault()

    def call(self, tool: str, *args):
        args = list(args)
        allowed = tool in self.caps

        if self.allow_cleartext:
            # OPT-OUT: record payloads in cleartext (only for non-sensitive data).
            if not allowed:
                self.log.append(Kind.TOOL_CALL, {"tool": tool, "args": args, "decision": "DENY"})
                return False, None
            result = self.replay.pop(0) if self.replay is not None else self.tools[tool](*args)
            self.log.append(Kind.TOOL_CALL, {"tool": tool, "args": args, "decision": "ALLOW",
                                             "result": result, "result_hash": _rh(result)})
            return True, result

        # SAFE DEFAULT: commit SALTED hashes; cleartext goes to the vault, not the receipt.
        from .redact import _commit
        idx = len(self.log)
        asalt = os.urandom(16)
        if not allowed:
            self.log.append(Kind.TOOL_CALL,
                            {"tool": tool, "args_commit": _commit(asalt, args), "decision": "DENY"})
            self.vault.put(idx, args_salt=asalt, args=args)
            return False, None
        result = self.replay.pop(0) if self.replay is not None else self.tools[tool](*args)
        rsalt = os.urandom(16)
        self.log.append(Kind.TOOL_CALL,
                        {"tool": tool, "args_commit": _commit(asalt, args),
                         "decision": "ALLOW", "result_commit": _commit(rsalt, result)})
        self.vault.put(idx, args_salt=asalt, args=args, result_salt=rsalt, result=result)
        return True, result


def recorded_tool_results(log: EventLog):
    """ALLOW results for a replay, from a CLEARTEXT-mode log. For a redacted log the
    results are in the vault -- use :func:`vitnify.redact.recorded_tool_results(log, vault)`."""
    return [e.payload["result"] for e in log.events
            if e.kind == Kind.TOOL_CALL.value and e.payload.get("decision") == "ALLOW"
            and "result" in e.payload]
