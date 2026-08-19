"""Userspace, kernel-free capability broker (adapted from the PoC).
Containment by construction: every side-effecting tool call routes through here,
and a tool the run wasn't granted is simply unreachable -- a jailbreak that reaches
an ungranted tool hits a wall, not a classifier. Each call is recorded to the event
log (with its result, so replay can re-inject it). No ML, no score, no bypass.
"""
from __future__ import annotations
import hashlib
from .events import EventLog, Kind

def _rh(x) -> str:
    return hashlib.blake2b(repr(x).encode(), digest_size=16).hexdigest()

class Broker:
    def __init__(self, capabilities, tools: dict, log: EventLog, replay=None):
        self.caps = set(capabilities)
        self.tools = tools
        self.log = log
        self.replay = replay        # if set: list of recorded tool results to re-inject

    def call(self, tool: str, *args):
        allowed = tool in self.caps
        if not allowed:
            self.log.append(Kind.TOOL_CALL, {"tool": tool, "args": list(args), "decision": "DENY"})
            return False, None
        if self.replay is not None:
            # external effect: DO NOT re-run the live tool; serve the recorded result
            result = self.replay.pop(0)
        else:
            result = self.tools[tool](*args)
        self.log.append(Kind.TOOL_CALL, {"tool": tool, "args": list(args),
                                         "decision": "ALLOW", "result": result, "result_hash": _rh(result)})
        return True, result

def recorded_tool_results(log: EventLog):
    """Extract the ordered list of ALLOW tool results, to feed a replay Broker."""
    return [e.payload["result"] for e in log.events
            if e.kind == Kind.TOOL_CALL.value and e.payload.get("decision") == "ALLOW"]
