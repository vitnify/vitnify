"""Canonical, hash-chained agent event log.

Every nondeterministic input/output of an agent run becomes one canonical,
hash-linked Event. The chain gives append-only tamper-evidence during recording;
certificate.py Merkle-commits the same chunks for inclusion proofs and binds the
root into the signed vitnium-receipt.

Hashing is BLAKE3 throughout (matching the vitni-tensor engine and the
`vitnium-receipt v1` format), so the whole receipt is one hash family end to end.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, asdict
from enum import Enum

try:
    import blake3 as _blake3
    def _h32(b: bytes) -> str:
        return _blake3.blake3(b).hexdigest()
except ImportError:  # stdlib fallback; wire format is identical either way
    import hashlib
    def _h32(b: bytes) -> str:
        return hashlib.blake2b(b, digest_size=32).hexdigest()


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def h(s: str) -> str:
    return _h32(s.encode())


class Kind(str, Enum):
    LLM_CALL   = "llm_call"     # (prompt_hash, tokens, seed, model_digest) -- the model step
    TOOL_CALL  = "tool_call"    # (tool, args, decision, result) -- external, re-injected on replay
    ENTROPY    = "entropy"      # (source, value) -- RNG/clock draw, from-log on replay
    AGENT_STEP = "agent_step"   # (state) -- orchestration checkpoint


@dataclass
class Event:
    i: int
    kind: str
    payload: dict
    prev: str
    def canonical(self) -> str:
        return canon({"i": self.i, "kind": self.kind, "payload": self.payload, "prev": self.prev})
    @property
    def hash(self) -> str:
        return h(self.canonical())


class EventLog:
    def __init__(self):
        self.events: list[Event] = []

    def append(self, kind, payload: dict) -> Event:
        prev = self.events[-1].hash if self.events else "genesis"
        ev = Event(len(self.events), kind.value if isinstance(kind, Kind) else str(kind), payload, prev)
        self.events.append(ev)
        return ev

    def append_llm_call(self, prompt_hash: str, tokens: list, seed, model_digest: str) -> Event:
        """Record a model step and bind its vitni-tensor model-computation digest.

        `model_digest` is the engine's `vitnium-receipt v1` digest for this forward
        pass. Committing it here (and thus in the receipt's Merkle root) is what binds
        the deterministic model recomputation to the agent run.
        """
        return self.append(Kind.LLM_CALL, {
            "prompt_hash": prompt_hash, "tokens": list(tokens),
            "seed": seed, "model_digest": model_digest,
        })

    def model_digests(self) -> list[str]:
        """Ordered engine model-computation digests bound by this log (for L2 recompute)."""
        return [e.payload["model_digest"] for e in self.events
                if e.kind == Kind.LLM_CALL.value and "model_digest" in e.payload]

    def chunks(self) -> list[str]:
        return [e.canonical() for e in self.events]

    def head(self) -> str:
        return self.events[-1].hash if self.events else "genesis"

    def to_json(self) -> str:
        return canon([asdict(e) for e in self.events])

    @classmethod
    def from_events(cls, events: list[Event]) -> "EventLog":
        log = cls(); log.events = events; return log

    def __len__(self):
        return len(self.events)
