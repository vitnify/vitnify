"""Canonical, hash-chained agent event log.

Every nondeterministic input/output of an agent run becomes one canonical,
hash-linked Event. The chain gives append-only tamper-evidence during recording;
certificate.py Merkle-commits the same chunks for inclusion proofs and binds the
root into the signed vitnify-receipt.

Hashing is BLAKE3 throughout (matching the vitni-tensor engine and the
`vitnify-receipt v1` format), so the whole receipt is one hash family end to end.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, asdict
from enum import Enum

# BLAKE3 is a hard dependency and DEFINES the wire format: a blake2b digest is a
# different value, so there is no silent stdlib fallback -- one would make honest
# receipts indistinguishable from forgeries across implementations (and the receipt
# carries no hash-suite identifier to tell them apart). A normal `pip install
# vitnify` always resolves the wheel; a missing blake3 fails loudly, not silently.
import blake3 as _blake3
def _h32(b: bytes) -> str:
    return _blake3.blake3(b).hexdigest()


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def h(s: str) -> str:
    return _h32(s.encode())


class Kind(str, Enum):
    LLM_CALL   = "llm_call"     # (prompt_hash, tokens, seed, model_digest, regime, weights_hash) -- the model step
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

    def append_llm_call(self, prompt_hash: str, tokens: list, seed, model_digest: str,
                        *, regime: str | None = None, weights_hash: str | None = None,
                        provider: dict | None = None) -> Event:
        """Record a model step and bind its vitni-tensor model-computation digest.

        `model_digest` is the engine's tier-1 (`vitnify-receipt v2`) digest for this
        forward pass. Committing it here (and thus in the receipt's Merkle root) is what
        binds the deterministic model recomputation to the agent run.

        `regime` and `weights_hash` are the two engine inputs the digest depends on but
        cannot be read back out of it: the numerical-regime identifier (e.g.
        `vitni-regime-1`) and the BLAKE3 of the model weights. Both are folded into the
        engine's `model_digest`, so both are *bound* -- but a bare digest mismatch on L2
        recompute cannot say which one moved. Recording them here makes each one *readable*
        as well, so a verifier reports "regime-1 vs regime-2" or "wrong weights"
        (`weights_hash` differs) instead of an opaque mismatch indistinguishable from
        tampering. Pass the engine's `regime` and `weights_hash` fields through.

        For a HOSTED model there is no reproducible computation to bind. Pass
        `provider` to record who produced the output -- e.g. {"provider": "openai",
        "model_version": ..., "response_id": ..., "system_fingerprint": ...}.
        Binding it lets a later check tell a provider change (version/backend drift)
        apart from tampering. Hosted receipts are integrity-only: do not replay them
        as a control (see the spec's hosted-model note).
        """
        payload = {"prompt_hash": prompt_hash, "tokens": list(tokens),
                   "seed": seed, "model_digest": model_digest}
        if regime is not None:
            payload["regime"] = regime
        if weights_hash is not None:
            payload["weights_hash"] = weights_hash
        if provider:
            payload["provider"] = dict(provider)
        return self.append(Kind.LLM_CALL, payload)

    def model_regimes(self) -> list:
        """Ordered numerical regimes each bound model step was produced under (None for a
        step that recorded none -- a hosted or pre-regime step). Lets an L2 verifier
        report a regime mismatch instead of an opaque digest mismatch."""
        return [e.payload.get("regime") for e in self.events
                if e.kind == Kind.LLM_CALL.value and "model_digest" in e.payload]

    def model_weights_hashes(self) -> list:
        """Ordered weights hashes each bound model step ran against (None if unrecorded).
        Lets an L2 verifier report "wrong weights" instead of an opaque digest mismatch."""
        return [e.payload.get("weights_hash") for e in self.events
                if e.kind == Kind.LLM_CALL.value and "model_digest" in e.payload]

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
