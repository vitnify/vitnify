"""Redaction-by-default: keep tool payloads (PHI, secrets) out of the receipt.

The default :class:`~vitnify.capability.Broker` records tool ``args``/``result`` in
CLEARTEXT into the signed event log -- on ALLOW and DENY alike -- so an MRN or a
patient name ends up in the receipt, and a *blocked* exfiltration attempt still
writes its argument into the permanent record. :class:`RedactingBroker` instead
commits a SALTED hash of each payload and keeps the cleartext in an org-held
:class:`Vault` that never leaves the boundary. The receipt binds the commitments
(so the run stays fully bound and tamper-evident); cleartext is disclosed one event
at a time, with an inclusion proof, only when an auditor needs it -- and a doctored
disclosure is caught by the commitment.

Salting is not optional: a bare hash of a 10-digit MRN is brute-forceable in
seconds, so an unsalted commit is NOT redaction. Each field gets a fresh random
salt, held only in the vault.

Containment is unchanged: an ungranted tool is still unreachable, and every call is
still recorded as an allow/deny at the wall -- the record just carries commitments
instead of cleartext, so ``verify_certificate`` sees the same containment evidence.
"""
from __future__ import annotations
import os
import json

import blake3 as _blake3

from .events import EventLog, Kind, canon
from ._vendor.pck.cas import MerkleCAS, InclusionProof, hash_text, verify_proof

_ABSENT = object()
_SALT_BYTES = 16


def _commit(salt: bytes, value) -> str:
    """Salted BLAKE3 commitment over a canonical encoding of ``value``.

    ``H(salt || canon(value))``. The salt (held only in the vault) is what stops a
    low-entropy value -- a 10-digit MRN, a short name -- from being recovered by
    brute force from the commitment.
    """
    return _blake3.blake3(salt + canon(value).encode()).hexdigest()


class Vault:
    """Org-held cleartext store, keyed by event index. Stays inside the boundary; the
    receipt binds only salted commitments, never these bytes. In production this is a
    local encrypted store the hospital/bank controls -- not something the SDK ships to
    a third party."""

    def __init__(self):
        self._store: dict[int, dict] = {}

    def put(self, idx: int, *, args_salt: bytes, args, result_salt: bytes | None = None,
            result=_ABSENT) -> None:
        rec = {"args_salt": args_salt.hex(), "args": args}
        if result is not _ABSENT:
            rec["result_salt"] = result_salt.hex()
            rec["result"] = result
        self._store[idx] = rec

    def get(self, idx: int) -> dict | None:
        return self._store.get(idx)

    def __contains__(self, idx: int) -> bool:
        return idx in self._store

    def __len__(self) -> int:
        return len(self._store)


class RedactingBroker:
    """Capability broker that commits SALTED hashes of args/results instead of the
    cleartext. Same wall as :class:`~vitnify.capability.Broker` -- an ungranted tool
    is unreachable and every call is recorded -- but no payload enters the receipt."""

    def __init__(self, capabilities, tools: dict, log: EventLog, vault: Vault, replay=None):
        self.caps = set(capabilities)
        self.tools = tools
        self.log = log
        self.vault = vault
        self.replay = replay  # if set: recorded ALLOW results to re-inject (from the vault)

    def call(self, tool: str, *args):
        args = list(args)
        idx = len(self.log)
        asalt = os.urandom(_SALT_BYTES)
        if tool not in self.caps:
            # DENY: commit the args (salted); record NO cleartext and NO result key, so
            # this is a clean denial to the verifier. The blocked call's argument -- an
            # MRN, an address, a wire amount -- never enters the receipt.
            self.log.append(Kind.TOOL_CALL,
                            {"tool": tool, "args_commit": _commit(asalt, args), "decision": "DENY"})
            self.vault.put(idx, args_salt=asalt, args=args)
            return False, None
        result = self.replay.pop(0) if self.replay is not None else self.tools[tool](*args)
        rsalt = os.urandom(_SALT_BYTES)
        self.log.append(Kind.TOOL_CALL,
                        {"tool": tool, "args_commit": _commit(asalt, args),
                         "decision": "ALLOW", "result_commit": _commit(rsalt, result)})
        self.vault.put(idx, args_salt=asalt, args=args, result_salt=rsalt, result=result)
        return True, result


def recorded_tool_results(log: EventLog, vault: Vault) -> list:
    """ALLOW results for a replay, read from the org's vault (the receipt carries only
    commitments). Ordered like the ALLOW events -- feeds a replay broker."""
    return [vault.get(e.i)["result"] for e in log.events
            if e.kind == Kind.TOOL_CALL.value and e.payload.get("decision") == "ALLOW"]


def cleartext_leak(log: EventLog, needles) -> list:
    """Any ``needle`` (an MRN, a name) that appears in cleartext in the EXACT bytes the
    receipt binds (the Merkle-committed chunks). Empty list == nothing leaked."""
    blob = "".join(log.chunks())
    return [n for n in needles if str(n) in blob]


def disclose(log: EventLog, vault: Vault, idx: int) -> dict:
    """A single-event disclosure the org hands an auditor: the event, its inclusion
    proof against the receipt's signed ``event_root``, and the salted cleartext from
    the vault. Reveals ONLY event ``idx`` -- no other event's payload is exposed."""
    v = vault.get(idx)
    if v is None:
        raise KeyError(f"no vault record for event {idx}")
    proof = MerkleCAS(log.chunks()).prove_index(idx)
    return {"index": idx, "event": log.events[idx].canonical(),
            "proof": proof.to_json(), "reveal": dict(v)}


def verify_disclosure(disc: dict, root: str) -> dict:
    """Verify a disclosure against a receipt's signed ``event_root``. ``ok`` iff the
    disclosed event is in the root AND every revealed field re-derives the commitment
    recorded in that event. A doctored value (wrong cleartext, or a swapped event)
    fails -- ``in_root`` catches a swapped/edited event, the ``*_bind`` checks catch a
    doctored payload."""
    checks: dict = {}
    ev_canon = disc["event"]
    leaf = hash_text(ev_canon)
    proof = InclusionProof.from_json(disc["proof"])
    # 1. the disclosure is for THIS event, and this event is in the signed root.
    checks["in_root"] = bool(proof.leaf == leaf and verify_proof(leaf, proof.path, root))
    # 2. the revealed cleartext re-derives the commitments the event actually recorded.
    payload = json.loads(ev_canon)["payload"]
    reveal = disc.get("reveal", {})
    checks["args_bind"] = ("args_commit" not in payload) or (
        "args" in reveal and "args_salt" in reveal
        and _commit(bytes.fromhex(reveal["args_salt"]), reveal["args"]) == payload["args_commit"])
    checks["result_bind"] = ("result_commit" not in payload) or (
        "result" in reveal and "result_salt" in reveal
        and _commit(bytes.fromhex(reveal["result_salt"]), reveal["result"]) == payload["result_commit"])
    checks["ok"] = all(bool(v) for v in checks.values())
    return checks
