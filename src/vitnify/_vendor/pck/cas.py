"""Content-addressed store + Merkle ledger — the provenance backbone of PCK.

Every source chunk is addressed by its cryptographic hash. A Merkle tree over those
hashes yields a single ``root`` that attests the whole corpus. Any single chunk can
then carry an *inclusion proof*: a short path of sibling hashes that recomputes the
root. The guarantees this buys, and why they matter for AI answers:

  * **Tamper-evidence** — change one byte of one chunk and the root changes.
  * **Independent verifiability** — anyone holding the root can check a chunk's proof
    without trusting the party that produced it (no model, no server, no secret key).
  * **Fabrication is uncredentialed** — a made-up "source" has no leaf in the tree, so
    it cannot produce a valid proof. This is the cryptographic half of catching a
    hallucination: a grounded claim points at a chunk with a valid proof; an invented
    one cannot.

This mirrors the BLAKE3 + Merkle design of a native runtime's ``cas_store`` (whose real
Rust code is exercised in ``research/pck_provenance/``); here we keep a dependency-light
pure-Python implementation that uses ``blake3`` when available and falls back to
``hashlib.blake2b`` otherwise. The wire format of a proof is identical either way.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

try:  # BLAKE3 if the user has it (matches the substrate); else a stdlib fallback.
    import blake3 as _blake3  # type: ignore

    _HASH_NAME = "blake3"

    def _digest(b: bytes) -> str:
        return _blake3.blake3(b).hexdigest()
except Exception:  # pragma: no cover - depends on environment
    _HASH_NAME = "blake2b-256"

    def _digest(b: bytes) -> str:
        return hashlib.blake2b(b, digest_size=32).hexdigest()


HASH_NAME = _HASH_NAME


def hash_bytes(b: bytes) -> str:
    """Content address of raw bytes (hex)."""
    return _digest(b)


def hash_text(s: str) -> str:
    """Content address of a text chunk (UTF-8, hex)."""
    return _digest(s.encode("utf-8"))


def _hash_pair(left: str, right: str) -> str:
    """Internal Merkle node = hash of the concatenated child hex digests."""
    return _digest((left + right).encode("utf-8"))


# --- inclusion proof -------------------------------------------------------------

@dataclass(frozen=True)
class ProofStep:
    """One level of a Merkle inclusion path."""

    sibling: str      # hex digest of the sibling node
    on_right: bool    # True if the *current* node is the right child at this level

    def to_json(self) -> dict:
        return {"sibling": self.sibling, "on_right": self.on_right}

    @staticmethod
    def from_json(d: dict) -> "ProofStep":
        return ProofStep(sibling=d["sibling"], on_right=bool(d["on_right"]))


@dataclass(frozen=True)
class InclusionProof:
    """A self-contained proof that ``leaf`` is committed under ``root``.

    Carries everything a third party needs to re-verify against a *published* root:
    the leaf hash, the sibling path, and the index. No tree, server, or key required.
    """

    leaf: str
    index: int
    path: list[ProofStep]
    hash_name: str = HASH_NAME

    def verify(self, root: str) -> bool:
        return verify_proof(self.leaf, self.path, root)

    def to_json(self) -> dict:
        return {
            "leaf": self.leaf,
            "index": self.index,
            "hash": self.hash_name,
            "path": [s.to_json() for s in self.path],
        }

    @staticmethod
    def from_json(d: dict) -> "InclusionProof":
        return InclusionProof(
            leaf=d["leaf"],
            index=int(d["index"]),
            path=[ProofStep.from_json(s) for s in d["path"]],
            hash_name=d.get("hash", HASH_NAME),
        )


def verify_proof(leaf: str, path: list[ProofStep], root: str) -> bool:
    """Recompute the root from ``leaf`` and ``path``; True iff it equals ``root``."""
    h = leaf
    for step in path:
        h = _hash_pair(step.sibling, h) if step.on_right else _hash_pair(h, step.sibling)
    return h == root


# --- the tree / store ------------------------------------------------------------

@dataclass
class MerkleCAS:
    """Content-addressed store with a Merkle commitment over its chunks.

    Odd layers duplicate the final node (Bitcoin-style), so a proof always exists for
    every leaf. Construction is deterministic in the chunk order.
    """

    chunks: list[str]
    leaves: list[str] = field(default_factory=list)
    layers: list[list[str]] = field(default_factory=list)
    _index_of_hash: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.chunks:
            raise ValueError("MerkleCAS requires at least one chunk")
        self.leaves = [hash_text(c) for c in self.chunks]
        # first occurrence wins if a chunk repeats
        for i, h in enumerate(self.leaves):
            self._index_of_hash.setdefault(h, i)
        self.layers = self._build(self.leaves)

    @staticmethod
    def _build(leaves: list[str]) -> list[list[str]]:
        layers = [leaves[:]]
        while len(layers[-1]) > 1:
            cur = layers[-1]
            nxt = [
                _hash_pair(cur[i], cur[i + 1] if i + 1 < len(cur) else cur[i])
                for i in range(0, len(cur), 2)
            ]
            layers.append(nxt)
        return layers

    @property
    def root(self) -> str:
        return self.layers[-1][0]

    def index_of(self, chunk_or_hash: str) -> Optional[int]:
        """Index of a chunk by its raw text or by its hash; None if absent."""
        if chunk_or_hash in self._index_of_hash:
            return self._index_of_hash[chunk_or_hash]
        return self._index_of_hash.get(hash_text(chunk_or_hash))

    def contains(self, chunk_or_hash: str) -> bool:
        return self.index_of(chunk_or_hash) is not None

    def prove_index(self, idx: int) -> InclusionProof:
        if not 0 <= idx < len(self.leaves):
            raise IndexError(idx)
        path: list[ProofStep] = []
        i = idx
        for layer in self.layers[:-1]:
            sib = i ^ 1 if (i ^ 1) < len(layer) else i  # duplicated node is its own sibling
            path.append(ProofStep(sibling=layer[sib], on_right=bool(i & 1)))
            i //= 2
        return InclusionProof(leaf=self.leaves[idx], index=idx, path=path)

    def prove(self, chunk_or_hash: str) -> Optional[InclusionProof]:
        """Inclusion proof for a chunk (by text or hash); None if not in the corpus."""
        idx = self.index_of(chunk_or_hash)
        return None if idx is None else self.prove_index(idx)
