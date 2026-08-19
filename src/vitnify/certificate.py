"""vitnify-receipt v1 -- the signed, self-verifying execution receipt.

One receipt binds an agent run into a single object:

    program hash | granted capabilities | hash-chained event log (Merkle root + head)
    | the engine's per-step model-computation digests

so an action can never be detached from the computation and context that produced
it. The receipt digest is BLAKE3 over a canonical body (matching the vitni-tensor
engine and the event log); the receipt is signed with ed25519 and embeds its own
public key, so ANYONE can verify it offline with no model, no network, and no secret.

Two verification levels:
  * level 1 (integrity): recompute the Merkle root, chain head, and event count from
    the raw events, and check the ed25519 signature. No model required.
  * level 2 (recomputation): re-run each bound model step through vitni-tensor and
    confirm every model_digest reproduces bit-for-bit.

verify_certificate() implements level 1 and is fully independent. HMAC signing is
retained only as a fallback for environments without an asymmetric key.
"""
from __future__ import annotations
import os, sys, json, hmac
from dataclasses import dataclass, field, asdict
from .events import EventLog

from ._vendor.pck.cas import MerkleCAS  # noqa: E402

FORMAT = "vitnify-receipt v1"

try:
    import blake3 as _blake3
    def _digest32(b: bytes) -> str:
        return _blake3.blake3(b).hexdigest()
except ImportError:
    import hashlib
    def _digest32(b: bytes) -> str:
        return hashlib.blake2b(b, digest_size=32).hexdigest()

# cryptography is imported lazily inside the ed25519 helpers so the fallback path
# still runs on a stock Python without the dependency.


def _canon(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


def gen_ed25519():
    """Return (private_key, public_key_hex). Persist the private key to sign future runs."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw().hex()


@dataclass
class ExecutionCertificate:
    program_hash: str
    capabilities: list
    event_root: str
    n_events: int
    head_hash: str
    model_digests: list = field(default_factory=list)   # engine per-step digests, bound by the log
    v: str = FORMAT
    sig: str | None = None
    sig_alg: str = "none"
    pubkey: str | None = None       # ed25519 public key (hex) -- verifier needs no secret

    def body(self) -> dict:
        return {"v": self.v, "program_hash": self.program_hash,
                "capabilities": sorted(self.capabilities), "event_root": self.event_root,
                "n_events": self.n_events, "head_hash": self.head_hash,
                "model_digests": list(self.model_digests)}

    def digest(self) -> str:
        return _digest32(_canon(self.body()).encode())

    def sign_ed25519(self, priv) -> "ExecutionCertificate":
        self.sig = priv.sign(bytes.fromhex(self.digest())).hex()
        self.pubkey = priv.public_key().public_bytes_raw().hex()
        self.sig_alg = "ed25519"
        return self

    def sign_hmac(self, key: bytes) -> "ExecutionCertificate":
        import hashlib
        self.sig = hmac.new(key, self.digest().encode(), hashlib.blake2b).hexdigest()
        self.sig_alg = "hmac-blake2b"
        return self

    def to_json(self) -> str:
        return _canon(asdict(self))


def issue_certificate(program_hash, capabilities, log: EventLog, priv=None, key: bytes | None = None):
    """Build and sign a vitnify-receipt for a completed run.

    The model-computation digests are read from the log's llm_call events, so the
    receipt binds exactly the model steps that were recorded. ed25519 (self-verifying)
    is the canonical signing path; pass `priv`.
    """
    cas = MerkleCAS(log.chunks())
    cert = ExecutionCertificate(
        program_hash, sorted(set(capabilities)), cas.root, len(log), log.head(),
        model_digests=log.model_digests(),
    )
    if priv is not None:
        cert.sign_ed25519(priv)
    elif key is not None:
        cert.sign_hmac(key)
    return cert, cas


def verify_certificate(cert: ExecutionCertificate, log: EventLog, key: bytes | None = None) -> dict:
    """Level-1 verification: recompute everything from the raw events; trust nothing.

    ed25519 receipts verify against their OWN embedded public key -- no secret required.
    (Level 2 -- recomputing each model_digest through vitni-tensor -- is a separate step
    that additionally needs the model weights.)
    """
    cas = MerkleCAS(log.chunks())
    checks = {
        "format": cert.v == FORMAT,
        "root_matches": cas.root == cert.event_root,
        "head_matches": log.head() == cert.head_hash,
        "count_matches": len(log) == cert.n_events,
        "model_digests_match": log.model_digests() == list(cert.model_digests),
    }
    if cert.sig_alg == "ed25519":
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(cert.pubkey)).verify(
                bytes.fromhex(cert.sig), bytes.fromhex(cert.digest()))
            checks["sig_valid"] = True
        except Exception:
            checks["sig_valid"] = False
    elif cert.sig_alg == "hmac-blake2b" and key is not None:
        import hashlib
        checks["sig_valid"] = cert.sig == hmac.new(key, cert.digest().encode(), hashlib.blake2b).hexdigest()
    checks["ok"] = all(checks.values())
    return checks
