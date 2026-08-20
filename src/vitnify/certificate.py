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
from .events import EventLog, Kind

from ._vendor.pck.cas import MerkleCAS  # noqa: E402

FORMAT = "vitnify-receipt v2"
# A published receipt format is frozen; older receipts must stay verifiable across a
# verifier upgrade. The verifier accepts every version it has ever issued and
# reconstructs each receipt's signed body per its own `v` (see body()).
SUPPORTED_FORMATS = frozenset({"vitnify-receipt v1", FORMAT})

# The tool decisions that count as GATED -- the call passed through the capability wall
# (allow) or was refused by it (deny). Any other label ("observed", ...) is watch-only,
# not enforcement. This is the SINGLE SOURCE OF TRUTH for the containment predicate:
# verify_certificate and the human-facing viewer both call it, so the rule cannot drift
# between the dict a machine checks and the page a person reads.
GATED_DECISIONS = frozenset({"allow", "deny"})


def decision_is_gated(decision) -> bool:
    """True if a tool decision was gated by the capability wall (allow/deny), not merely
    observed. Case- and whitespace-insensitive; fails closed on anything unrecognised."""
    return str(decision).strip().lower() in GATED_DECISIONS


def _now_iso() -> str:
    """Issuer-asserted UTC timestamp (second precision). Places the receipt in time
    and, with the nonce, makes every receipt unique. NOT a trusted timestamp -- an
    RFC 3161 token or the Verification Authority countersignature is what makes the
    time non-repudiable; this defeats silent replay, not a determined backdater."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# BLAKE3 is a hard dependency and DEFINES the wire format: a blake2b digest is a
# different value, so there is no silent stdlib fallback (see events.py). A missing
# blake3 fails loudly rather than producing incompatible digests.
import blake3 as _blake3
def _digest32(b: bytes) -> str:
    return _blake3.blake3(b).hexdigest()

# `cryptography` is imported lazily inside the ed25519 helpers, so HMAC-only signing
# works without it installed. (blake3, above, is a hard dependency -- there is no
# hash-free path; the module will not import without it.)


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
    issued_at: str | None = None    # ISO-8601 UTC, issuer-asserted (see _now_iso)
    nonce: str | None = None        # random per receipt -- makes each receipt unique, non-replayable
    run_id: str | None = None       # identifies THIS run; distinct runs get distinct receipts
    v: str = FORMAT
    sig: str | None = None
    sig_alg: str = "none"
    pubkey: str | None = None       # ed25519 public key (hex) -- verifier needs no secret

    def body(self) -> dict:
        # Everything here is signed, and the body is VERSIONED: v2+ additionally
        # binds issued_at/nonce/run_id (which place the receipt in time and make it
        # unique). Reconstructing the body per the receipt's OWN `v` is what lets a
        # v2 verifier still verify a receipt signed under v1 -- a published format is
        # frozen, so older receipts must remain verifiable.
        b = {"v": self.v, "program_hash": self.program_hash,
             "capabilities": sorted(self.capabilities), "event_root": self.event_root,
             "n_events": self.n_events, "head_hash": self.head_hash,
             "model_digests": list(self.model_digests)}
        if self.v != "vitnify-receipt v1":
            b["issued_at"] = self.issued_at
            b["nonce"] = self.nonce
            b["run_id"] = self.run_id
        return b

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


def issue_certificate(program_hash, capabilities, log: EventLog, priv=None, key: bytes | None = None,
                      run_id: str | None = None):
    """Build and sign a vitnify-receipt for a completed run.

    The model-computation digests are read from the log's llm_call events, so the
    receipt binds exactly the model steps that were recorded. `model_digests` is
    EMPTY for a run with no recomputable model step (a hosted API, or a torch /
    non-deterministic backend) -- such a receipt is integrity-only: it binds the
    transcript, not the computation.

    `program_hash` is CALLER-ASSERTED -- the receipt binds whatever string you pass;
    it does not itself hash your agent's code. Pass a hash of the exact program or
    config that ran if you want the receipt to pin it.

    Each receipt is stamped with an issuer-asserted UTC time, a random nonce, and a
    run id (pass `run_id` to set your own; a random one is used otherwise) so distinct
    runs produce distinct, time-placeable receipts. ed25519 (self-verifying) is the
    canonical signing path; pass `priv`.
    """
    cas = MerkleCAS(log.chunks())
    cert = ExecutionCertificate(
        program_hash, sorted(set(capabilities)), cas.root, len(log), log.head(),
        model_digests=log.model_digests(),
        issued_at=_now_iso(), nonce=os.urandom(16).hex(),
        run_id=run_id if run_id is not None else os.urandom(16).hex(),
    )
    if priv is not None:
        cert.sign_ed25519(priv)
    elif key is not None:
        cert.sign_hmac(key)
    return cert, cas


def verify_certificate(cert: ExecutionCertificate, log: EventLog, key: bytes | None = None,
                       pinned_pubkeys=None) -> dict:
    """Level-1 verification: recompute everything from the raw events; trust nothing.

    Fails CLOSED. A receipt is only `ok` if a signature was actually checked and
    passed: an unsigned receipt (`sig_alg="none"`), an unknown algorithm, or an
    HMAC receipt presented without its key all yield `sig_valid=False`, so a
    receipt that cannot be cryptographically verified can never report `ok=True`.

    ed25519 receipts verify against their OWN embedded public key -- no secret
    required -- but that proves signer continuity, not signer authority. Pass
    `pinned_pubkeys` (an allow-list of hex ed25519 keys) to additionally require
    the receipt was signed by a key you trust. (Level 2 -- recomputing each
    model_digest through vitni-tensor -- is a separate step that additionally
    needs the model weights.)
    """
    # An empty event log has no Merkle commitment, so no legitimately issued receipt
    # carries one (issue_certificate commits >=1 event). A verifier must FAIL CLOSED on
    # such degenerate/hostile input, never crash: compute the root only when there are
    # events and treat its absence as a non-match, instead of letting MerkleCAS raise.
    cas_root = MerkleCAS(log.chunks()).root if log.events else None
    # Every event kind must be recognised. The semantic checks below filter events
    # by an EXACT kind match, so an unknown kind ("TOOL_CALL", "toolcall", ...) would
    # slip past them silently -- the same self-declared-label class as an unknown
    # sig_alg or an unknown decision string. Fail closed here so the whole class is
    # gone: an unrecognised kind (or decision, or algorithm, or format) never verifies.
    known_kinds = {k.value for k in Kind}
    checks = {
        "format": cert.v in SUPPORTED_FORMATS,
        "kinds_known": all(e.kind in known_kinds for e in log.events),
        "root_matches": cas_root is not None and cas_root == cert.event_root,
        "head_matches": log.head() == cert.head_hash,
        "count_matches": len(log) == cert.n_events,
        "model_digests_match": log.model_digests() == list(cert.model_digests),
    }

    # Signature -- fail closed. Only an actually-checked, passing signature sets
    # this True; "none", an unknown alg, or keyless HMAC all leave it False, so an
    # unverifiable receipt can never reach ok=True.
    sig_valid = False
    if cert.sig_alg == "ed25519" and cert.sig and cert.pubkey:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(cert.pubkey)).verify(
                bytes.fromhex(cert.sig), bytes.fromhex(cert.digest()))
            sig_valid = True
        except Exception:
            sig_valid = False
    elif cert.sig_alg == "hmac-blake2b" and cert.sig and key is not None:
        import hashlib
        sig_valid = hmac.compare_digest(
            cert.sig, hmac.new(key, cert.digest().encode(), hashlib.blake2b).hexdigest())
    checks["sig_valid"] = sig_valid

    # Capability consistency -- the receipt must PROVE no ungranted tool executed,
    # not just carry a capability list. Every tool call must be within the declared,
    # signed-over capability set OR a CLEAN DENIAL (decision exactly "deny",
    # case/space-insensitive, with no result). Keying only off decision=="allow"
    # let a forged log slip an ungranted, result-bearing call through by relabelling
    # the decision ("PERMIT", " allow", omitted...) -- F11. Failing closed on
    # anything that is not a clean denial removes that, whatever string it carries.
    granted = set(cert.capabilities)

    def _clean_denial(p: dict) -> bool:
        return (str(p.get("decision", "")).strip().lower() == "deny"
                and "result" not in p and "result_hash" not in p)

    checks["caps_consistent"] = all(
        e.payload.get("tool") in granted or _clean_denial(e.payload)
        for e in log.events
        if e.kind == Kind.TOOL_CALL.value
    )

    # A verified receipt must carry NO data field its version does not sign. The v1
    # body binds none of the v2 issuance fields, so a v1 receipt with issued_at /
    # nonce / run_id set is carrying an unsigned, forgeable value (e.g. a backdated
    # issued_at) -- reject it, so ok=True never blesses data outside the signature.
    checks["fields_match_version"] = not (
        cert.v == "vitnify-receipt v1"
        and any(x is not None for x in (cert.issued_at, cert.nonce, cert.run_id)))

    # Optional signer pinning -- an embedded key proves continuity, not authority.
    # When an allow-list is supplied, the signer must be ed25519 and on the list.
    if pinned_pubkeys is not None:
        checks["signer_pinned"] = (
            sig_valid and cert.sig_alg == "ed25519" and cert.pubkey in set(pinned_pubkeys))

    # Enforcement vs observation. An "allow"/"deny" decision came from the capability
    # wall -- the call was GATED. Any other value (e.g. "observed" from the record-only
    # callback adapter) means it was WATCHED, not enforced, so the receipt is a
    # tamper-evident transcript, not proof containment was applied -- the containment
    # analogue of an empty model_digests. Reported separately, NOT folded into ok, so a
    # valid transcript stays valid while a containment PROOF requires ok AND this True.
    checks["containment_enforced"] = all(
        decision_is_gated(e.payload.get("decision"))
        for e in log.events
        if e.kind == Kind.TOOL_CALL.value
    )

    checks["ok"] = all(v for k, v in checks.items() if k != "containment_enforced")
    return checks
