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

# The mandatory integrity checks folded into `integrity_ok` -- always produced by
# verify_certificate. Module-level so a test can assert the verifier produces every one
# (a dropped key would otherwise weaken integrity_ok silently). `program_matches` is
# NOT here: it is optional (only when `program=` is supplied).
_INTEGRITY_KEYS = ("format", "kinds_known", "root_matches", "head_matches", "count_matches",
                   "model_digests_match", "sig_valid", "caps_consistent", "fields_match_version")


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


def derive_program_hash(program, root=None) -> str:
    """Derive a ``program_hash`` from the ACTUAL program, so the receipt binds what ran
    instead of a caller-asserted label -- ``"literally anything I type"`` no longer
    verifies against real code.

    ``program`` is a file path, an iterable of paths, or raw ``bytes``. Returns
    ``"sha256:<hex>"``. Pass the same value to :func:`issue_certificate` at issue time
    and to :func:`verify_certificate` (``program=``) at verify time.

    INJECTIVE by construction, matching the tier-1 digest discipline ("fields are
    length-prefixed so concatenation is injective"): each entry binds its
    **length-prefixed relative path** then its **length-prefixed content**. A raw
    ``\\x00`` delimiter is unsafe because file content can contain ``\\x00`` (two files
    then collide with one crafted file); a length prefix cannot. Entries are sorted by
    **relative path** -- a TOTAL order, unlike basename, so a program with several
    ``__init__.py`` is argument-order-independent -- and the relative path is bound, so
    moving a file between directories changes the hash. Pass ``root`` to control what the
    paths are relative to; otherwise paths are bound as given (pass relative paths for a
    machine-independent hash).
    """
    import hashlib
    import struct

    def _lp(b: bytes) -> bytes:  # length-prefixed: injective concatenation
        return struct.pack(">Q", len(b)) + b

    hsh = hashlib.sha256()
    if isinstance(program, (bytes, bytearray)):
        hsh.update(_lp(b""))            # anonymous single blob: empty relative path
        hsh.update(_lp(bytes(program)))
    else:
        paths = [program] if isinstance(program, (str, os.PathLike)) else list(program)
        entries = []
        for p in paths:
            rel = os.path.relpath(str(p), root) if root is not None else str(p)
            rel = rel.replace(os.sep, "/")   # stable across platforms
            with open(p, "rb") as f:
                entries.append((rel, f.read()))
        for rel, data in sorted(entries, key=lambda e: e[0]):   # total order by rel path
            hsh.update(_lp(rel.encode("utf-8")))
            hsh.update(_lp(data))
    return "sha256:" + hsh.hexdigest()


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
    if not log.events:
        raise ValueError("cannot issue a receipt for an empty event log: record at "
                         "least one event first (there is nothing to commit)")
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
                       pinned_pubkeys=None, program=None, require_authority: bool = True) -> dict:
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
        # A denial is clean ONLY if it carries no result key AT ALL. This is a
        # security boundary, not ergonomics: the most dangerous tool shape is a
        # side-effecting call that returns None (send_email, wire_transfer,
        # delete_record). An UNGRANTED one that actually executed and is logged
        # {"decision":"deny","result":None} must NOT pass -- yet an explicit None
        # and an absent key are indistinguishable by value, so accepting None (the
        # 0.2.13 loosening, now reverted) let a real side effect masquerade as a
        # block through any non-Broker wrapper. Every enforced deny site already
        # OMITS the key; a genuine block never writes it. If the ergonomics are
        # wanted later, the sound form is a POSITIVE Broker assertion
        # (``executed: false``), never an absence you cannot distinguish from a
        # None return. Guarded by tests/test_attack_matrix.py::...none_result.
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

    # Program binding -- an INTEGRITY check (computable offline, no trust root).
    # `program_hash` is caller-asserted by default; supplying `program` (the ACTUAL code:
    # a path, iterable of paths, or bytes) recomputes derive_program_hash and CONFIRMS the
    # receipt names that program, turning a self-asserted label into a checked binding.
    if program is not None:
        checks["program_matches"] = (cert.program_hash == derive_program_hash(program))

    # -------------------------------------------------------------- the verdict, SPLIT
    # A receipt answers TWO distinct questions, and collapsing them into one boolean is
    # wrong for somebody either way -- 0.3.x let a forgery read ok=True; 0.4.0 made an
    # honest receipt read ok=False to a stranger with no trust root, indistinguishable
    # from tampering. Keep them distinct:
    #
    #   integrity_ok -- is this transcript internally consistent and validly signed by
    #                   WHOEVER signed it (root/head/count, signature, caps, program)?
    #                   Answerable by ANYONE, offline, with no model and no secret.
    #   authority_ok -- was the signer an APPROVED runtime? Needs a trust root, so it is
    #                   True / False / None(unestablished). A stranger offline can never
    #                   answer it; None must NOT be reported as a bare False that reads as
    #                   "forged".
    #
    # The spec keeps signer pinning OPTIONAL (for integrity); this adds an explicit
    # authority verdict on top, so the two never contradict.
    # Mandatory integrity checks -- ALWAYS produced above. A missing one is a bug, so
    # default to False (fail CLOSED, never open): a check silently dropped in a refactor,
    # or a typo in this tuple, makes integrity_ok False, and the honest-receipt tests then
    # fail LOUDLY rather than a hole passing quietly. Coverage is asserted in
    # tests/test_safe_defaults.py::test_integrity_tuple_is_fully_produced.
    integ = all(checks.get(k, False) for k in _INTEGRITY_KEYS)
    if "program_matches" in checks:          # optional: only when `program=` was supplied
        integ = integ and checks["program_matches"]
    checks["integrity_ok"] = integ

    if pinned_pubkeys is not None:
        authority_ok = bool(sig_valid and cert.sig_alg == "ed25519"
                            and cert.pubkey in set(pinned_pubkeys))
    else:
        authority_ok = None                       # no trust root -> UNESTABLISHED, not False
    checks["authority_ok"] = authority_ok
    checks["authority"] = ("verified" if authority_ok is True else
                           "rejected: signer not on the pinned allow-list" if authority_ok is False else
                           "unestablished: no trust root supplied (pass pinned_pubkeys)")
    checks["signer_pinned"] = authority_ok is True    # back-compat alias

    # Enforcement vs observation (separate property, never folded into ok). An "allow"/
    # "deny" decision was GATED by the wall; any other value ("observed", ...) was merely
    # WATCHED, so the receipt is a tamper-evident transcript, not proof of containment.
    checks["containment_enforced"] = all(
        decision_is_gated(e.payload.get("decision"))
        for e in log.events
        if e.kind == Kind.TOOL_CALL.value
    )

    # `ok` = integrity AND an authorised signer (default). require_authority=False makes
    # `ok` the integrity-only verdict (authority is still reported, just not required) --
    # the answer a stranger CAN compute offline.
    checks["ok"] = bool(checks["integrity_ok"] and (authority_ok is True if require_authority else True))
    return checks


def verify_authorized(cert: ExecutionCertificate, log: EventLog, pinned_pubkeys, **kw) -> dict:
    """Production verification that requires an AUTHORISED signer.

    `verify_certificate` proves integrity and signer *continuity* from a receipt's own
    embedded key -- but a forger can re-sign an edited receipt with their OWN key and it
    still self-verifies (the honest limitation, kept as an xfail in the attack matrix).
    Authority requires anchoring the signer to keys you trust. This wrapper FAILS CLOSED
    unless `pinned_pubkeys` is a non-empty allow-list AND the signer is on it, so a
    re-signed forgery can never report `ok=True`, and neither can a call that simply
    forgot to pin. Use this -- not the bare verifier -- anywhere signer authority matters.

    The allow-list is the software anchor; the strongest form pins a TPM/enclave-resident
    key so the private key cannot leave an approved runtime (future hardening).
    """
    if not pinned_pubkeys:
        return {"ok": False, "signer_pinned": False, "containment_enforced": False,
                "error": "no pinned signer allow-list: signer authority cannot be established"}
    return verify_certificate(cert, log, pinned_pubkeys=pinned_pubkeys, **kw)
