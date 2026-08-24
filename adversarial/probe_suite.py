#!/usr/bin/env python3
"""vitnify adversarial probe suite — try to forge a receipt the verifier will accept.

Every probe below builds a forged or tampered receipt and asserts the SHIPPED
verifier (`vitnify.certificate.verify_certificate`) rejects it. It imports whatever
`vitnify` is installed, so you can point it at ANY release and watch which attacks
get through:

    pip install vitnify==0.2.4
    python adversarial/probe_suite.py

Exit code is 0 iff every attack was blocked. This is the claim the product makes
about your agents, turned on the product itself — don't trust it, run it. Found a
new one? Send it to security@vitnify.com; this suite is meant to grow.

F05 is the one documented trust-boundary limit. The verdict is split: an unpinned
self-signed receipt has ``integrity_ok=True`` but ``authority_ok=None`` (unestablished
— an embedded key proves continuity, not that an approved runtime signed it), so a
re-signed forgery is caught only once a trusted key is pinned (``authority_ok=False``).
Integrity attacks (tamper/forge the transcript) are caught by anyone offline via
``integrity_ok``; this suite keys each probe on the field the attack actually breaks.
"""
import sys
import copy
import importlib.metadata as _meta

from vitnify.events import EventLog, Kind
from vitnify.certificate import (
    ExecutionCertificate, issue_certificate, verify_certificate, gen_ed25519,
    _canon, _digest32,
)
from vitnify._vendor.pck.cas import MerkleCAS

PRIV, PUB = gen_ed25519()


def _honest_log():
    log = EventLog()
    log.append_llm_call("ph", [1, 2, 3], seed=0, model_digest="dd")
    log.append(Kind.TOOL_CALL, {"tool": "read_docs", "decision": "ALLOW",
                                "result": "ok", "result_hash": "h"})
    return log


def _rejected(cert, log, **kw):
    """True if the verifier REJECTS this receipt — the outcome an attack should get.

    The verdict is split (0.4.1): a tamper/forge attack on the transcript breaks
    ``integrity_ok`` (a stranger catches it offline, no trust root); a re-sign attack
    (F05) is caught only when a trust anchor is supplied, via the full ``ok``. Keying
    an integrity attack on the authority-dependent ``ok`` would make an HONEST unpinned
    receipt read 'blocked' too — a false green — so pick the right field per attack.
    """
    try:
        v = verify_certificate(cert, log, **kw)
        if kw.get("pinned_pubkeys") is not None:
            return v.get("ok") is False            # authority-aware verdict (F05)
        return v.get("integrity_ok") is False      # integrity attack: rejected offline
    except Exception:
        return True   # a crash is a rejection, not an acceptance


# ---- each probe returns (blocked: bool, note: str) -------------------------------

def p_unsigned():
    log = EventLog()
    log.append(Kind.TOOL_CALL, {"tool": "wire_transfer", "decision": "ALLOW", "result": "SENT"})
    cert, _ = issue_certificate("prog", ["wire_transfer"], log)   # no priv/key -> sig_alg="none"
    return _rejected(cert, log), 'sig_alg="none"'


def p_keyless_hmac():
    log = _honest_log()
    cert, _ = issue_certificate("prog", ["read_docs"], log, key=b"shared-secret")
    return _rejected(cert, log), "verifier holds no key"        # no key passed to verify


def p_out_of_policy_tool():
    log = EventLog()
    log.append(Kind.TOOL_CALL, {"tool": "wire_transfer", "decision": "ALLOW", "result": "x", "result_hash": "h"})
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=PRIV)
    return _rejected(cert, log), "wire_transfer not granted"


def p_edit_event():
    log = _honest_log()
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=PRIV)
    log.events[1].payload["decision"] = "DENY"                  # flip after signing
    return _rejected(cert, log), "flip ALLOW->DENY post-sign"


def p_delete_event():
    log = _honest_log()
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=PRIV)
    log.events.pop()
    return _rejected(cert, log), "truncate the transcript"


def p_reorder_events():
    log = _honest_log()
    log.append(Kind.AGENT_STEP, {"state": "x"})
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=PRIV)
    log.events[0], log.events[1] = log.events[1], log.events[0]
    return _rejected(cert, log), "swap event order"


def p_edit_model_digest():
    log = _honest_log()
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=PRIV)
    bad = copy.deepcopy(cert)
    bad.model_digests = ["0" * 64]                              # claim a computation not in the log
    return _rejected(bad, log), "swap model_digests"


def p_tamper_chain():
    log = _honest_log()
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=PRIV)
    log.events[1].prev = "00" * 32                             # rewrite a hash-chain link
    return _rejected(cert, log), "rewrite prev pointer"


def p_backdate_v1():
    log = _honest_log()
    cas = MerkleCAS(log.chunks())
    body = {"v": "vitnify-receipt v1", "program_hash": "p", "capabilities": ["read_docs"],
            "event_root": cas.root, "n_events": len(log), "head_hash": log.head(),
            "model_digests": log.model_digests()}
    sig = PRIV.sign(bytes.fromhex(_digest32(_canon(body).encode()))).hex()
    cert = ExecutionCertificate("p", ["read_docs"], cas.root, len(log), log.head(),
                                model_digests=log.model_digests())
    cert.v, cert.sig, cert.sig_alg, cert.pubkey = "vitnify-receipt v1", sig, "ed25519", PUB
    cert.issued_at = "2019-01-01T00:00:00Z"                    # forge a field v1 never signed
    return _rejected(cert, log), "backdated issued_at on v1"


def p_decision_string():
    log = EventLog()
    log.append(Kind.TOOL_CALL, {"tool": "wire_transfer", "decision": "PERMIT", "result": "x"})
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=PRIV)
    return _rejected(cert, log), 'decision="PERMIT"'


def p_relabel_kind():
    log = EventLog()
    log.append("TOOL_CALL", {"tool": "wire_transfer", "decision": "ALLOW", "result": "x"})  # unknown kind
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=PRIV)
    return _rejected(cert, log), 'kind="TOOL_CALL"'


def p_resign_unpinned():
    log = EventLog()
    log.append(Kind.TOOL_CALL, {"tool": "read_docs", "decision": "ALLOW", "result": "x", "result_hash": "h"})
    apriv, _apub = gen_ed25519()                               # attacker's own key
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=apriv)
    pinned = verify_certificate(cert, log, pinned_pubkeys=[PUB])
    unpinned = verify_certificate(cert, log)   # a stranger with no trust root
    # With a trust anchor the forged signer is rejected (authority_ok False -> ok False).
    # With none, integrity still holds (self-consistent) but authority is UNESTABLISHED --
    # reported as such, NOT as a bare pass or a bare 'forged'.
    blocked = (pinned.get("ok") is False and pinned.get("authority_ok") is False
               and unpinned.get("integrity_ok") is True and unpinned.get("authority_ok") is None)
    return blocked, "pinned: authority rejected; unpinned: integrity verified, authority unestablished"


PROBES = [
    ("F01", "unsigned receipt verifies",      p_unsigned),
    ("F02", "keyless HMAC verifies",          p_keyless_hmac),
    ("F03", "ungranted tool inside caps",     p_out_of_policy_tool),
    ("--",  "edited event",                   p_edit_event),
    ("--",  "deleted event",                  p_delete_event),
    ("--",  "reordered events",               p_reorder_events),
    ("--",  "edited model digest",            p_edit_model_digest),
    ("F13", "rewritten chain pointer",        p_tamper_chain),
    ("F10", "backdated v1 timestamp",         p_backdate_v1),
    ("F11", "decision-string evasion",        p_decision_string),
    ("F12", "relabelled event kind",          p_relabel_kind),
    ("F05", "re-signed by attacker key",      p_resign_unpinned),
]


def main():
    try:
        ver = _meta.version("vitnify")
    except Exception:
        ver = "?"
    print(f"\n  vitnify adversarial probe suite — target: vitnify {ver}\n")
    print(f"  {'id':<5}{'attack':<30}result")
    print("  " + "-" * 56)
    accepted = 0
    for pid, name, fn in PROBES:
        try:
            blocked, note = fn()
        except Exception as e:
            blocked, note = True, f"raised {type(e).__name__}"
        if not blocked:
            accepted += 1
        status = "blocked" if blocked else ">>> ACCEPTED <<<"
        print(f"  {pid:<5}{name:<30}{status:<16}({note})")
    print("  " + "-" * 56)
    n = len(PROBES)
    print(f"\n  {n} attacks attempted · {accepted} accepted · {n - accepted} blocked")

    # positive control: an honest, GATED receipt must verify AND prove containment
    log = _honest_log()
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=PRIV)
    c = verify_certificate(cert, log)   # a stranger: no trust root supplied
    # An honest receipt VERIFIES to anyone offline (integrity_ok) and proves containment;
    # authority is separately 'unestablished' without a pin -- NOT a bare False.
    control = (c.get("integrity_ok") is True and c.get("containment_enforced") is True
               and c.get("authority_ok") is None)
    print(f"  control: honest receipt verifies offline + proves containment · {'yes' if control else 'NO -- verifier is broken'}")

    # containment distinction: an OBSERVE-ONLY receipt (watched, not gated) is a valid
    # transcript (ok=True) but must NOT claim containment (containment_enforced=False),
    # so a watch-only run cannot masquerade as an enforced one.
    olog = EventLog()
    olog.append(Kind.TOOL_CALL, {"tool": "read_docs", "decision": "observed", "result": "x"})
    ocert, _ = issue_certificate("prog", ["read_docs"], olog, priv=PRIV)
    oc = verify_certificate(ocert, olog)
    observe_flagged = oc.get("integrity_ok") is True and oc.get("containment_enforced") is False
    print(f"  control: observe-only is valid but NOT contained · {'yes' if observe_flagged else 'NO -- laundering possible'}\n")

    sys.exit(1 if (accepted or not control or not observe_flagged) else 0)


if __name__ == "__main__":
    main()
