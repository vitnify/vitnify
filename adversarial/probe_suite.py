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

F05 is the one documented trust-boundary limit: an *unpinned* self-signed receipt
verifies by design (an embedded key proves continuity, not authority). The probe
shows it is blocked once a trusted key is pinned.
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
    """True if the verifier REJECTS this receipt — the outcome an attack should get."""
    try:
        return verify_certificate(cert, log, **kw).get("ok") is False
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
    pinned_blocks = verify_certificate(cert, log, pinned_pubkeys=[PUB]).get("ok") is False
    return pinned_blocks, "blocked with pinning; unpinned verifies by design"


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

    # positive control: an honest receipt must still verify
    log = _honest_log()
    cert, _ = issue_certificate("prog", ["read_docs"], log, priv=PRIV)
    control = verify_certificate(cert, log).get("ok") is True
    print(f"  control: honest receipt verifies · {'yes' if control else 'NO -- verifier is broken'}\n")

    sys.exit(1 if (accepted or not control) else 0)


if __name__ == "__main__":
    main()
