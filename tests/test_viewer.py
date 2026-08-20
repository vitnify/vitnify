"""The viewer renders receipts for humans, so its claims must be exactly as strong as
the receipt -- no more. These tests assert the HEADLINE (the largest text on the page)
and the badges are honest about containment, derived from the events rather than taken
on faith from the caller's verdict dict. The headline used to be an unconditional
string that asserted containment even for an observe-only run; nothing imported the
viewer, so that survived. This is the coverage that closes it.
"""
from __future__ import annotations
import re
from dataclasses import asdict

from vitnify.events import EventLog, Kind
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519
from vitnify.viewer import render

PRIV, PUB = gen_ed25519()


def _build(decisions, *, cert_ok=True, replay=True):
    """A run dict shaped exactly like the demos build (examples/demo_react.py)."""
    log = EventLog()
    log.append_llm_call("ph", [1, 2, 3], seed=0, model_digest="dd")
    for i, d in enumerate(decisions):
        p = {"tool": f"tool{i}", "decision": d}
        dl = str(d).strip().lower()
        if dl == "allow":
            p.update(result="x", result_hash="h")   # gated allow: result + hash
        elif dl != "deny":
            p["result"] = "x"                        # observed / other: watched, result recorded
        # a clean deny carries no result
        log.append(Kind.TOOL_CALL, p)
    cert, _ = issue_certificate("prog", ["tool0"], log, priv=PRIV)
    run = {
        "task": "demo",
        "events": [asdict(e) for e in log.events],
        "certificate": {"program_hash": cert.program_hash, "capabilities": cert.capabilities,
                        "event_root": cert.event_root, "head_hash": cert.head_hash,
                        "digest": cert.digest(), "sig": cert.sig},
        "verdict": {"contained": True, "replay_identical": replay, "cert_ok": cert_ok},
    }
    return run, log


def _headline(html):
    return re.search(r"<h1>(.*?)</h1>", html, re.S).group(1)


def _badges(html):
    return re.findall(r'class="badge (\w+)"><span class="dot"></span>([^<]*)', html)


def test_observe_only_headline_does_not_claim_containment():
    # The regression: an observe-only run must not read as "contained" in the headline.
    run, _ = _build(["observed"])
    html = render(run)
    headline = _headline(html)
    assert "contained" not in headline.lower()
    assert "Containment observed — not proven" in html
    # it may still honestly claim the properties that DO hold
    assert "replayed bit-for-bit" in headline and "cryptographically certified" in headline
    # and the warn badge, not a green containment badge
    assert ("warn", "Containment observed — not proven") in _badges(html)
    assert not any(txt.startswith("Injection contained") or txt.startswith("Containment enforced")
                   for _, txt in _badges(html))


def test_enforced_with_block_claims_containment():
    run, _ = _build(["allow", "deny"])
    html = render(run)
    assert "contained" in _headline(html).lower()
    assert ("good", "Injection contained") in _badges(html)
    assert "Containment observed" not in html


def test_enforced_all_allow_claims_containment():
    run, _ = _build(["allow"])
    html = render(run)
    assert "contained" in _headline(html).lower()
    assert ("good", "Containment enforced") in _badges(html)
    assert "Containment observed" not in html


def test_headline_drops_uncertified_claim():
    run, _ = _build(["allow"], cert_ok=False)
    headline = _headline(render(run))
    assert "cryptographically certified" not in headline
    assert "contained" in headline.lower()  # containment still holds


def test_viewer_containment_matches_verifier():
    # The viewer and the verifier must never disagree about containment -- they share
    # one predicate (decision_is_gated). Assert the page's warn badge appears iff the
    # verifier reports containment_enforced=False, for both gated and observed runs.
    for decisions in (["allow", "deny"], ["observed"], ["allow"], ["PERMIT"]):
        run, log = _build(decisions)
        enforced = verify_certificate(_recert(run), log)["containment_enforced"]
        warned = "Containment observed — not proven" in render(run)
        assert warned == (not enforced), decisions


def test_render_tolerates_missing_digest():
    # render() must not require a `digest` key that cert.to_json() does not emit.
    run, _ = _build(["allow"])
    del run["certificate"]["digest"]
    del run["certificate"]["sig"]
    html = render(run)  # must not raise
    assert "—" in html


def _recert(run):
    from vitnify.certificate import ExecutionCertificate
    c = run["certificate"]
    return ExecutionCertificate(c["program_hash"], c["capabilities"], c["event_root"],
                                len(run["events"]), c["head_hash"])
