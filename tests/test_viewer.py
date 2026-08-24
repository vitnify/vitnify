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


def _build(decisions, *, cert_ok=True, replay=True, authority=None):
    """A run dict shaped exactly like the demos build (examples/demo_react.py).
    `cert_ok` maps to the log's integrity_ok; `authority` is the split authority verdict
    (True / False / None-unestablished)."""
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
                        "digest": cert.digest(), "sig": cert.sig, "sig_alg": cert.sig_alg},
        "verdict": {"replay_identical": replay, "integrity_ok": cert_ok, "authority_ok": authority},
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
    assert "integrity-verified" in headline and "replayed bit-for-bit" in headline
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


def test_authority_badge_is_three_state():
    """The page carries the SAME split verdict as the machine dict: authority is a
    three-state badge (verified / rejected / unestablished), never collapsed to pass/fail.
    An honest receipt viewed with no trust root reads 'unestablished', NOT 'failed' -- the
    exact conflation the 0.4.1 split removed from the verifier, now removed from the page."""
    assert ("neutral", "Authority unestablished — no trust root supplied") in \
        _badges(render(_build(["allow"], authority=None)[0]))
    assert ("good", "Signed by an approved runtime") in \
        _badges(render(_build(["allow"], authority=True)[0]))
    assert ("bad", "Signer rejected — not on the trust list") in \
        _badges(render(_build(["allow"], authority=False)[0]))
    # the headline claims authority ONLY when it was actually verified
    assert "signed by an approved runtime" in _headline(render(_build(["allow"], authority=True)[0]))
    assert "signed by an approved runtime" not in _headline(render(_build(["allow"], authority=None)[0]))


def test_replay_badge_is_three_state():
    """not-run (absent) must read neutral, NOT a red 'diverged' -- the same false-negative
    the authority split removed, and now the COMMON case since L2 is the dispute path."""
    run, _ = _build(["allow"], replay=None)         # no replay data (L1-only receipt)
    b = _badges(render(run))
    assert ("neutral", "Replay not run — L1 verdict only") in b
    assert not any(t == "Replay diverged" for _, t in b)
    assert "replayed bit-for-bit" not in _headline(render(run))
    # ran & identical -> good; ran & diverged -> bad (distinct from not-run)
    assert ("good", "Replay bit-identical") in _badges(render(_build(["allow"], replay=True)[0]))
    assert ("bad", "Replay diverged") in _badges(render(_build(["allow"], replay=False)[0]))


def test_footer_makes_no_unbacked_claims():
    """The footer must not assert batch-invariance (not an engine property) or a fixed
    HMAC (the demo signs ed25519). It is derived from the run, not hardcoded marketing."""
    html = render(_build(["allow"])[0])
    assert "batch-invariant" not in html and "batch invariant" not in html
    assert "HMAC signing" not in html
    assert "ed25519" in html                         # the real signature algorithm, shown


def test_cert_failed_drops_all_derived_claims():
    # If the certificate does not verify, the event log is UNVERIFIED -- it may be the
    # very forgery the certificate exists to catch -- so the page must not claim
    # containment (or certification) from it, even though every event reads as gated.
    run, _ = _build(["allow"], cert_ok=False)
    html = render(run)
    headline = _headline(html)
    assert "integrity-verified" not in headline
    assert "contained" not in headline.lower()
    assert ("warn", "Containment unverified — log integrity failed") in _badges(html)
    assert ("bad", "Integrity FAILED — tampered") in _badges(html)
    assert not any(t in ("Injection contained", "Containment enforced") for _, t in _badges(html))


def test_zero_tool_run_is_not_vacuously_contained():
    # all([]) is True, so a tool-free run is containment_enforced at the API level -- but
    # the page must not tell a human the run was "contained" when nothing was ever gated.
    run, _ = _build([])  # llm_call only, no tool calls
    html = render(run)
    assert "contained" not in _headline(html).lower()
    assert ("neutral", "No tool calls") in _badges(html)


def test_viewer_never_claims_containment_without_verified_gating():
    # Soundness: the headline reads "contained" ONLY when the certificate verifies, a
    # tool was actually gated, and the verifier's own predicate agrees gating held. The
    # page never claims containment on unverified, empty, or ungated evidence.
    cases = [(["allow", "deny"], True), (["observed"], True), (["allow"], True),
             (["PERMIT"], True), (["allow"], False), ([], True)]
    for decisions, cert_ok in cases:
        run, log = _build(decisions, cert_ok=cert_ok)
        says_contained = "contained" in _headline(render(run)).lower()
        enforced = verify_certificate(_recert(run), log, require_authority=False)["containment_enforced"]
        if says_contained:
            assert cert_ok and bool(decisions) and enforced, (decisions, cert_ok)


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
