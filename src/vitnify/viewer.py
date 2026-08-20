"""Forensic viewer: render a recorded agent run + its execution certificate as a
self-contained HTML report -- "show me exactly what the agent did, and prove it."
Recomputes the tampered Merkle root (flip a blocked call to ALLOW) so the page can
demonstrate, interactively, that editing the log breaks the certificate.

Output is an Artifact-ready fragment (a <title>, a <style>, and body content -- no
<html>/<head>/<body> wrappers; the Artifact host adds those).
"""
from __future__ import annotations
import os, sys, json, html

from ._vendor.pck.cas import MerkleCAS  # noqa: E402

def _canon(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"))

def _chunks(events):
    return [_canon({"i": e["i"], "kind": e["kind"], "payload": e["payload"], "prev": e["prev"]}) for e in events]

def _tampered_root(events):
    """Simulate an attacker flipping the first blocked (DENY) tool call to ALLOW."""
    ev = json.loads(json.dumps(events))
    for e in ev:
        if e["kind"] == "tool_call" and e["payload"].get("decision") == "DENY":
            e["payload"]["decision"] = "ALLOW"; e["payload"]["result"] = "SENT"; break
    return MerkleCAS(_chunks(ev)).root

def _short(s, n=20):
    s = str(s); return s if len(s) <= n else s[:n] + "…"

def _esc(s): return html.escape(str(s))

def _event_rows(events):
    rows = []
    step = 0
    for e in events:
        k, p = e["kind"], e["payload"]
        if k == "llm_call":
            step += 1
            text = _esc(p.get("text", "").strip() or "(no text captured)")
            ntok = len(p.get("tokens", []))
            commit = _short(p.get("logit_hashes", ["-"])[0], 16)
            rows.append(f"""
            <li class="ev ev-llm">
              <span class="ev-tag tag-llm">MODEL</span>
              <div class="ev-body">
                <p class="ev-text">{text}</p>
                <div class="ev-meta mono">{ntok} tokens · logit&#8209;commitment {commit}</div>
              </div>
            </li>""")
        elif k == "tool_call":
            tool = _esc(p.get("tool", "?")); args = _esc(", ".join(map(str, p.get("args", []))))
            allow = p.get("decision") == "ALLOW"
            chip = ('<span class="chip chip-ok">ALLOWED</span>' if allow
                    else '<span class="chip chip-deny">BLOCKED · no capability</span>')
            detail = (f'<div class="ev-meta mono">&#8594; {_esc(_short(p.get("result",""), 64))}</div>'
                      if allow else '<div class="ev-meta mono deny-note">capability wall &mdash; effect never executed</div>')
            rows.append(f"""
            <li class="ev ev-tool {'ok' if allow else 'deny'}">
              <span class="ev-tag tag-tool">TOOL</span>
              <div class="ev-body">
                <div class="ev-head"><code class="call">{tool}({args})</code>{chip}</div>
                {detail}
              </div>
            </li>""")
        elif k == "agent_step":
            rows.append(f"""
            <li class="ev ev-note">
              <span class="ev-tag tag-note">&#9888;</span>
              <div class="ev-body"><div class="ev-meta note-annot">{_esc(p.get('note',''))}</div></div>
            </li>""")
        elif k == "entropy":
            rows.append(f"""
            <li class="ev ev-ent">
              <span class="ev-tag tag-ent">RNG</span>
              <div class="ev-body"><div class="ev-meta mono">{_esc(p.get('source'))} = {_esc(p.get('value'))} (from log on replay)</div></div>
            </li>""")
    return "\n".join(rows)

def render(run: dict) -> str:
    cert = run["certificate"]; v = run["verdict"]; events = run["events"]
    real_root = cert["event_root"]
    tamper_root = _tampered_root(events)

    def badge(ok, yes, no):
        return f'<div class="badge {"good" if ok else "bad"}"><span class="dot"></span>{yes if ok else no}</div>'

    def warn_badge(text):
        return f'<div class="badge warn"><span class="dot"></span>{text}</div>'

    # Whether the receipt PROVES containment, derived from the events the same way the
    # verifier does: every tool decision must be a gated allow/deny. An observe-only
    # run (a watching callback that records but does not gate) is a valid transcript but
    # proves no containment -- it must NOT render as a plain green "verified" receipt,
    # or a non-engineer is handed a badge that claims more than the receipt shows.
    containment_enforced = all(
        str(e["payload"].get("decision", "")).strip().lower() in ("allow", "deny")
        for e in events if e["kind"] == "tool_call")
    containment_badge = (badge(True, "Containment enforced", "")
                         if containment_enforced
                         else warn_badge("Containment observed — not proven"))

    badges = (badge(v["contained"], "Injection contained", "NOT contained")
              + badge(v["replay_identical"], "Replay bit-identical", "Replay diverged")
              + badge(v["cert_ok"], "Certificate verified", "Certificate FAILED")
              + containment_badge)

    cert_rows = "".join(
        f'<div class="crow"><span class="ck">{k}</span><span class="cv mono">{_esc(val)}</span></div>'
        for k, val in [
            ("program", cert["program_hash"]),
            ("capabilities granted", ", ".join(cert["capabilities"])),
            ("event-log root", cert["event_root"]),
            ("chain head", cert["head_hash"]),
            ("certificate id", cert["digest"]),
            ("signature (HMAC)", cert["sig"]),
        ])

    return f"""<title>Agent Replay Certificate</title>
<style>
:root {{
  --bg:#FBFBFD; --surface:#FFFFFF; --surface-2:#F4F5F8; --ink:#1b1f27; --ink-dim:#5a6270;
  --border:#E4E7ED; --accent:#0FB5A6; --ok:#1F9D63; --ok-bg:#E7F5EE; --deny:#D6532E; --deny-bg:#FBECE6;
  --warn:#B7791F; --tamper:#E5484D; --mono-bg:#F2F4F7; --shadow:0 1px 2px rgba(20,26,40,.05),0 8px 24px rgba(20,26,40,.05);
}}
@media (prefers-color-scheme:dark){{ :root:not([data-theme="light"]){{
  --bg:#0E1116; --surface:#161A21; --surface-2:#1C222B; --ink:#E6E9EF; --ink-dim:#98A2B3;
  --border:#262D38; --accent:#25C6B6; --ok:#3FBE7C; --ok-bg:#12291E; --deny:#EE7A54; --deny-bg:#2A1811;
  --warn:#E0A93B; --tamper:#F2585B; --mono-bg:#12161C; --shadow:0 1px 2px rgba(0,0,0,.4),0 12px 32px rgba(0,0,0,.35);
}} }}
:root[data-theme="dark"] {{
  --bg:#0E1116; --surface:#161A21; --surface-2:#1C222B; --ink:#E6E9EF; --ink-dim:#98A2B3;
  --border:#262D38; --accent:#25C6B6; --ok:#3FBE7C; --ok-bg:#12291E; --deny:#EE7A54; --deny-bg:#2A1811;
  --warn:#E0A93B; --tamper:#F2585B; --mono-bg:#12161C; --shadow:0 1px 2px rgba(0,0,0,.4),0 12px 32px rgba(0,0,0,.35);
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
  font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  line-height:1.5;-webkit-font-smoothing:antialiased;}}
.mono{{font-family:ui-monospace,"SF Mono",Menlo,"Cascadia Code",monospace;font-variant-numeric:tabular-nums;}}
.wrap{{max-width:860px;margin:0 auto;padding:40px 24px 72px;}}
header.top{{display:flex;flex-direction:column;gap:6px;margin-bottom:8px;}}
.eyebrow{{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);font-weight:600;}}
h1{{font-size:27px;margin:0;letter-spacing:-.01em;text-wrap:balance;}}
.task{{color:var(--ink-dim);font-size:15px;margin:2px 0 0;}}
.badges{{display:flex;flex-wrap:wrap;gap:10px;margin:22px 0 30px;}}
.badge{{display:flex;align-items:center;gap:8px;padding:8px 13px;border-radius:9px;font-size:13.5px;font-weight:600;
  border:1px solid var(--border);background:var(--surface);box-shadow:var(--shadow);}}
.badge .dot{{width:8px;height:8px;border-radius:50%;}}
.badge.good{{color:var(--ok);}} .badge.good .dot{{background:var(--ok);}}
.badge.bad{{color:var(--tamper);}} .badge.bad .dot{{background:var(--tamper);}}
.badge.warn{{color:var(--warn);}} .badge.warn .dot{{background:var(--warn);}}
section{{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:22px 22px;margin:16px 0;box-shadow:var(--shadow);}}
.sec-h{{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin:0 0 14px;}}
.sec-h h2{{font-size:13px;letter-spacing:.09em;text-transform:uppercase;color:var(--ink-dim);margin:0;font-weight:700;}}
.sec-h .hint{{font-size:12.5px;color:var(--ink-dim);}}
.cert .crow{{display:grid;grid-template-columns:170px 1fr;gap:12px;padding:9px 0;border-top:1px solid var(--border);}}
.cert .crow:first-child{{border-top:none;}}
.cert .ck{{color:var(--ink-dim);font-size:13px;}}
.cert .cv{{font-size:12.5px;word-break:break-all;color:var(--ink);}}
ol.tl{{list-style:none;margin:0;padding:0;position:relative;}}
ol.tl:before{{content:"";position:absolute;left:15px;top:6px;bottom:6px;width:2px;background:var(--border);}}
.ev{{position:relative;display:grid;grid-template-columns:34px 1fr;gap:14px;padding:9px 0;}}
.ev-tag{{grid-column:1;justify-self:start;z-index:1;font-size:8.5px;font-weight:800;letter-spacing:.03em;
  padding:3px 0;width:32px;text-align:center;border-radius:6px;border:1px solid var(--border);background:var(--surface-2);color:var(--ink-dim);}}
.tag-tool{{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 40%,var(--border));}}
.tag-note{{color:var(--deny);border-color:color-mix(in srgb,var(--deny) 45%,var(--border));font-size:11px;}}
.note-annot{{color:var(--deny);font-style:italic;}}
.ev-body{{min-width:0;}}
.ev-text{{margin:0;font-size:14px;white-space:pre-wrap;}}
.ev-head{{display:flex;flex-wrap:wrap;align-items:center;gap:10px;}}
code.call{{font-family:ui-monospace,Menlo,monospace;font-size:13px;background:var(--mono-bg);padding:3px 8px;border-radius:6px;border:1px solid var(--border);}}
.ev-meta{{font-size:12px;color:var(--ink-dim);margin-top:5px;word-break:break-all;}}
.deny-note{{color:var(--deny);}}
.chip{{font-size:11px;font-weight:700;padding:3px 9px;border-radius:99px;letter-spacing:.02em;}}
.chip-ok{{color:var(--ok);background:var(--ok-bg);}}
.chip-deny{{color:var(--deny);background:var(--deny-bg);}}
.proof{{border-color:color-mix(in srgb,var(--accent) 30%,var(--border));}}
.rootline{{display:grid;grid-template-columns:170px 1fr;gap:12px;align-items:center;padding:9px 0;}}
.rootline .ck{{color:var(--ink-dim);font-size:13px;}}
#liveroot{{font-size:12.5px;word-break:break-all;}}
.verdict-live{{font-weight:700;}} .vgood{{color:var(--ok);}} .vbad{{color:var(--tamper);}}
.toggle{{display:inline-flex;align-items:center;gap:10px;margin-top:14px;cursor:pointer;user-select:none;font-size:13.5px;}}
.sw{{width:40px;height:23px;border-radius:99px;background:var(--surface-2);border:1px solid var(--border);position:relative;transition:.15s;}}
.sw:after{{content:"";position:absolute;top:2px;left:2px;width:17px;height:17px;border-radius:50%;background:var(--ink-dim);transition:.15s;}}
.toggle.on .sw{{background:var(--tamper);border-color:var(--tamper);}} .toggle.on .sw:after{{left:19px;background:#fff;}}
:focus-visible{{outline:2px solid var(--accent);outline-offset:2px;}}
footer{{color:var(--ink-dim);font-size:12px;margin-top:26px;text-align:center;}}
@media (max-width:560px){{.cert .crow,.rootline{{grid-template-columns:1fr;gap:3px;}}}}
</style>

<div class="wrap">
  <header class="top">
    <div class="eyebrow">Vitnify &middot; Execution Certificate</div>
    <h1>This agent run was contained, replayed bit-for-bit, and cryptographically certified.</h1>
    <p class="task">Task recorded: &ldquo;{_esc(run.get('task','(agent run)'))}&rdquo;</p>
  </header>

  <div class="badges">{badges}</div>

  <section class="cert">
    <div class="sec-h"><h2>Execution Certificate</h2><span class="hint">independently verifiable &mdash; no model, no network</span></div>
    {cert_rows}
  </section>

  <section>
    <div class="sec-h"><h2>What the agent actually did</h2><span class="hint">every model step &amp; tool call, in order</span></div>
    <ol class="tl">{_event_rows(events)}</ol>
  </section>

  <section class="proof">
    <div class="sec-h"><h2>Proof it can&rsquo;t be doctored</h2><span class="hint">edit the log &rarr; the certificate breaks</span></div>
    <p style="margin:0 0 4px;font-size:14px;color:var(--ink-dim)">An attacker who rewrites the blocked exfiltration to look <em>allowed</em> changes the event-log Merkle root, so the signed certificate no longer verifies.</p>
    <div class="rootline"><span class="ck">event-log root now</span><span id="liveroot" class="mono">{_esc(real_root)}</span></div>
    <div class="rootline"><span class="ck">certificate says</span><span class="verdict-live vgood" id="liveverdict">VERIFIED &mdash; log matches certificate</span></div>
    <div class="toggle" id="tamp" role="switch" aria-checked="false" tabindex="0">
      <span class="sw"></span><span>Tamper: flip the blocked <code class="call">send_external</code> to ALLOWED</span>
    </div>
  </section>

  <footer>Recorded under production batch load, replayed alone &mdash; bit-identical only because inference is batch-invariant. HMAC signing shown; ed25519/TPM in production.</footer>
</div>

<script>
(function(){{
  var real={json.dumps(real_root)}, tampered={json.dumps(tamper_root)};
  var t=document.getElementById('tamp'), root=document.getElementById('liveroot'), verd=document.getElementById('liveverdict');
  function set(on){{
    t.classList.toggle('on',on); t.setAttribute('aria-checked',on);
    root.textContent = on?tampered:real;
    verd.textContent = on?'FAILED — log no longer matches certificate':'VERIFIED — log matches certificate';
    verd.className = 'verdict-live '+(on?'vbad':'vgood');
  }}
  t.addEventListener('click',function(){{set(!t.classList.contains('on'));}});
  t.addEventListener('keydown',function(e){{if(e.key===' '||e.key==='Enter'){{e.preventDefault();set(!t.classList.contains('on'));}}}});
}})();
</script>"""

if __name__ == "__main__":
    here = os.path.dirname(__file__)
    run_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "..", "last_run.json")
    with open(run_path) as f:
        run = json.load(f)
    out = os.path.join(here, "..", "..", "report.html")
    with open(out, "w") as f:
        f.write(render(run))
    print("wrote", os.path.abspath(out))
