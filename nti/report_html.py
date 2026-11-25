"""Self-contained interactive HTML dashboard (no external assets, works offline)."""

from __future__ import annotations

import json
from html import escape

from nti.utils import defang, fmt_duration, fmt_ts, human_bytes

SEV_COLORS = {"Critical": "#d7263d", "High": "#f46036", "Medium": "#e5a50a", "Low": "#2e86ab", "Info": "#7a869a"}
RISK_COLORS = {**SEV_COLORS, "Clean": "#2a9d8f"}

CSS = """
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1f2630;--text:#e6edf3;--muted:#8b949e;--line:#30363d;--accent:#58a6ff}
@media (prefers-color-scheme: light){:root{--bg:#f6f8fa;--panel:#fff;--panel2:#f0f3f6;--text:#1f2328;--muted:#59636e;--line:#d0d7de;--accent:#0969da}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:28px 32px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:24px;align-items:center;justify-content:space-between}
h1{margin:0;font-size:22px}h2{font-size:17px;margin:0 0 14px}.muted{color:var(--muted)}
main{max-width:1280px;margin:0 auto;padding:24px 32px 64px}
.risk{display:flex;align-items:center;gap:14px}.gauge{width:84px;height:84px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.kpi b{display:block;font-size:22px}.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:20px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px}@media(max-width:900px){.grid2{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;cursor:pointer;user-select:none}
tr:hover td{background:var(--panel2)}code{font:12px ui-monospace,Consolas,monospace;word-break:break-all}
.sev{display:inline-block;padding:2px 8px;border-radius:999px;color:#fff;font-size:11px;font-weight:700}
.bar{height:8px;border-radius:4px;background:var(--accent)}.barwrap{background:var(--panel2);border-radius:4px;min-width:80px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
input[type=search]{flex:1;min-width:200px;padding:8px 12px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--text)}
.chip{padding:6px 12px;border-radius:999px;border:1px solid var(--line);background:var(--panel2);color:var(--text);cursor:pointer;font-size:12px}
.chip.on{border-color:var(--accent);color:var(--accent)}
details summary{cursor:pointer}details ul{margin:6px 0 0;padding-left:18px;color:var(--muted)}
.sevbars div{display:flex;align-items:center;gap:10px;margin:6px 0}.sevbars label{width:70px}
button.copy{float:right;padding:6px 12px;border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--text);cursor:pointer}
footer{text-align:center;color:var(--muted);font-size:12px;padding:24px}
"""

JS = """
const q=document.getElementById('q');let sev='All';
function filt(){const t=q.value.toLowerCase();document.querySelectorAll('#findings tbody tr').forEach(r=>{
const okS=sev==='All'||r.dataset.sev===sev;r.style.display=okS&&r.innerText.toLowerCase().includes(t)?'':'none'})}
q.addEventListener('input',filt);
document.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{document.querySelectorAll('.chip').forEach(x=>x.classList.remove('on'));c.classList.add('on');sev=c.dataset.sev;filt()});
document.querySelectorAll('th').forEach((th,i)=>th.onclick=()=>{const tb=th.closest('table').tBodies[0];const idx=[...th.parentNode.children].indexOf(th);
const rows=[...tb.rows];const asc=th.dataset.asc!=='1';th.dataset.asc=asc?'1':'0';
rows.sort((a,b)=>{const x=a.cells[idx].dataset.v??a.cells[idx].innerText,y=b.cells[idx].dataset.v??b.cells[idx].innerText;
const nx=parseFloat(x),ny=parseFloat(y);const r=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y);return asc?r:-r});rows.forEach(r=>tb.appendChild(r))});
document.getElementById('copyIocs').onclick=()=>{navigator.clipboard.writeText(IOCS.map(i=>i.value).join('\\n'));
const b=document.getElementById('copyIocs');b.innerText='Copied';setTimeout(()=>b.innerText='Copy raw IOCs',1500)};
"""


def _e(v) -> str:
    return escape(str(v if v is not None else ""))


def _badge(sev: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLORS.get(sev, "#777")}">{_e(sev)}</span>'


def _bar(value: float, maximum: float) -> str:
    pct = 0 if not maximum else max(2, round(100 * value / maximum))
    return f'<div class="barwrap"><div class="bar" style="width:{pct}%"></div></div>'


def _gauge(score: int, color: str) -> str:
    circ = 2 * 3.14159 * 34
    dash = circ * score / 100
    return (f'<svg class="gauge" viewBox="0 0 84 84"><circle cx="42" cy="42" r="34" fill="none" stroke="var(--line)" '
            f'stroke-width="8"/><circle cx="42" cy="42" r="34" fill="none" stroke="{color}" stroke-width="8" '
            f'stroke-dasharray="{dash:.1f} {circ:.1f}" transform="rotate(-90 42 42)" stroke-linecap="round"/>'
            f'<text x="42" y="48" text-anchor="middle" font-size="20" font-weight="700" fill="var(--text)">{score}</text></svg>')


def build_html(res: dict, out_path: str) -> str:
    meta, stats, risk = res["meta"], res["stats"], res["risk"]
    dns, tls, traffic = res["dns"], res["tls"], res["traffic"]
    findings, iocs = res["findings"], res["iocs"]
    rc = RISK_COLORS.get(risk["level"], "#777")

    kpis = [
        ("Packets", f"{stats['packets']:,}"), ("Volume", human_bytes(stats["bytes"])),
        ("Duration", fmt_duration(stats["duration"])), ("Flows", f"{traffic['flows']:,}"),
        ("DNS queries", f"{dns['total_queries']:,}"), ("TLS sessions", f"{tls['sessions']:,}"),
        ("Findings", len(findings)), ("IOCs", len(iocs)),
    ]
    kpi_html = "".join(f'<div class="kpi"><b>{_e(v)}</b><span>{_e(k)}</span></div>' for k, v in kpis)

    max_sev = max(risk["by_severity"].values() or [0])
    sev_html = "".join(
        f'<div><label>{_badge(s)}</label><div style="flex:1">{_bar(n, max_sev)}</div><b>{n}</b></div>'
        for s, n in risk["by_severity"].items())

    cat_rows = "".join(f"<tr><td>{_e(c)}</td><td data-v='{n}'>{n}</td></tr>" for c, n in risk["by_category"].items())

    f_rows = []
    for n, f in enumerate(findings, 1):
        ev = "".join(f"<li>{_e(x)}</li>" for x in f.get("evidence", [])[:8])
        f_rows.append(
            f'<tr data-sev="{_e(f["severity"])}"><td>F-{n:03d}</td>'
            f'<td data-v="{["Info", "Low", "Medium", "High", "Critical"].index(f["severity"])}">{_badge(f["severity"])}</td>'
            f'<td><details><summary><b>{_e(f["title"])}</b></summary><p>{_e(f["description"])}</p><ul>{ev}</ul></details></td>'
            f'<td>{_e(f["category"])}</td><td><code>{_e(f["src"])}</code></td><td><code>{_e(f["dst"])}</code></td>'
            f'<td>{_e(f["mitre"])}</td><td data-v="{f["count"]}">{f["count"]}</td></tr>')

    i_rows = "".join(
        f'<tr><td>{_e(i["type"])}</td><td><code>{_e(defang(i["value"]))}</code></td>'
        f'<td data-v="{["Info", "Low", "Medium", "High", "Critical"].index(i["severity"])}">{_badge(i["severity"])}</td>'
        f'<td data-v="{i["hits"]}">{i["hits"]}</td><td>{_e(fmt_ts(i["first_seen"]))}</td>'
        f'<td>{_e("; ".join(i["categories"]))}</td><td>{_e(i.get("context", ""))}</td></tr>' for i in iocs)

    servers = tls["servers"][:20]
    max_tls = max((s["total"] for s in servers), default=0)
    t_rows = "".join(
        f'<tr><td><code>{_e(s["ip"])}</code></td><td>{_e(", ".join(s["sni"][:3]) or "-")}</td>'
        f'<td data-v="{s["sessions"]}">{s["sessions"]}</td><td data-v="{s["bytes_out"]}">{human_bytes(s["bytes_out"])}</td>'
        f'<td data-v="{s["bytes_in"]}">{human_bytes(s["bytes_in"])}</td>'
        f'<td data-v="{s["total"]}">{human_bytes(s["total"])}{_bar(s["total"], max_tls)}</td>'
        f'<td>{_e(", ".join(map(str, s["ports"])))}</td></tr>' for s in servers)

    max_dom = max((c for _, c in dns["top_domains"]), default=0)
    d_rows = "".join(f'<tr><td>{_e(d)}</td><td data-v="{c}">{c}{_bar(c, max_dom)}</td></tr>'
                     for d, c in dns["top_domains"])

    talk = traffic["top_talkers"]
    max_talk = max((t["bytes"] for t in talk), default=0)
    tk_rows = "".join(
        f'<tr><td><code>{_e(t["ip"])}</code></td><td>{"internal" if t["internal"] else "external"}</td>'
        f'<td data-v="{t["sent"]}">{human_bytes(t["sent"])}</td><td data-v="{t["recv"]}">{human_bytes(t["recv"])}</td>'
        f'<td data-v="{t["bytes"]}">{human_bytes(t["bytes"])}{_bar(t["bytes"], max_talk)}</td></tr>' for t in talk)

    files = ", ".join(f'{_e(f["name"])} <span class="muted">sha256 {_e(f["sha256"][:16])}…</span>' for f in meta["files"])
    ioc_json = json.dumps([{"type": i["type"], "value": i["value"]} for i in iocs]).replace("</", "<\\/")
    chips = "".join(f'<button class="chip{" on" if s == "All" else ""}" data-sev="{s}">{s}</button>'
                    for s in ["All", "Critical", "High", "Medium", "Low", "Info"])

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>NTI {_e(meta['case_id'])}</title>
<style>{CSS}</style></head><body>
<header><div><h1>Network Traffic Investigation &middot; {_e(meta['case_id'])}</h1>
<div class="muted">TLP:{_e(meta['tlp'])} &middot; Analyst: {_e(meta['analyst'])} &middot; Generated {_e(meta['generated'])} &middot; {_e(meta['tool'])}</div>
<div class="muted">Capture: {files}</div>
<div class="muted">Window: {_e(fmt_ts(stats['start']))} &rarr; {_e(fmt_ts(stats['end']))}</div></div>
<div class="risk">{_gauge(risk['score'], rc)}<div><div class="muted">Overall risk</div>
<div style="font-size:24px;font-weight:800;color:{rc}">{_e(risk['level'].upper())}</div></div></div></header>
<main>
<div class="kpis">{kpi_html}</div>
<div class="grid2"><section><h2>Findings by severity</h2><div class="sevbars">{sev_html}</div></section>
<section><h2>Findings by category</h2><table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>{cat_rows}</tbody></table></section></div>
<section><h2>Findings</h2><div class="toolbar"><input type="search" id="q" placeholder="Filter findings (IP, domain, technique...)">{chips}</div>
<table id="findings"><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Category</th><th>Source</th><th>Destination</th><th>MITRE ATT&amp;CK</th><th>Count</th></tr></thead>
<tbody>{''.join(f_rows)}</tbody></table></section>
<section><button class="copy" id="copyIocs">Copy raw IOCs</button><h2>Indicators of Compromise ({len(iocs)})</h2>
<table><thead><tr><th>Type</th><th>Value (defanged)</th><th>Severity</th><th>Hits</th><th>First seen</th><th>Categories</th><th>Context</th></tr></thead>
<tbody>{i_rows}</tbody></table></section>
<section><h2>TLS / HTTPS &mdash; data volume per server IP</h2>
<p class="muted">{tls['sessions']:,} sessions, {tls['handshakes_parsed']:,} ClientHellos parsed, {tls['unique_sni']} unique SNI, {human_bytes(tls['total_bytes'])} total.</p>
<table><thead><tr><th>Server IP</th><th>SNI</th><th>Sessions</th><th>Sent (client&rarr;srv)</th><th>Received</th><th>Total</th><th>Ports</th></tr></thead><tbody>{t_rows}</tbody></table></section>
<div class="grid2"><section><h2>Top DNS base domains</h2><table><thead><tr><th>Domain</th><th>Queries</th></tr></thead><tbody>{d_rows}</tbody></table></section>
<section><h2>Top talkers</h2><table><thead><tr><th>IP</th><th>Scope</th><th>Sent</th><th>Received</th><th>Total</th></tr></thead><tbody>{tk_rows}</tbody></table></section></div>
</main><footer>Generated by {_e(meta['tool'])} &middot; Detections are heuristic and must be validated by an analyst.</footer>
<script>const IOCS={ioc_json};{JS}</script></body></html>"""
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return out_path
