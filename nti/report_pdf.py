"""PDF report generator (executive + tactical) built with ReportLab + Matplotlib."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_CENTER, TA_LEFT  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import cm  # noqa: E402
from reportlab.platypus import Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # noqa: E402

from .utils import defang, fmt_duration, fmt_ts, human_bytes  # noqa: E402

NAVY = colors.HexColor("#0B1F3A")
ACCENT = colors.HexColor("#1F6FEB")
LIGHT = colors.HexColor("#F3F6FA")
GRID = colors.HexColor("#D0D7E2")
MUTED = colors.HexColor("#5B6B80")
SEV_COLORS = {
    "Critical": "#8B0000", "High": "#D9480F", "Medium": "#E8A317",
    "Low": "#2F80ED", "Info": "#6C757D", "Clean": "#2E7D32",
}
CHART_COLORS = ["#1F6FEB", "#0B1F3A", "#E8A317", "#D9480F", "#2E7D32", "#8E44AD", "#16A085", "#6C757D"]

RECOMMENDATIONS = {
    "Threat Intel": "Block the listed domains/IPs at DNS, proxy and firewall; isolate affected hosts and perform endpoint forensics (memory + disk).",
    "DNS - DGA": "Isolate hosts generating DGA lookups, run EDR scan for the responsible process, and sinkhole the generated domains.",
    "DNS - Tunneling": "Block the tunneling domain, enforce DNS through corporate resolvers only, and alert on long/high-entropy query names.",
    "DNS - NXDOMAIN": "Review the process making failed lookups on the host; correlate with DGA findings.",
    "DNS - Suspicious TLD": "Consider blocking or alerting on high-abuse TLDs that have no business need.",
    "DNS - Resolver Bypass": "Block outbound UDP/TCP 53 and DoH/DoT except from approved resolvers.",
    "DNS - Anomalous Query": "Review long DNS queries for encoded data and verify the owning application.",
    "TLS - Non-standard Port": "Restrict egress to approved ports; inspect or block TLS on unusual ports.",
    "TLS - Missing SNI": "Alert on direct-to-IP TLS from workstations; route web traffic through an inspecting proxy.",
    "TLS - Weak Protocol": "Disable SSLv3/TLS 1.0/1.1 and identify legacy clients.",
    "TLS - Rare JA3": "Identify the software behind the rare fingerprint and add it to an allow/block list.",
    "C2 - Beaconing": "Treat the source host as compromised: isolate it, block the destination, and hunt for the implant and persistence.",
    "Exfiltration": "Block the destination, quantify data loss, determine which files were sent, and trigger the incident-response/legal process.",
    "Recon - Port Scan": "Investigate the scanning host (authorized scanner or compromise?) and review exposed services on the target.",
    "Recon - Host Sweep": "Confirm whether the sweep was authorized; segment the network to limit lateral discovery.",
    "DoS - SYN Flood": "Enable SYN cookies / rate limiting and engage upstream DDoS protection.",
    "Suspicious Port": "Block egress on backdoor ports and inspect the host for reverse shells or RATs.",
    "ICMP Tunneling": "Limit ICMP payload size at the perimeter and investigate the source process.",
    "ARP Spoofing": "Enable Dynamic ARP Inspection / port security, locate the rogue MAC on the switch and remove it.",
    "Cleartext Credentials": "Reset exposed credentials immediately and migrate to encrypted protocols (SFTP/FTPS, IMAPS, HTTPS).",
    "HTTP - Suspicious Request": "Retrieve and analyze the downloaded file in a sandbox; block the URL and hunt for execution on the host.",
}


# ----------------------------------------------------------------- styles
def _styles():
    ss = getSampleStyleSheet()
    s = {
        "title": ParagraphStyle("t", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=26,
                                textColor=colors.white, alignment=TA_LEFT, leading=32),
        "subtitle": ParagraphStyle("st", parent=ss["Normal"], fontSize=13, textColor=colors.HexColor("#C9D6EA"),
                                   leading=18),
        "h1": ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold", fontSize=16,
                             textColor=NAVY, spaceBefore=6, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=12,
                             textColor=ACCENT, spaceBefore=10, spaceAfter=5),
        "body": ParagraphStyle("b", parent=ss["Normal"], fontSize=9.5, leading=13.5),
        "small": ParagraphStyle("s", parent=ss["Normal"], fontSize=7.8, leading=10),
        "cell": ParagraphStyle("c", parent=ss["Normal"], fontSize=7.8, leading=9.8),
        "cellb": ParagraphStyle("cb", parent=ss["Normal"], fontSize=7.8, leading=9.8, fontName="Helvetica-Bold"),
        "hdr": ParagraphStyle("hd", parent=ss["Normal"], fontSize=8, leading=10, fontName="Helvetica-Bold",
                              textColor=colors.white),
        "kpi_v": ParagraphStyle("kv", parent=ss["Normal"], fontSize=14, leading=17, fontName="Helvetica-Bold",
                                textColor=NAVY, alignment=TA_CENTER),
        "kpi_l": ParagraphStyle("kl", parent=ss["Normal"], fontSize=7.5, leading=9, textColor=MUTED,
                                alignment=TA_CENTER),
        "bullet": ParagraphStyle("bl", parent=ss["Normal"], fontSize=9.5, leading=13.5, leftIndent=12,
                                 bulletIndent=2),
    }
    return s


def _p(text, style) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def _sev_badge(sev: str, st) -> Paragraph:
    return Paragraph(f'<font color="{SEV_COLORS.get(sev, "#000")}"><b>{escape(sev)}</b></font>', st["cell"])


def _table(header, rows, widths, st, sev_col: int | None = None, zebra=True) -> Table:
    data = [[_p(h, st["hdr"]) for h in header]]
    for r in rows:
        cells = []
        for i, v in enumerate(r):
            if isinstance(v, Paragraph):
                cells.append(v)
            elif sev_col is not None and i == sev_col:
                cells.append(_sev_badge(v, st))
            else:
                cells.append(_p(v, st["cell"]))
        data.append(cells)
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if zebra:
        for i in range(1, len(data)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), LIGHT))
    t.setStyle(TableStyle(style))
    return t


# ----------------------------------------------------------------- charts
def _fig_to_image(fig, width_cm: float) -> Image:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=170, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    buf.seek(0)
    img = Image(buf)
    ratio = img.imageHeight / img.imageWidth
    img.drawWidth = width_cm * cm
    img.drawHeight = width_cm * cm * ratio
    return img


def _style_axes(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.spines["left"].set_color("#B0B8C4")
    ax.spines["bottom"].set_color("#B0B8C4")
    ax.tick_params(colors="#3A4A5E", labelsize=8)


def _chart_severity(by_sev: dict) -> Image | None:
    labels = [s for s in ("Critical", "High", "Medium", "Low", "Info")]
    values = [by_sev.get(s, 0) for s in labels]
    if not any(values):
        return None
    fig, ax = plt.subplots(figsize=(5.2, 2.4))
    bars = ax.barh(labels[::-1], values[::-1], color=[SEV_COLORS[s] for s in labels[::-1]], height=0.6)
    for b, v in zip(bars, values[::-1], strict=False):
        ax.text(b.get_width() + 0.1, b.get_y() + b.get_height() / 2, str(v), va="center", fontsize=8)
    ax.set_title("Findings by severity", fontsize=10, color="#0B1F3A", loc="left")
    _style_axes(ax)
    ax.xaxis.set_major_locator(matplotlib.ticker.MaxNLocator(integer=True))
    return _fig_to_image(fig, 8.4)


def _chart_protocols(protocols: list) -> Image | None:
    if not protocols:
        return None
    top = protocols[:6]
    other = sum(n for _, n in protocols[6:])
    if other:
        top = top + [("Other", other)]
    fig, ax = plt.subplots(figsize=(4.2, 2.6))
    wedges, _ = ax.pie([n for _, n in top], colors=CHART_COLORS[:len(top)], startangle=90,
                       wedgeprops={"width": 0.38, "edgecolor": "white"})
    total = sum(n for _, n in top)
    ax.legend(wedges, [f"{k} ({n / total:.0%})" for k, n in top], loc="center left",
              bbox_to_anchor=(1, 0.5), fontsize=7.5, frameon=False)
    ax.set_title("Packets by protocol", fontsize=10, color="#0B1F3A", loc="left")
    return _fig_to_image(fig, 8.4)


def _chart_tls_ips(servers: list) -> Image | None:
    rows = servers[:10]
    if not rows:
        return None
    labels = [r["ip"] + (f"\n{r['sni'][0][:28]}" if r["sni"] else "") for r in rows][::-1]
    out = [r["bytes_out"] / 1024 / 1024 for r in rows][::-1]
    inn = [r["bytes_in"] / 1024 / 1024 for r in rows][::-1]
    fig, ax = plt.subplots(figsize=(7.6, 0.42 * len(rows) + 1.1))
    ax.barh(labels, out, color="#D9480F", label="Sent by internal client (MB)", height=0.6)
    ax.barh(labels, inn, left=out, color="#1F6FEB", label="Received from server (MB)", height=0.6)
    ax.set_title("TLS/HTTPS volume per destination IP (top 10)", fontsize=10, color="#0B1F3A", loc="left")
    ax.legend(fontsize=7.5, frameon=False, loc="lower right")
    ax.tick_params(axis="y", labelsize=7)
    _style_axes(ax)
    return _fig_to_image(fig, 17)


def _chart_domains(top_domains: list) -> Image | None:
    if not top_domains:
        return None
    rows = top_domains[:12][::-1]
    fig, ax = plt.subplots(figsize=(7.6, 0.32 * len(rows) + 1))
    ax.barh([d[:40] for d, _ in rows], [n for _, n in rows], color="#0B1F3A", height=0.6)
    ax.set_title("Most queried base domains", fontsize=10, color="#0B1F3A", loc="left")
    ax.tick_params(axis="y", labelsize=7.5)
    _style_axes(ax)
    return _fig_to_image(fig, 15.5)


def _chart_timeline(timeline: list, bucket: int) -> Image | None:
    if len(timeline) < 2:
        return None
    xs = [datetime.fromtimestamp(t, tz=timezone.utc) for t, _ in timeline]
    ys = [n for _, n in timeline]
    fig, ax = plt.subplots(figsize=(7.6, 2.3))
    ax.fill_between(xs, ys, color="#1F6FEB", alpha=0.18, step="mid")
    ax.plot(xs, ys, color="#1F6FEB", lw=1.4, drawstyle="steps-mid")
    ax.set_title(f"Packet rate over time ({bucket}s buckets, UTC)", fontsize=10, color="#0B1F3A", loc="left")
    ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%H:%M"))
    _style_axes(ax)
    return _fig_to_image(fig, 17)


def _domain_list(domains: list, limit: int = 6) -> str:
    if not domains:
        return "-"
    text = ", ".join(defang(d) for d in domains[:limit])
    return text + (f" (+{len(domains) - limit} more)" if len(domains) > limit else "")


# ------------------------------------------------------------- page decor
def _decorate(meta):
    def on_page(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(NAVY)
        canvas.rect(0, h - 1.1 * cm, w, 1.1 * cm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(1.6 * cm, h - 0.7 * cm, "NETWORK TRAFFIC INVESTIGATION REPORT")
        canvas.setFont("Helvetica", 8.5)
        canvas.drawRightString(w - 1.6 * cm, h - 0.7 * cm, f"Case {meta['case_id']}")
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(1.6 * cm, 0.9 * cm, f"TLP:{meta['tlp']}  |  Generated {meta['generated']}")
        canvas.drawRightString(w - 1.6 * cm, 0.9 * cm, f"Page {doc.page}")
        canvas.setStrokeColor(GRID)
        canvas.line(1.6 * cm, 1.25 * cm, w - 1.6 * cm, 1.25 * cm)
        canvas.restoreState()

    def on_cover(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(NAVY)
        canvas.rect(0, h * 0.52, w, h * 0.48, fill=1, stroke=0)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, h * 0.52 - 0.18 * cm, w, 0.18 * cm, fill=1, stroke=0)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(1.6 * cm, 0.9 * cm, f"TLP:{meta['tlp']}  |  CONFIDENTIAL - for authorized recipients only")
        canvas.restoreState()

    return on_cover, on_page


# ------------------------------------------------------------- narrative
def _executive_narrative(res: dict) -> list[str]:
    risk, findings = res["risk"], res["findings"]
    stats = res["stats"]
    cats = risk["by_category"]
    paras = [
        f"This report presents the results of an automated forensic analysis of "
        f"{stats['packets']:,} packets ({human_bytes(stats['bytes'])}) captured over "
        f"{fmt_duration(stats['duration'])} between {fmt_ts(stats['start'])} and {fmt_ts(stats['end'])}. "
        f"{res['traffic']['internal_hosts']} internal and {res['traffic']['external_hosts']} external hosts "
        f"were observed across {res['traffic']['flows']:,} network flows."
    ]
    if not findings:
        paras.append("No malicious or anomalous behaviour was detected with the current detection thresholds. "
                     "The capture appears consistent with normal activity.")
        return paras
    bs = risk["by_severity"]
    paras.append(
        f"The overall risk rating is <b>{risk['level'].upper()}</b> (score {risk['score']}/100). "
        f"The engine raised {len(findings)} findings: {bs['Critical']} critical, {bs['High']} high, "
        f"{bs['Medium']} medium and {bs['Low']} low severity, producing {len(res['iocs'])} unique indicators of compromise."
    )
    key = []
    if any(c.startswith("C2") for c in cats) or "Threat Intel" in cats:
        key.append("command-and-control communication (periodic beaconing and/or contact with blocklisted infrastructure)")
    if "Exfiltration" in cats or "DNS - Tunneling" in cats:
        key.append("probable data exfiltration (large outbound transfers and/or DNS tunneling)")
    if "DNS - DGA" in cats:
        key.append("malware-style domain generation (DGA) lookups")
    if any(c.startswith("Recon") for c in cats):
        key.append("internal reconnaissance (port scanning / host sweeps)")
    if "ARP Spoofing" in cats:
        key.append("man-in-the-middle activity via ARP spoofing")
    if "Cleartext Credentials" in cats:
        key.append("credentials exposed in cleartext protocols")
    if key:
        paras.append("Key observations indicate " + "; ".join(key) + ".")
    hosts = {}
    for f in findings:
        if f["severity"] in ("Critical", "High"):
            for h in (f["src"] or "").split(", "):
                if h:
                    hosts[h] = hosts.get(h, 0) + 1
    if hosts:
        top = sorted(hosts.items(), key=lambda kv: -kv[1])[:5]
        paras.append("Hosts requiring immediate attention: " +
                     ", ".join(f"<b>{escape(h)}</b> ({n} high-severity findings)" for h, n in top) + ".")
    return paras


# ------------------------------------------------------------------ build
def build_pdf(res: dict, out_path: str) -> str:
    st = _styles()
    meta = res["meta"]
    doc = SimpleDocTemplate(out_path, pagesize=A4, leftMargin=1.6 * cm, rightMargin=1.6 * cm,
                            topMargin=1.7 * cm, bottomMargin=1.7 * cm,
                            title=f"Network Traffic Investigation - {meta['case_id']}",
                            author=meta["analyst"], subject="PCAP forensic analysis")
    on_cover, on_page = _decorate(meta)
    story = []
    W = A4[0] - 3.2 * cm
    risk = res["risk"]

    # ================================ Cover
    story.append(Spacer(1, 3.2 * cm))
    story.append(Paragraph("Network Traffic<br/>Investigation Report", st["title"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("Executive &amp; Tactical Analysis of Packet Capture Evidence", st["subtitle"]))
    story.append(Spacer(1, 6.6 * cm))
    rc = SEV_COLORS.get(risk["level"], "#000")
    badge = Table([[Paragraph(f'<font color="white" size="9">OVERALL RISK</font><br/>'
                              f'<font color="white" size="22"><b>{risk["level"].upper()}</b></font><br/>'
                              f'<font color="white" size="9">Score {risk["score"]}/100</font>',
                              ParagraphStyle("bd", alignment=TA_CENTER, leading=26))]],
                  colWidths=[6 * cm], rowHeights=[3.0 * cm])
    badge.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(rc)),
                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    files = "<br/>".join(escape(f["name"]) for f in meta["files"])
    sha = "<br/>".join(escape(f["sha256"]) for f in meta["files"])
    info = [
        ["Case ID", meta["case_id"]],
        ["Evidence file(s)", Paragraph(files, st["cell"])],
        ["SHA-256", Paragraph(sha, st["cell"])],
        ["Capture window", f"{fmt_ts(res['stats']['start'])} -> {fmt_ts(res['stats']['end'])}"],
        ["Analyst", meta["analyst"]],
        ["Report generated", meta["generated"]],
        ["Classification", f"TLP:{meta['tlp']}"],
    ]
    info_t = Table([[_p(k, st["cellb"]), v if isinstance(v, Paragraph) else _p(v, st["cell"])] for k, v in info],
                   colWidths=[3.2 * cm, 8.2 * cm])
    info_t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, GRID), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    story.append(Table([[info_t, badge]], colWidths=[11.8 * cm, 6.2 * cm],
                       style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(PageBreak())

    # ================================ 1. Executive summary
    story.append(_p("1. Executive Summary", st["h1"]))
    for para in _executive_narrative(res):
        story.append(Paragraph(para, st["body"]))
        story.append(Spacer(1, 4))
    stats, traffic, dns, tls = res["stats"], res["traffic"], res["dns"], res["tls"]
    kpis = [
        (f"{stats['packets']:,}", "Packets"), (human_bytes(stats["bytes"]), "Total volume"),
        (str(traffic["unique_ips"]), "Unique IPs"), (f"{dns['total_queries']:,}", "DNS queries"),
        (f"{tls['sessions']:,}", "TLS sessions"), (str(len(res["iocs"])), "Unique IOCs"),
    ]
    kt = Table([[Paragraph(escape(v), st["kpi_v"]) for v, _ in kpis],
                [Paragraph(escape(lbl), st["kpi_l"]) for _, lbl in kpis]], colWidths=[W / 6] * 6)
    kt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), LIGHT), ("BOX", (0, 0), (-1, -1), 0.5, GRID),
                            ("LINEAFTER", (0, 0), (-2, -1), 0.5, colors.white),
                            ("TOPPADDING", (0, 0), (-1, 0), 8), ("BOTTOMPADDING", (0, 1), (-1, 1), 8)]))
    story.append(Spacer(1, 6))
    story.append(kt)
    story.append(Spacer(1, 8))
    c1, c2 = _chart_severity(risk["by_severity"]), _chart_protocols(traffic["protocols"])
    if c1 or c2:
        story.append(Table([[c1 or "", c2 or ""]], colWidths=[W / 2, W / 2]))

    story.append(_p("Top priority findings", st["h2"]))
    top = [f for f in res["findings"] if f["severity"] in ("Critical", "High")][:8] or res["findings"][:8]
    if top:
        story.append(_table(["Severity", "Finding", "Source", "ATT&CK"],
                            [[f["severity"], f["title"], f["src"] or "-", f["mitre"].split(" ")[0]] for f in top],
                            [1.7 * cm, 9.6 * cm, 3.5 * cm, 3.2 * cm], st, sev_col=0))
    else:
        story.append(_p("No findings.", st["body"]))

    story.append(_p("Immediate actions", st["h2"]))
    seen = []
    for f in res["findings"]:
        if f["severity"] in ("Critical", "High") and f["category"] not in seen:
            seen.append(f["category"])
    for cat in seen[:6]:
        story.append(Paragraph(f"<b>{escape(cat)}:</b> {escape(RECOMMENDATIONS.get(cat, 'Investigate.'))}",
                               st["bullet"], bulletText="•"))
    if not seen:
        story.append(_p("Continue routine monitoring; no urgent action required.", st["body"]))
    story.append(PageBreak())

    # ================================ 2. IOC summary
    story.append(_p("2. Indicators of Compromise (IOCs)", st["h1"]))
    story.append(_p("Indicators are defanged for safe handling. A machine-readable copy is provided in the "
                    "accompanying CSV/JSON exports for SIEM/firewall ingestion.", st["body"]))
    story.append(Spacer(1, 6))
    if res["iocs"]:
        rows = [[i["severity"], i["type"].upper(), defang(i["value"]) if i["type"] in ("ip", "domain", "url") else i["value"],
                 ", ".join(i["categories"]), str(i["hits"]), i.get("context") or "-"] for i in res["iocs"][:120]]
        story.append(_table(["Severity", "Type", "Indicator", "Related detections", "Hits", "Context"], rows,
                            [1.6 * cm, 1.5 * cm, 5.2 * cm, 5.2 * cm, 1.1 * cm, 3.4 * cm], st, sev_col=0))
    else:
        story.append(_p("No indicators extracted.", st["body"]))
    story.append(PageBreak())

    # ================================ 3. Tactical findings
    story.append(_p("3. Tactical Findings", st["h1"]))
    story.append(_p("Detailed findings ordered by severity, each mapped to MITRE ATT&CK with supporting evidence.",
                    st["body"]))
    for n, f in enumerate(res["findings"], 1):
        sc = SEV_COLORS[f["severity"]]
        head = Table([[Paragraph(f'<font color="white"><b>{escape(f["severity"].upper())}</b></font>',
                                 ParagraphStyle("x", fontSize=8, alignment=TA_CENTER)),
                       Paragraph(f'<b>F-{n:03d}</b> &nbsp; {escape(f["title"])}', st["cell"])]],
                     colWidths=[2 * cm, W - 2 * cm])
        head.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), colors.HexColor(sc)),
                                  ("BACKGROUND", (1, 0), (1, 0), LIGHT),
                                  ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                  ("BOX", (0, 0), (-1, -1), 0.4, GRID)]))
        when = fmt_ts(f["first_seen"]) + (f" -> {fmt_ts(f['last_seen'])}" if f.get("last_seen") else "")
        details = [
            ["Category", f["category"], "ATT&CK", f["mitre"] or "-"],
            ["Source", f["src"] or "-", "Destination", f["dst"] or "-"],
            ["Observed", when, "Occurrences", str(f["count"])],
        ]
        dt = Table([[_p(a, st["cellb"]), _p(b, st["cell"]), _p(c, st["cellb"]), _p(d, st["cell"])]
                    for a, b, c, d in details],
                   colWidths=[2 * cm, 6.2 * cm, 2.2 * cm, W - 10.4 * cm])
        dt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.3, GRID),
                                ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        block = [head, Spacer(1, 2), _p(f["description"], st["small"]), Spacer(1, 2), dt]
        if f["evidence"]:
            ev = "<br/>".join("&bull; " + escape(str(e)) for e in f["evidence"][:10])
            block += [Spacer(1, 2), Paragraph(f"<b>Evidence:</b><br/>{ev}", st["small"])]
        block.append(Spacer(1, 9))
        story.append(KeepTogether(block))
    if not res["findings"]:
        story.append(_p("No findings were produced.", st["body"]))
    story.append(PageBreak())

    # ================================ 4. DNS analysis
    story.append(_p("4. DNS Analysis", st["h1"]))
    rcodes = dict(dns["rcodes"])
    dns_kv = [
        ["Total queries", f"{dns['total_queries']:,}", "Responses", f"{dns['total_responses']:,}"],
        ["Unique names", f"{dns['unique_names']:,}", "Unique base domains", f"{dns['unique_base_domains']:,}"],
        ["NXDOMAIN", str(rcodes.get("NXDOMAIN", 0)), "Query types",
         ", ".join(f"{k}:{v}" for k, v in dns["qtypes"][:6]) or "-"],
        ["Resolvers", ", ".join(f"{k} ({v})" for k, v in dns["resolvers"]) or "-", "Top client",
         f"{dns['top_clients'][0][0]} ({dns['top_clients'][0][1]})" if dns["top_clients"] else "-"],
    ]
    story.append(_table(["Metric", "Value", "Metric", "Value"], dns_kv,
                        [3.2 * cm, 5.8 * cm, 3.4 * cm, 5.6 * cm], st))
    story.append(Spacer(1, 8))
    ch = _chart_domains(dns["top_domains"])
    if ch:
        story.append(ch)
    dns_f = [f for f in res["findings"] if f["category"].startswith("DNS") or
             (f["category"] == "Threat Intel" and "DNS" in f["title"])]
    story.append(_p("Suspicious DNS activity", st["h2"]))
    if dns_f:
        story.append(_table(["Severity", "Detection", "Domain(s)", "Client(s)", "Count"],
                            [[f["severity"], f["category"].replace("DNS - ", ""),
                              _domain_list([i["value"] for i in f["indicators"] if i["type"] == "domain"]),
                              f["src"] or "-", str(f["count"])] for f in dns_f],
                            [1.6 * cm, 2.8 * cm, 8.2 * cm, 3.6 * cm, 1.8 * cm], st, sev_col=0))
    else:
        story.append(_p("No suspicious DNS activity detected.", st["body"]))
    story.append(PageBreak())

    # ================================ 5. TLS analysis
    story.append(_p("5. TLS / HTTPS Analysis", st["h1"]))
    story.append(Paragraph(
        f"{tls['sessions']:,} TLS sessions were identified ({tls['handshakes_parsed']:,} with a parsed ClientHello), "
        f"carrying <b>{escape(human_bytes(tls['total_bytes']))}</b> in total to {len(tls['servers'])} distinct server IPs "
        f"and {tls['unique_sni']} unique SNI values. Protocol versions offered: "
        f"{escape(', '.join(f'{k} ({v})' for k, v in tls['versions']) or 'n/a')}.", st["body"]))
    story.append(Spacer(1, 6))
    ch = _chart_tls_ips(tls["servers"])
    if ch:
        story.append(ch)
    story.append(_p("Data volume per destination IP", st["h2"]))
    if tls["servers"]:
        rows = [[s["ip"], ", ".join(s["sni"] or s["dns_names"])[:60] or "(no SNI)",
                 ",".join(map(str, s["ports"])), str(s["sessions"]), human_bytes(s["bytes_out"]),
                 human_bytes(s["bytes_in"]), human_bytes(s["total"])] for s in tls["servers"][:30]]
        story.append(_table(["Server IP", "SNI / DNS name", "Port", "Sess.", "Sent", "Received", "Total"], rows,
                            [2.6 * cm, 5.6 * cm, 1.4 * cm, 1.1 * cm, 2.4 * cm, 2.4 * cm, 2.5 * cm], st))
    story.append(_p("Data volume per internal client", st["h2"]))
    if tls["clients"]:
        rows = [[c["ip"], str(c["sessions"]), str(c["servers"]), human_bytes(c["bytes_out"]),
                 human_bytes(c["bytes_in"]), human_bytes(c["total"])] for c in tls["clients"][:20]]
        story.append(_table(["Client IP", "Sessions", "Servers", "Sent", "Received", "Total"], rows,
                            [3.4 * cm, 2.4 * cm, 2.4 * cm, 3.2 * cm, 3.2 * cm, 3.4 * cm], st))
    if tls["ja3_top"]:
        story.append(_p("JA3 client fingerprints", st["h2"]))
        story.append(_table(["JA3 hash", "Sessions"], [[h, str(n)] for h, n in tls["ja3_top"]],
                            [12 * cm, 3 * cm], st))
    story.append(PageBreak())

    # ================================ 6. Traffic overview
    story.append(_p("6. Traffic Overview", st["h1"]))
    ch = _chart_timeline(traffic["timeline"], traffic["bucket_seconds"])
    if ch:
        story.append(ch)
    story.append(_p("Top talkers", st["h2"]))
    story.append(_table(["IP", "Scope", "Sent", "Received", "Total"],
                        [[t["ip"], "Internal" if t["internal"] else "External", human_bytes(t["sent"]),
                          human_bytes(t["recv"]), human_bytes(t["bytes"])] for t in traffic["top_talkers"][:12]],
                        [4.4 * cm, 2.6 * cm, 3.6 * cm, 3.6 * cm, 3.8 * cm], st))
    story.append(_p("Top conversations", st["h2"]))
    story.append(_table(["Client", "Server", "Service", "Bytes"],
                        [[c["client"], c["server"], f"{c['proto']}/{c['port']}", human_bytes(c["bytes"])]
                         for c in traffic["top_conversations"][:12]],
                        [4.8 * cm, 4.8 * cm, 3.6 * cm, 4.8 * cm], st))
    story.append(PageBreak())

    # ================================ 7. Recommendations + methodology
    story.append(_p("7. Recommendations", st["h1"]))
    cats = list(dict.fromkeys(f["category"] for f in res["findings"]))
    if cats:
        story.append(_table(["Detection area", "Recommended response"],
                            [[c, RECOMMENDATIONS.get(c, "Investigate further.")] for c in cats],
                            [4.4 * cm, 13.6 * cm], st))
    story.append(Spacer(1, 6))
    for line in ["Preserve the original PCAP and its SHA-256 hash to maintain chain of custody.",
                 "Correlate these network findings with EDR, proxy and authentication logs for the same window.",
                 "Feed the exported IOC list into SIEM watchlists and perimeter block lists.",
                 "Re-run this analysis on subsequent captures to confirm containment."]:
        story.append(Paragraph(escape(line), st["bullet"], bulletText="•"))

    story.append(_p("Appendix A - Methodology & Thresholds", st["h1"]))
    story.append(_p("Packets are streamed once with Scapy and aggregated into bidirectional flows. TLS ClientHello "
                    "messages are parsed to extract SNI and compute JA3 fingerprints. DNS transactions are analysed "
                    "for entropy (DGA), subdomain volume (tunneling), NXDOMAIN rates and threat-intel matches. "
                    "Behavioural detectors cover beaconing (interval regularity), scanning, exfiltration volume, "
                    "suspicious ports, ICMP tunneling, ARP spoofing and cleartext credentials. Detections are "
                    "heuristic and should be validated by an analyst.", st["body"]))
    story.append(Spacer(1, 6))
    th = res["meta"]["thresholds"]
    keys = list(th.items())
    half = (len(keys) + 1) // 2
    rows = []
    for i in range(half):
        a = keys[i]
        b = keys[i + half] if i + half < len(keys) else ("", "")
        rows.append([a[0], str(a[1]), b[0], str(b[1])])
    story.append(_table(["Parameter", "Value", "Parameter", "Value"], rows,
                        [5 * cm, 4 * cm, 5 * cm, 4 * cm], st))
    story.append(Spacer(1, 6))
    ti = meta["intel"]
    story.append(_p(f"Threat intel loaded: {ti['domains']} domains, {ti['ips']} IPs, {ti['ja3']} JA3 hashes. "
                    f"Internal networks: {', '.join(meta['internal_cidrs'])}. Parse errors: {stats['errors']}.",
                    st["small"]))

    doc.build(story, onFirstPage=on_cover, onLaterPages=on_page)
    return out_path
