"""Static, dependency-free HTML dashboard (open results/dashboard.html in any browser)."""
from html import escape

COL = {"P0": "#b91c1c", "P1": "#ea580c", "P2": "#ca8a04", "P3": "#4b5563", "BREACHED": "#b91c1c", "DUE_SOON": "#ea580c", "OK": "#15803d"}


def _epss(f):
    return "" if f["epss"] is None else f"{f['epss']:.3f}"


def _bars(title, counts):
    mx = max(counts.values() or [1]) or 1
    rows = "".join(f'<div class="bar"><span>{escape(str(k))}</span><div style="width:{v / mx * 100:.0f}%;background:{COL.get(k, "#2563eb")}">{v}</div></div>'
                   for k, v in counts.items())
    return f'<div class="card"><h3>{escape(title)}</h3>{rows}</div>'


def render(findings, summary, metrics, feeds_meta, generated):
    from collections import Counter
    pr = Counter(f["priority"] for f in findings); sla = Counter(f["sla_status"] for f in findings)
    tools = Counter(t for f in findings for t in f["tools"])
    kpis = [("Open findings", summary["open"]), ("P0 (KEV)", pr.get("P0", 0)), ("P1", pr.get("P1", 0)),
            ("SLA breached", summary["breached"]), ("Due ≤3d", summary["due_soon"]), ("MTTR (d)", summary["mttr_days"] if summary["mttr_days"] is not None else "–")]
    rows = "".join(
        f"<tr><td><b style='color:{COL[f['priority']]}'>{f['priority']}</b></td><td>{f['risk_score']}</td><td>{escape(f['cve'] or f['vuln_id'])}</td>"
        f"<td>{escape(f['package'])} {escape(f['version'])}</td><td>{escape(f['fixed_version'] or '-')}</td><td>{f['cvss']}</td>"
        f"<td>{_epss(f)}</td><td>{'✔' + (' 🔒ransomware' if f['kev_ransomware'] else '') if f['kev'] else ''}</td>"
        f"<td>{','.join(f['tools'])}</td><td>{f['due']}</td><td style='color:{COL[f['sla_status']]}'>{f['sla_status']} ({f['days_left']}d)</td>"
        f"<td>{escape(f['title'][:70])}</td></tr>" for f in findings)
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>VulnOps dashboard (lab)</title><style>
body{{font-family:system-ui,sans-serif;margin:24px;background:#f8fafc;color:#0f172a}} .kpis{{display:flex;gap:12px;flex-wrap:wrap}}
.kpi{{background:#fff;border-radius:8px;padding:12px 18px;box-shadow:0 1px 3px #0002}} .kpi b{{font-size:28px;display:block}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:16px 0}} .card{{background:#fff;border-radius:8px;padding:12px;box-shadow:0 1px 3px #0002}}
.bar{{display:flex;align-items:center;margin:4px 0}} .bar span{{width:90px;font-size:13px}} .bar div{{color:#fff;font-size:12px;padding:2px 6px;border-radius:3px;min-width:18px}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:12px}} td,th{{border-bottom:1px solid #e2e8f0;padding:4px 6px;text-align:left}}
</style></head><body><h1>VulnOps — risk-based vulnerability dashboard</h1>
<p><b>LAB DATA</b>: scans of an intentionally outdated sample app. Generated {escape(generated)}. CISA KEV catalog {escape(str(feeds_meta['kev_version']))} ({feeds_meta['kev_count']} CVEs); EPSS scores dated {escape(str(feeds_meta['epss_date']))}.</p>
<div class="kpis">{''.join(f'<div class="kpi"><b>{v}</b>{escape(k)}</div>' for k, v in kpis)}</div>
<div class="grid">{_bars('By priority', dict(sorted(pr.items())))}{_bars('SLA status', dict(sla))}{_bars('Findings per tool (after dedup)', dict(tools))}</div>
<div class="card"><h3>CVSS-only vs risk-based (CVSS+EPSS+KEV)</h3><pre>{escape(__import__('json').dumps(metrics, indent=1))}</pre></div>
<h2>Fix queue</h2><table><tr><th>Pri</th><th>Risk</th><th>ID</th><th>Package</th><th>Fix</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Tools</th><th>Due</th><th>SLA</th><th>Title</th></tr>{rows}</table>
</body></html>"""
