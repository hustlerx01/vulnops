"""python -m vulnops.cli --trivy scans/trivy.json --grype scans/grype.json --zap scans/zap.json -o results [--offline] [--today YYYY-MM-DD]"""
import argparse, csv, json, time
from collections import Counter
from datetime import date, datetime
from pathlib import Path
from .normalize import from_trivy, from_grype, from_zap, merge
from .feeds import load_kev, load_epss
from .prioritize import enrich, apply_sla
from .dashboard import render


def compare(findings, top=20):
    """How many KEV / high-EPSS items land in the first `top` slots: CVSS-only ordering vs ours."""
    by_cvss = sorted(findings, key=lambda f: -f["cvss"])[:top]
    ours = findings[:top]
    hot = lambda xs: sum(f["kev"] for f in xs), lambda xs: sum((f["epss"] or 0) >= 0.10 for f in xs)
    kev_total = sum(f["kev"] for f in findings)
    return {"top_n": top, "kev_total": kev_total,
            "kev_in_top_cvss_only": hot[0](by_cvss), "kev_in_top_risk_based": hot[0](ours),
            "epss>=0.1_in_top_cvss_only": hot[1](by_cvss), "epss>=0.1_in_top_risk_based": hot[1](ours),
            "workload_cvss>=7": sum(f["cvss"] >= 7 for f in findings),
            "workload_P0+P1": sum(f["priority"] in ("P0", "P1") for f in findings)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--trivy"); ap.add_argument("--grype"); ap.add_argument("--zap")
    ap.add_argument("-o", "--out", default="results"); ap.add_argument("--feeds", default="feeds")
    ap.add_argument("--state", default="state.json"); ap.add_argument("--offline", action="store_true")
    ap.add_argument("--today", default=None, help="override 'today' (simulate SLA ageing)")
    a = ap.parse_args(argv)
    t0 = time.time()
    raw = []
    for path, fn in ((a.trivy, from_trivy), (a.grype, from_grype), (a.zap, from_zap)):
        if path:
            raw += fn(json.loads(Path(path).read_text()))
    merged = merge(raw)
    kev = load_kev(Path(a.feeds), offline=a.offline)
    epss = load_epss([f["cve"] for f in merged], Path(a.feeds), offline=a.offline)
    findings = enrich(merged, kev, epss)
    today = date.fromisoformat(a.today) if a.today else date.today()
    sp = Path(a.state); state = json.loads(sp.read_text()) if sp.exists() else {}
    summary = apply_sla(findings, state, today)
    sp.write_text(json.dumps(state, indent=1, sort_keys=True))
    raw_by_tool = Counter(t for f in raw for t in f["tools"])
    dated = [v["date"] for v in epss.values() if v.get("date")]
    metrics = {"raw_by_tool": dict(raw_by_tool), "raw_total": len(raw), "after_dedup": len(merged),
               "dedup_removed": len(raw) - len(merged),
               "with_cve": sum(bool(f["cve"]) for f in findings), "epss_scored": sum(f["epss"] is not None for f in findings),
               "by_priority": dict(sorted(Counter(f["priority"] for f in findings).items())),
               "kev_ransomware": sum(f["kev_ransomware"] for f in findings), **compare(findings), "sla": summary,
               "today": today.isoformat(), "runtime_s": round(time.time() - t0, 2)}
    meta = {"kev_version": kev["catalogVersion"], "kev_count": kev["count"], "epss_date": max(dated) if dated else None}
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(findings, indent=1))
    with open(out / "findings.csv", "w", newline="") as fh:
        cols = ["priority", "risk_score", "cve", "vuln_id", "package", "version", "fixed_version", "cvss", "epss", "kev", "tools", "first_seen", "due", "sla_status", "title"]
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore"); w.writeheader()
        for f in findings:
            w.writerow({**f, "tools": "+".join(f["tools"])})
    (out / "metrics.json").write_text(json.dumps({**metrics, "feeds": meta}, indent=1))
    (out / "dashboard.html").write_text(render(findings, summary, metrics, meta, datetime.now().strftime("%Y-%m-%d %H:%M IST")))
    print(json.dumps({**metrics, "feeds": meta}, indent=1))


if __name__ == "__main__":
    main()
