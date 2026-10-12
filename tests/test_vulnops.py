import json
from datetime import date
from pathlib import Path
from vulnops.normalize import from_trivy, from_grype, from_zap, merge
from vulnops.prioritize import enrich, apply_sla, priority
from vulnops.dashboard import render
from vulnops import cli

ROOT = Path(__file__).resolve().parents[1]
TRIVY = {"Results": [{"Target": "pom.xml", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2021-44228", "PkgName": "org.apache.logging.log4j:log4j-core", "InstalledVersion": "2.14.1",
     "FixedVersion": "2.15.0", "Severity": "CRITICAL", "CVSS": {"nvd": {"V3Score": 10.0}}, "Title": "Log4Shell"}]}]}
GRYPE = {"matches": [{"vulnerability": {"id": "GHSA-jfh8-c2jp-5v3q", "severity": "Critical", "cvss": [], "fix": {"versions": ["2.15.0"]}},
                      "relatedVulnerabilities": [{"id": "CVE-2021-44228", "cvss": [{"version": "3.1", "metrics": {"baseScore": 10.0}}]}],
                      "artifact": {"name": "log4j-core", "version": "2.14.1", "locations": [{"path": "/pom.xml"}]}}]}
ZAP = {"site": [{"@name": "http://127.0.0.1:8088", "alerts": [{"pluginid": "10038", "alert": "CSP Header Not Set", "riskcode": "2",
        "cweid": "693", "instances": [{"uri": "http://127.0.0.1:8088/"}]}]}]}
KEV = {"catalogVersion": "t", "count": 1, "by_cve": {"CVE-2021-44228": {"knownRansomwareCampaignUse": "Known", "dateAdded": "2021-12-10"}}}
EPSS = {"CVE-2021-44228": {"epss": 0.97, "percentile": 1.0, "date": "x"}}


def test_parsers_normalise_and_ghsa_maps_to_cve():
    t, g, z = from_trivy(TRIVY), from_grype(GRYPE), from_zap(ZAP)
    assert t[0]["cve"] == g[0]["cve"] == "CVE-2021-44228"
    assert z[0]["severity"] == "MEDIUM" and z[0]["cvss_source"] == "zap-riskcode-map"


def test_cross_tool_dedup_handles_maven_naming():
    m = merge(from_trivy(TRIVY) + from_grype(GRYPE) + from_zap(ZAP))
    assert len(m) == 2
    assert next(f for f in m if f["cve"])["tools"] == ["grype", "trivy"]


def test_priority_policy():
    base = {"cvss": 5.0, "epss": 0.0, "kev": False}
    assert priority({**base, "kev": True}) == "P0"
    assert priority({**base, "epss": 0.2}) == "P1"
    assert priority({**base, "cvss": 9.8, "epss": 0.02}) == "P1"
    assert priority({**base, "cvss": 9.8, "epss": 0.001}) == "P2"   # critical CVSS but nobody exploits it
    assert priority(base) == "P3"


def test_enrich_orders_kev_first():
    f = enrich(merge(from_trivy(TRIVY) + from_zap(ZAP)), KEV, EPSS)
    assert f[0]["priority"] == "P0" and f[0]["kev_ransomware"] and f[0]["risk_score"] > f[1]["risk_score"]


def test_sla_breach_fix_and_mttr():
    f = enrich(merge(from_trivy(TRIVY) + from_zap(ZAP)), KEV, EPSS)
    state = {}
    apply_sla(f, state, date(2026, 10, 1))
    s = apply_sla(f, state, date(2026, 10, 10))           # P0 = 7 days -> breached
    assert f[0]["sla_status"] == "BREACHED" and s["breached"] == 1
    s = apply_sla(f[1:], state, date(2026, 10, 12))       # log4j gone -> fixed after 11 days
    assert s["fixed_total"] == 1 and s["mttr_days"] == 11.0


def test_dashboard_escapes_html():
    zap = json.loads(json.dumps(ZAP)); zap["site"][0]["alerts"][0]["alert"] = "<script>alert(1)</script>"
    f = enrich(from_zap(zap), KEV, EPSS); s = apply_sla(f, {}, date(2026, 10, 1))
    html = render(f, s, {}, {"kev_version": "t", "kev_count": 1, "epss_date": None}, "now")
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


def test_cli_offline_on_real_scans(tmp_path):
    cli.main(["--trivy", str(ROOT / "scans/trivy.json"), "--grype", str(ROOT / "scans/grype.json"), "--zap", str(ROOT / "scans/zap.json"),
              "-o", str(tmp_path), "--feeds", str(ROOT / "feeds"), "--state", str(tmp_path / "s.json"), "--offline", "--today", "2026-10-11"])
    m = json.loads((tmp_path / "metrics.json").read_text())
    assert m["kev_total"] >= 1 and m["kev_in_top_risk_based"] == m["kev_total"]
    assert (tmp_path / "dashboard.html").exists()
