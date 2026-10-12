"""Turn scanner-specific JSON into one Finding schema."""
from __future__ import annotations
import hashlib, re

SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "moderate": "MEDIUM", "low": "LOW",
       "negligible": "LOW", "informational": "INFO", "info": "INFO", "unknown": "UNKNOWN"}
# ZAP has no CVSS; map its riskcode to a representative score (documented assumption, see README)
ZAP_RISK = {"3": ("HIGH", 7.5), "2": ("MEDIUM", 5.0), "1": ("LOW", 3.0), "0": ("INFO", 0.0)}
SEV_DEFAULT_CVSS = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 0.0, "UNKNOWN": 5.0}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _fid(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:12]


def _f(tool, vuln_id, cve, pkg, ver, fixed, sev, cvss, title, location, kind="dependency"):
    sev = SEV.get(str(sev).lower(), "UNKNOWN")
    pkg_key = pkg.split(":")[-1].lower().replace("_", "-")  # trivy 'g:a' vs grype 'a' for Maven
    return {"id": _fid(cve or vuln_id, pkg_key, ver, location if kind == "web" else ""), "tools": [tool], "vuln_id": vuln_id,
            "cve": cve, "package": pkg, "version": ver, "fixed_version": fixed or "", "severity": sev,
            "cvss": cvss if cvss is not None else SEV_DEFAULT_CVSS[sev], "cvss_source": "scanner" if cvss is not None else "severity-default",
            "title": (title or "")[:160], "location": location, "kind": kind}


def from_trivy(doc: dict) -> list[dict]:
    out = []
    for res in doc.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            scores = [c.get("V3Score") for src in ("nvd", "ghsa", "redhat") for c in [v.get("CVSS", {}).get(src, {})] if c.get("V3Score")]
            vid = v["VulnerabilityID"]
            cve = vid if vid.startswith("CVE-") else next((x for x in v.get("VendorIDs", []) if x.startswith("CVE-")), "")
            out.append(_f("trivy", vid, cve, v["PkgName"], v["InstalledVersion"], v.get("FixedVersion"), v.get("Severity", "unknown"),
                          scores[0] if scores else None, v.get("Title") or vid, res.get("Target", "")))
    return out


def from_grype(doc: dict) -> list[dict]:
    out = []
    for m in doc.get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        rel = m.get("relatedVulnerabilities", []) or []
        cve = v["id"] if v["id"].startswith("CVE-") else next((r["id"] for r in rel if r["id"].startswith("CVE-")), "")
        scores = [c.get("metrics", {}).get("baseScore") for c in (v.get("cvss") or []) + [c for r in rel for c in (r.get("cvss") or [])]
                  if str(c.get("version", "3")).startswith("3")]
        scores = [s for s in scores if s]
        loc = (a.get("locations") or [{}])[0].get("path", "").lstrip("/")
        out.append(_f("grype", v["id"], cve, a["name"], a["version"], ",".join(v.get("fix", {}).get("versions", [])),
                      v.get("severity", "unknown"), max(scores) if scores else None, (rel[0].get("description") if rel else v.get("description")) or v["id"], loc))
    return out


def from_zap(doc: dict) -> list[dict]:
    out = []
    for site in doc.get("site", []):
        for al in site.get("alerts", []):
            sev, cvss = ZAP_RISK.get(str(al.get("riskcode")), ("UNKNOWN", 5.0))
            cve = (CVE_RE.findall(al.get("reference", "") + al.get("otherinfo", "")) or [""])[0]
            urls = sorted({i.get("uri", "") for i in al.get("instances", [])})
            f = _f("zap", f"ZAP-{al.get('pluginid')}", cve, site.get("@name", ""), "", "", sev, cvss, al.get("alert") or al.get("name"),
                   urls[0] if urls else site.get("@name", ""), kind="web")
            f["cvss_source"] = "zap-riskcode-map"; f["cwe"] = al.get("cweid"); f["instances"] = len(urls)
            out.append(f)
    return out


def merge(findings: list[dict]) -> list[dict]:
    """Dedup across tools on (CVE or vuln id, package, version); keep the highest CVSS, union the tools."""
    by = {}
    for f in findings:
        k = f["id"]
        if k in by:
            g = by[k]
            g["tools"] = sorted(set(g["tools"]) | set(f["tools"]))
            if f["cvss_source"] == "scanner" and (g["cvss_source"] != "scanner" or f["cvss"] > g["cvss"]):
                g["cvss"], g["cvss_source"] = f["cvss"], "scanner"
            g["fixed_version"] = g["fixed_version"] or f["fixed_version"]
        else:
            by[k] = dict(f)
    return list(by.values())
