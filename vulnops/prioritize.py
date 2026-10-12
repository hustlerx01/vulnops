"""Risk-based priority (CVSS + EPSS + KEV) and SLA tracking.

Priority policy (mine; loosely follows CISA BOD 22-01 + FIRST EPSS guidance):
  P0  in CISA KEV                                   -> fix in 7 days (or KEV dueDate-style urgency)
  P1  EPSS >= 0.10, or CVSS >= 9.0 with EPSS >= 0.01 -> 15 days
  P2  CVSS >= 7.0                                   -> 30 days
  P3  everything else (incl. INFO web findings)     -> 90 days
risk_score (0-100) for ordering inside a bucket = 40*KEV + 40*EPSS + 2*CVSS.
"""
from __future__ import annotations
from datetime import date, timedelta

SLA_DAYS = {"P0": 7, "P1": 15, "P2": 30, "P3": 90}


def priority(f: dict) -> str:
    e = f.get("epss") or 0.0
    if f.get("kev"):
        return "P0"
    if e >= 0.10 or (f["cvss"] >= 9.0 and e >= 0.01):
        return "P1"
    if f["cvss"] >= 7.0:
        return "P2"
    return "P3"


def enrich(findings: list[dict], kev: dict, epss: dict) -> list[dict]:
    for f in findings:
        e = epss.get(f["cve"], {}) if f["cve"] else {}
        f["epss"], f["epss_percentile"] = e.get("epss"), e.get("percentile")
        k = kev["by_cve"].get(f["cve"])
        f["kev"] = bool(k)
        f["kev_ransomware"] = (k or {}).get("knownRansomwareCampaignUse") == "Known"
        f["kev_date_added"] = (k or {}).get("dateAdded")
        f["priority"] = priority(f)
        f["risk_score"] = round(40 * f["kev"] + 40 * (f["epss"] or 0) + 2 * f["cvss"], 1)
    return sorted(findings, key=lambda f: (f["priority"], -f["risk_score"]))


def apply_sla(findings: list[dict], state: dict, today: date) -> dict:
    """state: {finding_id: {"first_seen": iso, "status": open|fixed}}; updated in place. Returns summary."""
    current = {f["id"] for f in findings}
    for fid, s in state.items():
        if fid not in current and s["status"] == "open":
            s["status"], s["fixed_on"] = "fixed", today.isoformat()
    for f in findings:
        s = state.setdefault(f["id"], {"first_seen": today.isoformat(), "status": "open"})
        if s["status"] == "fixed":  # regression: re-opened
            s.update(status="open", first_seen=today.isoformat(), reopened=True)
        first = date.fromisoformat(s["first_seen"])
        due = first + timedelta(days=SLA_DAYS[f["priority"]])
        f["first_seen"], f["due"] = s["first_seen"], due.isoformat()
        f["age_days"] = (today - first).days
        f["days_left"] = (due - today).days
        f["sla_status"] = "BREACHED" if f["days_left"] < 0 else "DUE_SOON" if f["days_left"] <= 3 else "OK"
    fixed = [s for s in state.values() if s["status"] == "fixed" and s.get("fixed_on")]
    mttr = (sum((date.fromisoformat(s["fixed_on"]) - date.fromisoformat(s["first_seen"])).days for s in fixed) / len(fixed)) if fixed else None
    return {"open": len(findings), "breached": sum(f["sla_status"] == "BREACHED" for f in findings),
            "due_soon": sum(f["sla_status"] == "DUE_SOON" for f in findings), "fixed_total": len(fixed),
            "mttr_days": round(mttr, 1) if mttr is not None else None}
