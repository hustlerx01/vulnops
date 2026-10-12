"""Real public threat feeds with on-disk cache:
- CISA KEV  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- FIRST EPSS https://api.first.org/data/v1/epss?cve=...
Offline mode uses the cache only (CI and tests never hit the network)."""
from __future__ import annotations
import json, time
from pathlib import Path
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
UA = {"User-Agent": "vulnops-lab/0.1 (portfolio project)"}


def _get(url: str, timeout=60) -> bytes:
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()


def load_kev(cache_dir: Path, offline=False, max_age_h=24) -> dict:
    p = Path(cache_dir) / "kev.json"
    if not offline and (not p.exists() or time.time() - p.stat().st_mtime > max_age_h * 3600):
        p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(_get(KEV_URL))
    doc = json.loads(p.read_text())
    return {"catalogVersion": doc.get("catalogVersion"), "count": doc.get("count"),
            "by_cve": {v["cveID"]: v for v in doc["vulnerabilities"]}}


def load_epss(cves: list[str], cache_dir: Path, offline=False, batch=50) -> dict:
    p = Path(cache_dir) / "epss.json"
    cache = json.loads(p.read_text()) if p.exists() else {}
    missing = sorted({c for c in cves if c and c not in cache})
    if not offline:
        for i in range(0, len(missing), batch):
            doc = json.loads(_get(EPSS_URL + ",".join(missing[i:i + batch])))
            for row in doc.get("data", []):
                cache[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row["date"]}
            for c in missing[i:i + batch]:
                cache.setdefault(c, {"epss": None, "percentile": None, "date": None})  # not scored by FIRST
        p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(cache, indent=1, sort_keys=True))
    return cache
