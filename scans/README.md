# Raw scanner outputs (real runs on the box, 2026-10-11 IST)

| File | Command | Tool version |
|---|---|---|
| `trivy.json` | `trivy fs --scanners vuln --format json -o scans/trivy.json sample-app` | Trivy 0.75.0 |
| `grype.json` | `grype dir:sample-app -o json --file scans/grype.json` | Grype 0.120.1 |
| `zap.json` | `zap.sh -cmd -port 8099 -quickurl http://127.0.0.1:8088/ -quickout scans/zap.json` against `python3 sample-app/server.py` on localhost | ZAP 2.16.1 (Temurin JRE 17) |
| `trivy_v2.json`, `grype_v2.json` | same, on `sample-app-v2/` (log4j 2.17.1, spring-beans 5.3.18, lodash 4.17.21, minimist 1.2.6): the "after patching" scan | same |

The sample apps are **intentionally outdated lab targets**. Never deploy them.
