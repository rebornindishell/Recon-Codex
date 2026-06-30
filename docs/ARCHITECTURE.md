# Recon-Codex Architecture

## Core idea
Recon-Codex keeps one normalized inventory and enriches it with tool output over time.

Manual entries are authoritative. Automated discovery, exposure checks, and vulnerability enrichment add confidence, evidence, findings, and recommendations.

## Modules
- `app/main.py`: HTTP server, API routes, and orchestration entry points
- `app/storage.py`: SQLite schema, persistence, imports, scan runs, and dashboard summaries
- `app/scoring.py`: criticality, exposure, severity, KEV, and EPSS based priority logic
- `app/connectors.py`: integration boundary for local tools and external APIs
- `static/`: browser dashboard

## Asset flow
1. User manually enters or imports inventory.
2. Discovery adds candidate assets.
3. Exposure and software fields are updated by connectors.
4. Vulnerability enrichment creates findings.
5. Risk scoring updates recommended priority and remediation guidance.
6. Daily monitoring repeats exposure and vuln checks.

## Connector plan
- `subfinder`: passive subdomain discovery
- `crt.sh`: certificate transparency subdomains
- `dnsx`: DNS confirmation and IP mapping
- `httpx`: live web confirmation and basic fingerprints
- `Shodan`: exposed services, banners, CPEs, and vulnerability hints
- `SecurityTrails`: DNS and historical enrichment
- `NVD`: CVE lookup by CPE or product/version
- `CISA KEV`: active exploitation prioritization
- `EPSS`: exploit probability scoring
- `DeHashed`: leaked credential exposure signals
- `RocketReach` and LinkedIn tooling: employee/email enrichment

## Risk priority
Priority is calculated from:
- business criticality
- internet exposure
- detected software/version
- vulnerability severity
- CISA KEV status
- EPSS probability

The app stores both human-entered priority and suggested priority so analysts can override the recommendation without losing the system's view.
