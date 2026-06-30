# Recon-Codex

Recon-Codex is an internal asset inventory, exposure, and vulnerability monitoring app for authorized organizational use.

## What it does
- Manual inventory for IPs, subdomains, URLs, emails, mobile apps, and software services
- Bulk JSON import
- Organization and business-unit tracking
- Criticality, priority, tags, owner, environment, and notes
- Passive discovery stubs for subdomains and web exposure
- Vulnerability enrichment hooks for NVD, CISA KEV, EPSS, Shodan, SecurityTrails, DeHashed, RocketReach, LinkedIn, and crt.sh
- Daily monitoring loop and change history

## Stack
- Python standard library backend
- SQLite for persistence
- Vanilla HTML/CSS/JS frontend

## Run
```bash
python -m app.main
```

Then open:
```text
http://127.0.0.1:8000
```

## Notes
- Manual inventory is the source of truth.
- Discovery enriches and verifies that inventory over time.
- Findings always keep evidence and confidence.
- External integrations are designed as connectors, so you can turn them on as you get API keys or local tools.
