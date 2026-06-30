from __future__ import annotations

import csv
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from app import connectors, storage
from app.scoring import score_asset

BASE_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = BASE_DIR / "static"


class ReconHandler(BaseHTTPRequestHandler):
    server_version = "ReconCodex/0.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.serve_static("index.html")
            return
        if parsed.path.startswith("/static/"):
            self.serve_static(parsed.path.removeprefix("/static/"))
            return
        if parsed.path.startswith("/api/"):
            self.handle_api_get(parsed.path, parse_qs(parsed.query))
            return
        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self.send_error(404, "Not found")
            return
        try:
            self.handle_api_post(parsed.path, self.read_body())
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:  # pragma: no cover - final guard for the interactive app.
            self.send_json({"error": str(exc)}, status=500)

    def handle_api_get(self, path: str, query: dict[str, list[str]]) -> None:
        organization_id = optional_int(query.get("organization_id", [None])[0])
        if path == "/api/summary":
            self.send_json(storage.dashboard_summary(organization_id))
        elif path == "/api/organizations":
            self.send_json({"organizations": storage.list_organizations()})
        elif path == "/api/business-units":
            self.send_json({"business_units": storage.list_business_units(organization_id)})
        elif path == "/api/assets":
            self.send_json({"assets": storage.list_assets(organization_id)})
        elif path == "/api/findings":
            asset_id = optional_int(query.get("asset_id", [None])[0])
            self.send_json({"findings": storage.list_findings(organization_id, asset_id)})
        elif path == "/api/connectors":
            self.send_json({"connectors": connectors.connector_status()})
        elif path == "/api/scan-runs":
            self.send_json({"scan_runs": storage.list_scan_runs(organization_id)})
        else:
            self.send_error(404, "Unknown API route")

    def handle_api_post(self, path: str, payload: Any) -> None:
        if path == "/api/organizations":
            self.send_json(storage.create_organization(payload["name"], payload.get("notes")), status=201)
        elif path == "/api/business-units":
            self.send_json(
                storage.create_business_unit(
                    int(payload.get("organization_id", 1)),
                    payload["name"],
                    payload.get("criticality", "medium"),
                    payload.get("priority", "P3"),
                    payload.get("tags") or [],
                    payload.get("notes"),
                ),
                status=201,
            )
        elif path == "/api/assets":
            asset = normalize_asset_payload(payload)
            saved = storage.upsert_asset(asset)
            self.recalculate_asset(saved["id"])
            self.send_json(storage.get_asset(saved["id"]), status=201)
        elif path == "/api/import/json":
            assets = payload.get("assets")
            if not isinstance(assets, list):
                raise ValueError("Expected JSON body with an 'assets' array.")
            saved = [storage.upsert_asset(normalize_asset_payload(asset)) for asset in assets]
            for asset in saved:
                self.recalculate_asset(asset["id"])
            self.send_json({"imported": len(saved), "assets": saved}, status=201)
        elif path == "/api/import/csv":
            csv_text = payload.get("csv", "")
            saved = import_csv(csv_text)
            for asset in saved:
                self.recalculate_asset(asset["id"])
            self.send_json({"imported": len(saved), "assets": saved}, status=201)
        elif path == "/api/discover":
            self.send_json(run_discovery(payload), status=201)
        elif path == "/api/vuln-check":
            self.send_json(run_vuln_check(int(payload.get("organization_id", 1))), status=201)
        elif path == "/api/recalculate":
            self.send_json(recalculate_all(int(payload.get("organization_id", 1))), status=201)
        elif path == "/api/daily-monitor":
            self.send_json(run_daily_monitor(int(payload.get("organization_id", 1))), status=201)
        else:
            self.send_error(404, "Unknown API route")

    def recalculate_asset(self, asset_id: int) -> dict[str, Any] | None:
        asset = storage.get_asset(asset_id)
        if not asset:
            return None
        findings = storage.list_findings(asset_id=asset_id)
        scored = score_asset(asset, findings)
        return storage.update_asset_risk(
            asset_id,
            scored["risk_score"],
            scored["suggested_priority"],
            scored["recommendation"],
        )

    def read_body(self) -> Any:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        if not body.strip():
            return {}
        return json.loads(body)

    def serve_static(self, relative_path: str) -> None:
        target = (STATIC_DIR / relative_path).resolve()
        if STATIC_DIR.resolve() not in target.parents and target != STATIC_DIR.resolve():
            self.send_error(403, "Forbidden")
            return
        if not target.exists() or not target.is_file():
            self.send_error(404, "Not found")
            return
        mime_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        content = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, payload: Any, status: int = 200) -> None:
        content = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}")


def optional_int(value: str | None) -> int | None:
    return int(value) if value not in (None, "") else None


def normalize_asset_payload(payload: dict[str, Any]) -> dict[str, Any]:
    allowed_types = {"domain", "subdomain", "ip", "url", "email", "mobile_app", "software_service"}
    asset_type = payload.get("asset_type")
    if asset_type not in allowed_types:
        raise ValueError(f"asset_type must be one of: {', '.join(sorted(allowed_types))}")
    value = str(payload.get("value") or "").strip()
    if not value:
        raise ValueError("value is required")
    tags = payload.get("tags") or []
    if isinstance(tags, str):
        tags = [tag.strip() for tag in tags.replace(";", ",").split(",") if tag.strip()]
    return {
        "organization_id": int(payload.get("organization_id") or 1),
        "business_unit_id": optional_int(str(payload.get("business_unit_id"))) if payload.get("business_unit_id") else None,
        "asset_type": asset_type,
        "value": value,
        "display_name": payload.get("display_name") or value,
        "owner": payload.get("owner"),
        "environment": payload.get("environment"),
        "criticality": payload.get("criticality", "medium"),
        "priority": payload.get("priority", "P3"),
        "tags": tags,
        "source": payload.get("source", "manual"),
        "confidence": float(payload.get("confidence", 1.0)),
        "status": payload.get("status", "active"),
        "notes": payload.get("notes"),
        "software_name": payload.get("software_name"),
        "software_version": payload.get("software_version"),
        "exposed": truthy(payload.get("exposed", False)),
    }


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "exposed"}


def import_csv(csv_text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(csv_text.splitlines())
    saved: list[dict[str, Any]] = []
    for row in reader:
        if not row.get("asset_type") or not row.get("value"):
            continue
        saved.append(storage.upsert_asset(normalize_asset_payload(row)))
    return saved


def run_discovery(payload: dict[str, Any]) -> dict[str, Any]:
    organization_id = int(payload.get("organization_id") or 1)
    domains = payload.get("domains") or []
    if isinstance(domains, str):
        domains = [item.strip() for item in domains.replace("\n", ",").split(",") if item.strip()]
    scan_run_id = storage.create_scan_run(organization_id, "passive_discovery", "Heuristic discovery run")
    discovered: list[dict[str, Any]] = []
    for domain in domains:
        for candidate in connectors.heuristic_discovery(domain):
            candidate["organization_id"] = organization_id
            saved = storage.upsert_asset(candidate)
            discovered.append(saved)
    for asset in discovered:
        recalculate_asset_by_id(asset["id"])
    summary = {"domains": domains, "discovered": len(discovered)}
    storage.finish_scan_run(scan_run_id, "completed", summary)
    return {"scan_run_id": scan_run_id, **summary, "assets": discovered}


def run_vuln_check(organization_id: int) -> dict[str, Any]:
    scan_run_id = storage.create_scan_run(organization_id, "vulnerability_enrichment", "Local version matching")
    assets = storage.list_assets(organization_id)
    created = 0
    for asset in assets:
        matches = connectors.match_local_vulnerabilities(asset.get("software_name"), asset.get("software_version"))
        for match in matches:
            match["asset_id"] = asset["id"]
            match["source"] = "local_vuln_rules"
            storage.upsert_finding(match)
            created += 1
        recalculate_asset_by_id(asset["id"])
    summary = {"assets_checked": len(assets), "findings_created_or_updated": created}
    storage.finish_scan_run(scan_run_id, "completed", summary)
    return {"scan_run_id": scan_run_id, **summary}


def recalculate_all(organization_id: int) -> dict[str, Any]:
    assets = storage.list_assets(organization_id)
    for asset in assets:
        recalculate_asset_by_id(asset["id"])
    return {"recalculated": len(assets)}


def run_daily_monitor(organization_id: int) -> dict[str, Any]:
    scan_run_id = storage.create_scan_run(organization_id, "daily_monitor", "Daily exposure and vuln reassessment")
    vuln_summary = run_vuln_check(organization_id)
    recalc_summary = recalculate_all(organization_id)
    summary = {"vulnerability": vuln_summary, "risk": recalc_summary}
    storage.finish_scan_run(scan_run_id, "completed", summary)
    return {"scan_run_id": scan_run_id, "summary": summary}


def recalculate_asset_by_id(asset_id: int) -> dict[str, Any] | None:
    asset = storage.get_asset(asset_id)
    if not asset:
        return None
    findings = storage.list_findings(asset_id=asset_id)
    scored = score_asset(asset, findings)
    return storage.update_asset_risk(asset_id, scored["risk_score"], scored["suggested_priority"], scored["recommendation"])


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    storage.initialize()
    server = ThreadingHTTPServer((host, port), ReconHandler)
    print(f"Recon-Codex running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
