from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "recon.db"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    ensure_data_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize() -> None:
    ensure_data_dir()
    with connect() as conn:
        conn.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS business_units (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                criticality TEXT NOT NULL DEFAULT 'medium',
                priority TEXT NOT NULL DEFAULT 'P3',
                tags_json TEXT NOT NULL DEFAULT '[]',
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(organization_id, name),
                FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                business_unit_id INTEGER,
                asset_type TEXT NOT NULL,
                value TEXT NOT NULL,
                display_name TEXT,
                owner TEXT,
                environment TEXT,
                criticality TEXT NOT NULL DEFAULT 'medium',
                priority TEXT NOT NULL DEFAULT 'P3',
                tags_json TEXT NOT NULL DEFAULT '[]',
                source TEXT NOT NULL DEFAULT 'manual',
                confidence REAL NOT NULL DEFAULT 1.0,
                status TEXT NOT NULL DEFAULT 'active',
                notes TEXT,
                software_name TEXT,
                software_version TEXT,
                exposed INTEGER NOT NULL DEFAULT 0,
                risk_score INTEGER NOT NULL DEFAULT 0,
                suggested_priority TEXT NOT NULL DEFAULT 'P3',
                recommendation TEXT,
                last_scanned_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(organization_id, asset_type, value, source),
                FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                FOREIGN KEY (business_unit_id) REFERENCES business_units(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual',
                kind TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'medium',
                cve_id TEXT,
                cvss REAL NOT NULL DEFAULT 0.0,
                epss REAL NOT NULL DEFAULT 0.0,
                kev INTEGER NOT NULL DEFAULT 0,
                summary TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.8,
                evidence_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                note TEXT,
                summary_json TEXT NOT NULL DEFAULT '{}',
                started_at TEXT NOT NULL,
                finished_at TEXT,
                FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
            );
            """
        )
        seed_defaults(conn)


def seed_defaults(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()
    if row:
        return
    created_at = utc_now()
    conn.execute(
        "INSERT INTO organizations (name, notes, created_at, updated_at) VALUES (?, ?, ?, ?)",
        ("Primary Organization", "Seeded organization for Recon-Codex.", created_at, created_at),
    )
    organization_id = conn.execute("SELECT id FROM organizations WHERE name = ?", ("Primary Organization",)).fetchone()["id"]
    conn.execute(
        """
        INSERT INTO business_units (organization_id, name, criticality, priority, tags_json, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            organization_id,
            "Default",
            "medium",
            "P3",
            json.dumps(["seeded"]),
            "Default business unit.",
            created_at,
            created_at,
        ),
    )
    conn.commit()


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    for key in ("tags_json", "evidence_json", "summary_json"):
        if key in result and result[key]:
            try:
                result[key[:-5] if key.endswith("_json") else key] = json.loads(result.pop(key))
            except json.JSONDecodeError:
                result[key[:-5] if key.endswith("_json") else key] = []
    return normalize_row(result)


def normalize_row(data: dict[str, Any]) -> dict[str, Any]:
    if "tags_json" in data:
        data["tags"] = json.loads(data.pop("tags_json") or "[]")
    if "evidence_json" in data:
        data["evidence"] = json.loads(data.pop("evidence_json") or "{}")
    if "summary_json" in data:
        data["summary"] = json.loads(data.pop("summary_json") or "{}")
    for boolean_key in ("exposed", "kev"):
        if boolean_key in data:
            data[boolean_key] = bool(data[boolean_key])
    return data


def list_organizations() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM organizations ORDER BY name").fetchall()
    return [normalize_row(dict(row)) for row in rows]


def create_organization(name: str, notes: str | None = None) -> dict[str, Any]:
    stamp = utc_now()
    with connect() as conn:
        conn.execute(
            "INSERT INTO organizations (name, notes, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (name.strip(), notes, stamp, stamp),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM organizations WHERE name = ?", (name.strip(),)).fetchone()
    return normalize_row(dict(row))


def list_business_units(organization_id: int | None = None) -> list[dict[str, Any]]:
    with connect() as conn:
        if organization_id is None:
            rows = conn.execute("SELECT * FROM business_units ORDER BY name").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM business_units WHERE organization_id = ? ORDER BY name",
                (organization_id,),
            ).fetchall()
    return [normalize_row(dict(row)) for row in rows]


def create_business_unit(
    organization_id: int,
    name: str,
    criticality: str = "medium",
    priority: str = "P3",
    tags: Iterable[str] | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    stamp = utc_now()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO business_units (organization_id, name, criticality, priority, tags_json, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (organization_id, name.strip(), criticality, priority, json.dumps(list(tags or [])), notes, stamp, stamp),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM business_units WHERE organization_id = ? AND name = ?",
            (organization_id, name.strip()),
        ).fetchone()
    return normalize_row(dict(row))


def list_assets(organization_id: int | None = None) -> list[dict[str, Any]]:
    with connect() as conn:
        if organization_id is None:
            rows = conn.execute("SELECT * FROM assets ORDER BY risk_score DESC, value").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM assets WHERE organization_id = ? ORDER BY risk_score DESC, value",
                (organization_id,),
            ).fetchall()
    return [normalize_row(dict(row)) for row in rows]


def get_asset(asset_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    return normalize_row(dict(row)) if row else None


def upsert_asset(asset: dict[str, Any]) -> dict[str, Any]:
    stamp = utc_now()
    payload = {
        "organization_id": int(asset.get("organization_id") or 1),
        "business_unit_id": asset.get("business_unit_id"),
        "asset_type": asset["asset_type"],
        "value": str(asset["value"]).strip(),
        "display_name": asset.get("display_name"),
        "owner": asset.get("owner"),
        "environment": asset.get("environment"),
        "criticality": asset.get("criticality", "medium"),
        "priority": asset.get("priority", "P3"),
        "tags_json": json.dumps(list(asset.get("tags") or [])),
        "source": asset.get("source", "manual"),
        "confidence": float(asset.get("confidence", 1.0)),
        "status": asset.get("status", "active"),
        "notes": asset.get("notes"),
        "software_name": asset.get("software_name"),
        "software_version": asset.get("software_version"),
        "exposed": 1 if asset.get("exposed") else 0,
        "risk_score": int(asset.get("risk_score", 0)),
        "suggested_priority": asset.get("suggested_priority", asset.get("priority", "P3")),
        "recommendation": asset.get("recommendation"),
        "last_scanned_at": asset.get("last_scanned_at"),
    }
    with connect() as conn:
        existing = conn.execute(
            """
            SELECT id FROM assets
            WHERE organization_id = ? AND asset_type = ? AND value = ? AND source = ?
            """,
            (payload["organization_id"], payload["asset_type"], payload["value"], payload["source"]),
        ).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE assets
                SET business_unit_id = ?, display_name = ?, owner = ?, environment = ?, criticality = ?, priority = ?,
                    tags_json = ?, confidence = ?, status = ?, notes = ?, software_name = ?, software_version = ?,
                    exposed = ?, risk_score = ?, suggested_priority = ?, recommendation = ?, last_scanned_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    payload["business_unit_id"],
                    payload["display_name"],
                    payload["owner"],
                    payload["environment"],
                    payload["criticality"],
                    payload["priority"],
                    payload["tags_json"],
                    payload["confidence"],
                    payload["status"],
                    payload["notes"],
                    payload["software_name"],
                    payload["software_version"],
                    payload["exposed"],
                    payload["risk_score"],
                    payload["suggested_priority"],
                    payload["recommendation"],
                    payload["last_scanned_at"],
                    stamp,
                    existing["id"],
                ),
            )
            asset_id = existing["id"]
        else:
            conn.execute(
                """
                INSERT INTO assets (
                    organization_id, business_unit_id, asset_type, value, display_name, owner, environment,
                    criticality, priority, tags_json, source, confidence, status, notes, software_name,
                    software_version, exposed, risk_score, suggested_priority, recommendation, last_scanned_at,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["organization_id"],
                    payload["business_unit_id"],
                    payload["asset_type"],
                    payload["value"],
                    payload["display_name"],
                    payload["owner"],
                    payload["environment"],
                    payload["criticality"],
                    payload["priority"],
                    payload["tags_json"],
                    payload["source"],
                    payload["confidence"],
                    payload["status"],
                    payload["notes"],
                    payload["software_name"],
                    payload["software_version"],
                    payload["exposed"],
                    payload["risk_score"],
                    payload["suggested_priority"],
                    payload["recommendation"],
                    payload["last_scanned_at"],
                    stamp,
                    stamp,
                ),
            )
            asset_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        conn.commit()
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    return normalize_row(dict(row))


def update_asset_risk(
    asset_id: int,
    risk_score: int,
    suggested_priority: str,
    recommendation: str,
    last_scanned_at: str | None = None,
) -> dict[str, Any]:
    stamp = utc_now()
    with connect() as conn:
        conn.execute(
            """
            UPDATE assets
            SET risk_score = ?, suggested_priority = ?, recommendation = ?, last_scanned_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (risk_score, suggested_priority, recommendation, last_scanned_at or stamp, stamp, asset_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    return normalize_row(dict(row))


def list_findings(organization_id: int | None = None, asset_id: int | None = None) -> list[dict[str, Any]]:
    query = [
        "SELECT findings.*, assets.organization_id AS organization_id FROM findings JOIN assets ON assets.id = findings.asset_id"
    ]
    params: list[Any] = []
    where: list[str] = []
    if organization_id is not None:
        where.append("assets.organization_id = ?")
        params.append(organization_id)
    if asset_id is not None:
        where.append("findings.asset_id = ?")
        params.append(asset_id)
    if where:
        query.append("WHERE " + " AND ".join(where))
    query.append("ORDER BY CASE findings.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, findings.updated_at DESC")
    with connect() as conn:
        rows = conn.execute(" ".join(query), params).fetchall()
    return [normalize_row(dict(row)) for row in rows]


def delete_findings_for_asset(asset_id: int, source: str | None = None) -> None:
    with connect() as conn:
        if source is None:
            conn.execute("DELETE FROM findings WHERE asset_id = ?", (asset_id,))
        else:
            conn.execute("DELETE FROM findings WHERE asset_id = ? AND source = ?", (asset_id, source))
        conn.commit()


def upsert_finding(finding: dict[str, Any]) -> dict[str, Any]:
    stamp = utc_now()
    payload = {
        "asset_id": int(finding["asset_id"]),
        "source": finding.get("source", "manual"),
        "kind": finding["kind"],
        "severity": finding.get("severity", "medium"),
        "cve_id": finding.get("cve_id"),
        "cvss": float(finding.get("cvss", 0.0)),
        "epss": float(finding.get("epss", 0.0)),
        "kev": 1 if finding.get("kev") else 0,
        "summary": finding["summary"],
        "recommendation": finding["recommendation"],
        "confidence": float(finding.get("confidence", 0.8)),
        "evidence_json": json.dumps(finding.get("evidence") or {}),
        "status": finding.get("status", "open"),
    }
    with connect() as conn:
        row = conn.execute(
            """
            SELECT id FROM findings
            WHERE asset_id = ? AND source = ? AND kind = ? AND COALESCE(cve_id, '') = COALESCE(?, '') AND summary = ?
            """,
            (payload["asset_id"], payload["source"], payload["kind"], payload["cve_id"], payload["summary"]),
        ).fetchone()
        if row:
            conn.execute(
                """
                UPDATE findings
                SET severity = ?, cvss = ?, epss = ?, kev = ?, recommendation = ?, confidence = ?, evidence_json = ?, status = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    payload["severity"],
                    payload["cvss"],
                    payload["epss"],
                    payload["kev"],
                    payload["recommendation"],
                    payload["confidence"],
                    payload["evidence_json"],
                    payload["status"],
                    stamp,
                    row["id"],
                ),
            )
            finding_id = row["id"]
        else:
            conn.execute(
                """
                INSERT INTO findings (
                    asset_id, source, kind, severity, cve_id, cvss, epss, kev, summary, recommendation,
                    confidence, evidence_json, status, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["asset_id"],
                    payload["source"],
                    payload["kind"],
                    payload["severity"],
                    payload["cve_id"],
                    payload["cvss"],
                    payload["epss"],
                    payload["kev"],
                    payload["summary"],
                    payload["recommendation"],
                    payload["confidence"],
                    payload["evidence_json"],
                    payload["status"],
                    stamp,
                    stamp,
                ),
            )
            finding_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        conn.commit()
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return normalize_row(dict(row))


def create_scan_run(organization_id: int, kind: str, note: str | None = None) -> int:
    stamp = utc_now()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_runs (organization_id, kind, status, note, summary_json, started_at)
            VALUES (?, ?, 'running', ?, ?, ?)
            """,
            (organization_id, kind, note, json.dumps({}), stamp),
        )
        run_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        conn.commit()
    return run_id


def finish_scan_run(scan_run_id: int, status: str, summary: dict[str, Any]) -> None:
    stamp = utc_now()
    with connect() as conn:
        conn.execute(
            "UPDATE scan_runs SET status = ?, summary_json = ?, finished_at = ? WHERE id = ?",
            (status, json.dumps(summary), stamp, scan_run_id),
        )
        conn.commit()


def list_scan_runs(organization_id: int | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM scan_runs"
    params: list[Any] = []
    if organization_id is not None:
        query += " WHERE organization_id = ?"
        params.append(organization_id)
    query += " ORDER BY started_at DESC"
    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [normalize_row(dict(row)) for row in rows]


def dashboard_summary(organization_id: int | None = None) -> dict[str, Any]:
    assets = list_assets(organization_id)
    findings = list_findings(organization_id)
    by_type: dict[str, int] = {}
    for asset in assets:
        by_type[asset["asset_type"]] = by_type.get(asset["asset_type"], 0) + 1
    return {
        "asset_count": len(assets),
        "finding_count": len(findings),
        "critical_count": sum(1 for asset in assets if asset.get("criticality") == "critical"),
        "exposed_count": sum(1 for asset in assets if asset.get("exposed")),
        "assets_by_type": by_type,
        "top_findings": findings[:10],
        "recent_assets": assets[:10],
        "organizations": list_organizations(),
    }

