from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class ConnectorStatus:
    name: str
    configured: bool
    details: str


def connector_status() -> list[dict[str, Any]]:
    return [
        _status("subfinder", False, "CLI connector stub ready"),
        _status("crt.sh", True, "Passive certificate transparency source"),
        _status("shodan", bool(os.getenv("SHODAN_API_KEY")), "API key required"),
        _status("securitytrails", bool(os.getenv("SECURITYTRAILS_API_KEY")), "API key required"),
        _status("nvd", bool(os.getenv("NVD_API_KEY") or True), "API available without key but rate-limited"),
        _status("epss", True, "Public EPSS feed/API"),
        _status("dehashed", bool(os.getenv("DEHASHED_USERNAME") and os.getenv("DEHASHED_API_KEY")), "Credentials required"),
        _status("rocketreach", bool(os.getenv("ROCKETREACH_API_KEY")), "API key required"),
        _status("linkedin_tool", bool(os.getenv("LINKEDIN_TOOL_ENABLED")), "Optional local tool integration"),
    ]


def _status(name: str, configured: bool, details: str) -> dict[str, Any]:
    return ConnectorStatus(name=name, configured=configured, details=details).__dict__


def heuristic_discovery(domain: str) -> list[dict[str, Any]]:
    domain = domain.strip().lower()
    prefixes = ["www", "api", "mail", "portal", "admin", "vpn", "dev", "staging"]
    results: list[dict[str, Any]] = []
    for prefix in prefixes:
        host = f"{prefix}.{domain}"
        results.append(
            {
                "asset_type": "subdomain",
                "value": host,
                "display_name": host,
                "source": "heuristic_discovery",
                "confidence": 0.35,
                "exposed": True,
                "notes": "Generated from a standard business exposure pattern. Validate with passive sources.",
            }
        )
        results.append(
            {
                "asset_type": "url",
                "value": f"https://{host}",
                "display_name": f"https://{host}",
                "source": "heuristic_discovery",
                "confidence": 0.3,
                "exposed": True,
                "notes": "Generated URL candidate from the discovered host pattern.",
            }
        )
    return results


def extract_hostname(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname
    return value.split("/")[0]


LOCAL_VULN_RULES = [
    {
        "software_name": "OpenSSH",
        "version_prefix": "8.7",
        "severity": "high",
        "summary": "OpenSSH version is in a sensitive range and should be checked against vendor advisories.",
        "recommendation": "Upgrade OpenSSH to the latest supported vendor release and confirm the fix in official advisories.",
    },
    {
        "software_name": "nginx",
        "version_prefix": "1.18",
        "severity": "medium",
        "summary": "nginx version is old enough to warrant validation against the supported release line.",
        "recommendation": "Upgrade nginx to a supported stable release and review the vendor changelog.",
    },
    {
        "software_name": "Apache httpd",
        "version_prefix": "2.4",
        "severity": "medium",
        "summary": "Apache httpd 2.4.x should be checked against your patch baseline.",
        "recommendation": "Upgrade Apache httpd to your approved supported release and verify modules in use.",
    },
    {
        "software_name": "Microsoft IIS",
        "version_prefix": "10.",
        "severity": "medium",
        "summary": "IIS version should be reviewed against Microsoft security guidance.",
        "recommendation": "Apply the latest Windows Server security updates and validate IIS hardening.",
    },
]


def version_matches_prefix(version: str, prefix: str) -> bool:
    cleaned_version = version.strip().lower()
    cleaned_prefix = prefix.strip().lower()
    return cleaned_version.startswith(cleaned_prefix)


def match_local_vulnerabilities(software_name: str | None, version: str | None) -> list[dict[str, Any]]:
    if not software_name or not version:
        return []
    matches: list[dict[str, Any]] = []
    for rule in LOCAL_VULN_RULES:
        if software_name.lower() == rule["software_name"].lower() and version_matches_prefix(version, rule["version_prefix"]):
            matches.append(
                {
                    "kind": "version_match",
                    "severity": rule["severity"],
                    "summary": rule["summary"],
                    "recommendation": rule["recommendation"],
                    "cve_id": None,
                    "cvss": 0.0,
                    "epss": 0.0,
                    "kev": False,
                    "confidence": 0.55,
                    "evidence": {"matched_rule": rule},
                }
            )
    return matches

