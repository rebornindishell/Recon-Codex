from __future__ import annotations

from typing import Any, Mapping, Sequence

CRITICALITY_SCORE = {"low": 10, "medium": 25, "high": 45, "critical": 70}
SEVERITY_SCORE = {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 45}


def clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


def priority_from_score(score: int) -> str:
    if score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 35:
        return "P3"
    return "P4"


def severity_to_priority(severity: str) -> str:
    severity = severity.lower()
    if severity == "critical":
        return "P1"
    if severity == "high":
        return "P2"
    if severity == "medium":
        return "P3"
    return "P4"


def score_asset(asset: Mapping[str, Any], findings: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    findings = findings or []
    score = CRITICALITY_SCORE.get(str(asset.get("criticality", "medium")), 25)

    if asset.get("exposed"):
        score += 15
    if asset.get("source") != "manual":
        score += 5
    if asset.get("software_name"):
        score += 5
    if asset.get("software_version"):
        score += 5

    strongest_priority = "P4"
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        score += SEVERITY_SCORE.get(severity, 0)
        if finding.get("kev"):
            score += 20
        epss = float(finding.get("epss") or 0.0)
        if epss >= 0.7:
            score += 15
        elif epss >= 0.4:
            score += 8
        finding_priority = severity_to_priority(severity)
        strongest_priority = min_priority(strongest_priority, finding_priority)

    score = clamp(score)
    suggested_priority = min_priority(priority_from_score(score), strongest_priority)
    recommendation = build_recommendation(asset, findings, score)
    return {"risk_score": score, "suggested_priority": suggested_priority, "recommendation": recommendation}


def min_priority(left: str, right: str) -> str:
    order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
    return left if order[left] < order[right] else right


def build_recommendation(asset: Mapping[str, Any], findings: Sequence[Mapping[str, Any]], score: int) -> str:
    if findings:
        top = sorted(findings, key=lambda item: SEVERITY_SCORE.get(str(item.get("severity", "info")).lower(), 0), reverse=True)[0]
        recommendation = str(top.get("recommendation") or "Investigate the highest severity finding and verify vendor guidance.")
        if top.get("kev"):
            recommendation += " Prioritize this asset because the CVE is in CISA KEV."
        return recommendation

    software = " ".join(filter(None, [str(asset.get("software_name") or ""), str(asset.get("software_version") or "")])).strip()
    if software:
        return f"Verify the installed version of {software} against vendor advisories and patch to the latest supported release."
    if asset.get("exposed"):
        return "Review whether this exposure is necessary and reduce the attack surface if possible."
    if score >= 60:
        return "Validate ownership, exposure, and patch status, then schedule remediation."
    return "Keep the asset inventoried and recheck it on the daily monitoring cycle."
