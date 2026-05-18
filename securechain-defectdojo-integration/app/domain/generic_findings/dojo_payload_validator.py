from __future__ import annotations

from typing import Any, Dict, List

from app.exceptions.defectdojo_exceptions import InvalidGenericFindingsPayload


REQUIRED_FINDING_FIELDS = ("title", "severity", "description")
FORBIDDEN_FINDING_FIELDS = ("duplicate",)


def validate_dojo_generic_findings_payload(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise InvalidGenericFindingsPayload("payload must be an object")

    findings = payload.get("findings")

    if findings is None:
        raise InvalidGenericFindingsPayload("payload must contain 'findings'")

    if not isinstance(findings, list):
        raise InvalidGenericFindingsPayload("'findings' must be a list")

    for index, finding in enumerate(findings):
        _validate_finding(index=index, finding=finding)


def _validate_finding(index: int, finding: Any) -> None:
    if not isinstance(finding, dict):
        raise InvalidGenericFindingsPayload(
            f"finding at index {index} must be an object"
        )

    for forbidden_field in FORBIDDEN_FINDING_FIELDS:
        if forbidden_field in finding:
            raise InvalidGenericFindingsPayload(
                f"finding at index {index} contains forbidden field '{forbidden_field}'"
            )

    for required_field in REQUIRED_FINDING_FIELDS:
        value = finding.get(required_field)
        if not isinstance(value, str) or not value.strip():
            raise InvalidGenericFindingsPayload(
                f"finding at index {index} must contain non-empty '{required_field}'"
            )

def sanitize_dojo_generic_findings_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    findings = payload.get("findings", [])

    if not isinstance(findings, list):
        return payload

    sanitized_findings: List[Dict[str, Any]] = []

    for finding in findings:
        if not isinstance(finding, dict):
            sanitized_findings.append(finding)
            continue

        clean = dict(finding)

        # DefectDojo Generic Findings espera "mitigated" como fecha/string.
        # Si recibe bool, rompe con:
        # TypeError: Parser must be a string or character stream, not bool
        if isinstance(clean.get("mitigated"), bool):
            clean.pop("mitigated", None)

        # Campo prohibido en tu instancia Dojo.
        clean.pop("duplicate", None)

        severity = clean.get("severity")
        if isinstance(severity, str):
            severity_map = {
                "INFO": "info",
                "LOW": "Low",
                "MEDIUM": "Medium",
                "HIGH": "High",
                "CRITICAL": "Critical",
            }
            clean["severity"] = severity_map.get(
                severity.strip().upper(),
                severity.strip(),
            )

        sanitized_findings.append(clean)

    return {"findings": sanitized_findings}  
