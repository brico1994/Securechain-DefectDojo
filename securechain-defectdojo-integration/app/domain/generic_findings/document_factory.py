from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.schemas.generic_findings.generic_findings_schemas import GenericFindingsDocument


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_findings_list(findings: Any) -> List[Dict[str, Any]]:
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")

    normalized: List[Dict[str, Any]] = []
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            raise ValueError(f"finding at index {index} must be an object")
        normalized.append(item)

    return normalized


def build_repository_id(
    repository_id: Optional[str] = None,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
) -> str:
    if repository_id:
        return repository_id

    owner_value = (owner or "").strip()
    repo_value = (repo or "").strip()

    if owner_value and repo_value:
        return f"{owner_value}/{repo_value}"
    if repo_value:
        return repo_value

    return "unknown"


def build_generic_findings_document(
    findings: List[Dict[str, Any]],
    repository_id: Optional[str] = None,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    sbom_name: Optional[str] = None,
    document_id: Optional[str] = None,
    created_at: Optional[datetime] = None,
    updated_at: Optional[datetime] = None,
) -> GenericFindingsDocument:
    normalized_findings = ensure_findings_list(findings)

    now = utcnow()
    created_value = created_at or now
    updated_value = updated_at or now

    if created_value.tzinfo is None:
        created_value = created_value.replace(tzinfo=timezone.utc)

    if updated_value.tzinfo is None:
        updated_value = updated_value.replace(tzinfo=timezone.utc)

    resolved_repository_id = build_repository_id(
        repository_id=repository_id,
        owner=owner,
        repo=repo,
    )

    return GenericFindingsDocument(
        document_id=document_id or str(uuid4()),
        repository_id=resolved_repository_id,
        findings_count=len(normalized_findings),
        created_at=created_value,
        updated_at=updated_value,
        owner=owner,
        repo=repo,
        sbom_name=sbom_name,
        findings=normalized_findings,
    )
