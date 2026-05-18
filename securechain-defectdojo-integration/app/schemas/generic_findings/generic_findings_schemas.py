from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


#class GenerateGenericFindingsRequest(BaseModel):
#    repository_id: str = Field(..., description="Repository identifier")

class GenerateGenericFindingsRequest(BaseModel):
    """
    Request para generar Generic Findings desde un repositorio
    """
    owner: str = Field(..., description="GitHub owner or organization")
    repository: str = Field(..., description="GitHub repository name")


class GenericFindingsDocument(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    document_id: str
    repository_id: str

    findings_count: int = 0

    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    owner: Optional[str] = None
    repo: Optional[str] = None
    sbom_name: Optional[str] = None

    findings: List[Dict[str, Any]] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="python")

    def to_mongo_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="python")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GenericFindingsDocument":
        return cls.model_validate(data)

    def to_summary_response(self) -> "GenericFindingsSummaryResponse":
        return GenericFindingsSummaryResponse(
            document_id=self.document_id,
            repository_id=self.repository_id,
            findings_count=self.findings_count,
            created_at=self.created_at,
            updated_at=self.updated_at,
            owner=self.owner,
            repo=self.repo,
            sbom_name=self.sbom_name,
        )

    def to_document_response(self) -> "GenericFindingsDocumentResponse":
        return GenericFindingsDocumentResponse(
            document_id=self.document_id,
            repository_id=self.repository_id,
            findings_count=self.findings_count,
            created_at=self.created_at,
            updated_at=self.updated_at,
            owner=self.owner,
            repo=self.repo,
            sbom_name=self.sbom_name,
            findings=self.findings,
        )


class GenericFindingsSummaryResponse(BaseModel):
    document_id: str
    repository_id: str

    findings_count: int

    created_at: datetime
    updated_at: datetime

    owner: Optional[str] = None
    repo: Optional[str] = None
    sbom_name: Optional[str] = None

    @classmethod
    def from_document(cls, document: GenericFindingsDocument) -> "GenericFindingsSummaryResponse":
        return document.to_summary_response()


class GenericFindingsDocumentResponse(BaseModel):
    document_id: str
    repository_id: str

    findings_count: int

    created_at: datetime
    updated_at: datetime

    owner: Optional[str] = None
    repo: Optional[str] = None
    sbom_name: Optional[str] = None

    findings: List[Dict[str, Any]]

    @classmethod
    def from_document(cls, document: GenericFindingsDocument) -> "GenericFindingsDocumentResponse":
        return document.to_document_response()

# =========================================================
# RESPONSE — GENERATE (SUMMARY)
# =========================================================
class GenerateGenericFindingsResponse(BaseModel):
    """
    Respuesta del endpoint de generación
    """
    document_id: str

    owner: str
    repository: str

    findings_count: int

    created_at: datetime

class DefectDojoImportRequest(BaseModel):
    product_name: Optional[str] = None
    engagement_name: Optional[str] = None
    test_title: Optional[str] = None

class DefectDojoImportResponse(BaseModel):
    document_id: str
    import_status: str
    defectdojo_import_id: Optional[str] = None
    message: str

# =========================================================
# RESPONSE — SUMMARY (LIST)
# =========================================================
#class GenericFindingsSummaryResponse(BaseModel):
#    document_id: str
#    owner: Optional[str] = None
#    repository: Optional[str] = None
#
#    findings_count: int
#
#    created_at: datetime
#    updated_at: datetime
#
## =========================================================
## RESPONSE — FULL DOCUMENT
## =========================================================
#class GenericFindingsDocumentResponse(BaseModel):
#    document_id: str
#
#    owner: Optional[str] = None
#    repository: Optional[str] = None
#
#    findings_count: int
#
#    created_at: datetime
#    updated_at: datetime
#
#    findings: List[Dict[str, Any]]
#
