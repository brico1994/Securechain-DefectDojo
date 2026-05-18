from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol

from app.schemas.generic_findings.generic_findings_schemas import (
    GenericFindingsDocument,
    GenericFindingsSummaryResponse,
)


class CollectionLike(Protocol):
    def replace_one(self, filter: Dict[str, Any], replacement: Dict[str, Any], upsert: bool = False) -> Any:
        ...

    def find_one(self, filter: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ...

    def find(self, filter: Optional[Dict[str, Any]] = None) -> Any:
        ...


class GenericFindingsRepository:
    def __init__(self, collection: CollectionLike):
        self.collection = collection

    def save(self, document: GenericFindingsDocument) -> GenericFindingsSummaryResponse:
        self.collection.replace_one(
            {"document_id": document.document_id},
            document.to_mongo_dict(),
            upsert=True,
        )
        return document.to_summary_response()

    def get_by_document_id(self, document_id: str) -> Optional[GenericFindingsDocument]:
        raw = self.collection.find_one({"document_id": document_id})
        if not raw:
            return None

        cleaned = dict(raw)
        cleaned.pop("_id", None)
        return GenericFindingsDocument.from_dict(cleaned)

    def list_by_repository(self, repository_id: str) -> List[GenericFindingsSummaryResponse]:
        cursor = self.collection.find({"repository_id": repository_id})
        documents = [self._to_document(item) for item in cursor]
        documents.sort(key=lambda item: item.updated_at, reverse=True)
        return [document.to_summary_response() for document in documents]

    def list_all(self) -> List[GenericFindingsSummaryResponse]:
        cursor = self.collection.find({})
        documents = [self._to_document(item) for item in cursor]
        documents.sort(key=lambda item: item.updated_at, reverse=True)
        return [document.to_summary_response() for document in documents]

    @staticmethod
    def _to_document(raw: Dict[str, Any]) -> GenericFindingsDocument:
        cleaned = dict(raw)
        cleaned.pop("_id", None)
        return GenericFindingsDocument.from_dict(cleaned)
