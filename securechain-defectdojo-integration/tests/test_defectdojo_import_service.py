from __future__ import annotations

import pytest

from app.domain.generic_findings.repository import GenericFindingsRepository
from app.exceptions.defectdojo_exceptions import (
    DefectDojoImportError,
    DefectDojoNotConfigured,
    DocumentNotFoundError,
    InvalidGenericFindingsPayload,
)
from app.schemas.generic_findings.generic_findings_schemas import GenericFindingsDocument
from app.services.generic_findings_service import GenericFindingsService


class InMemoryCollection:
    def __init__(self):
        self._documents = []

    def replace_one(self, filter, replacement, upsert=False):
        document_id = filter.get("document_id")

        for index, existing in enumerate(self._documents):
            if existing.get("document_id") == document_id:
                self._documents[index] = dict(replacement)
                return

        if upsert:
            self._documents.append(dict(replacement))

    def find_one(self, filter):
        document_id = filter.get("document_id")

        for document in self._documents:
            if document.get("document_id") == document_id:
                return dict(document)

        return None

    def find(self, filter=None):
        filter = filter or {}
        if not filter:
            return [dict(document) for document in self._documents]

        return [
            dict(document)
            for document in self._documents
            if all(document.get(key) == value for key, value in filter.items())
        ]

class SuccessfulDefectDojoClient:
    def import_generic_findings(
        self,
        payload,
        product_name=None,
        engagement_name=None,
        test_title=None,
    ):
        return {"import_id": "dojo-import-1"}

class NotConfiguredDefectDojoClient:
    def import_generic_findings(
        self,
        payload,
        product_name=None,
        engagement_name=None,
        test_title=None,
    ):
        raise DefectDojoNotConfigured("DefectDojo is not configured")

class FailingDefectDojoClient:
    def import_generic_findings(
        self,
        payload,
        product_name=None,
        engagement_name=None,
        test_title=None,
    ):
        raise DefectDojoImportError("DefectDojo import failed")

@pytest.fixture
def repository():
    return GenericFindingsRepository(collection=InMemoryCollection())


def save_valid_document(repository: GenericFindingsRepository) -> GenericFindingsDocument:
    document = GenericFindingsDocument(
        document_id="doc-valid",
        repository_id="acme/demo",
        owner="acme",
        repo="demo",
        sbom_name="sbom.json",
        findings_count=1,
        findings=[
            {
                "title": "CVE-2024-0001",
                "severity": "High",
                "description": "demo vulnerability",
            }
        ],
    )
    repository.save(document)
    return document


def test_import_document_to_defectdojo_success(repository):
    document = save_valid_document(repository)

    service = GenericFindingsService(
        repository=repository,
        defectdojo_client=SuccessfulDefectDojoClient(),
    )

    response = service.import_document_to_defectdojo(document.document_id)

    assert response.document_id == document.document_id
    assert response.import_status == "success"
    assert response.defectdojo_import_id == "dojo-import-1"
    assert response.message == "import completed"


def test_import_document_to_defectdojo_document_not_found(repository):
    service = GenericFindingsService(
        repository=repository,
        defectdojo_client=SuccessfulDefectDojoClient(),
    )

    with pytest.raises(DocumentNotFoundError):
        service.import_document_to_defectdojo("missing-doc")


def test_import_document_to_defectdojo_invalid_payload_duplicate(repository):
    document = GenericFindingsDocument(
        document_id="doc-invalid",
        repository_id="acme/demo",
        findings_count=1,
        findings=[
            {
                "title": "CVE-2024-0001",
                "severity": "High",
                "description": "demo vulnerability",
                "duplicate": False,
            }
        ],
    )
    repository.save(document)

    service = GenericFindingsService(
        repository=repository,
        defectdojo_client=SuccessfulDefectDojoClient(),
    )

    with pytest.raises(InvalidGenericFindingsPayload):
        service.import_document_to_defectdojo(document.document_id)


def test_import_document_to_defectdojo_not_configured(repository):
    document = save_valid_document(repository)

    service = GenericFindingsService(
        repository=repository,
        defectdojo_client=NotConfiguredDefectDojoClient(),
    )

    with pytest.raises(DefectDojoNotConfigured):
        service.import_document_to_defectdojo(document.document_id)


def test_import_document_to_defectdojo_client_error(repository):
    document = save_valid_document(repository)

    service = GenericFindingsService(
        repository=repository,
        defectdojo_client=FailingDefectDojoClient(),
    )

    with pytest.raises(DefectDojoImportError):
        service.import_document_to_defectdojo(document.document_id)
