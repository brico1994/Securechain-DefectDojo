from __future__ import annotations

from fastapi.testclient import TestClient

from app.domain.generic_findings.repository import GenericFindingsRepository
from app.exceptions.defectdojo_exceptions import (
    DefectDojoImportError,
    DefectDojoNotConfigured,
)
from app.main import app
from app.schemas.generic_findings.generic_findings_schemas import GenericFindingsDocument
from app.services.generic_findings_service import GenericFindingsService


BASE_URL = "/api/defectdojo/generic-findings"


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


def build_service_with_document(
    *,
    document_id: str = "doc-valid",
    defectdojo_client=None,
    invalid_duplicate: bool = False,
) -> GenericFindingsService:
    collection = InMemoryCollection()
    repository = GenericFindingsRepository(collection=collection)

    finding = {
        "title": "CVE-2024-0001",
        "severity": "High",
        "description": "demo vulnerability",
    }

    if invalid_duplicate:
        finding["duplicate"] = False

    document = GenericFindingsDocument(
        document_id=document_id,
        repository_id="acme/demo",
        owner="acme",
        repo="demo",
        sbom_name="sbom.json",
        findings_count=1,
        findings=[finding],
    )
    repository.save(document)

    return GenericFindingsService(
        repository=repository,
        defectdojo_client=defectdojo_client or SuccessfulDefectDojoClient(),
    )


def override_service(service: GenericFindingsService):
    def _override():
        return service

    return _override


def test_import_document_to_defectdojo_success():
    from app.dependencies import get_service

    service = build_service_with_document()

    app.dependency_overrides[get_service] = override_service(service)
    try:
        client = TestClient(app)
        response = client.post(f"{BASE_URL}/documents/doc-valid/import")

        assert response.status_code == 200
        payload = response.json()

        assert payload["document_id"] == "doc-valid"
        assert payload["import_status"] == "success"
        assert payload["defectdojo_import_id"] == "dojo-import-1"
        assert payload["message"] == "import completed"
    finally:
        app.dependency_overrides.clear()


def test_import_document_to_defectdojo_not_found_returns_404():
    from app.dependencies import get_service

    service = build_service_with_document()

    app.dependency_overrides[get_service] = override_service(service)
    try:
        client = TestClient(app)
        response = client.post(f"{BASE_URL}/documents/missing-doc/import")

        assert response.status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_import_document_to_defectdojo_invalid_payload_returns_400():
    from app.dependencies import get_service

    service = build_service_with_document(invalid_duplicate=True)

    app.dependency_overrides[get_service] = override_service(service)
    try:
        client = TestClient(app)
        response = client.post(f"{BASE_URL}/documents/doc-valid/import")

        assert response.status_code == 400
    finally:
        app.dependency_overrides.clear()


def test_import_document_to_defectdojo_not_configured_returns_501():
    from app.dependencies import get_service

    service = build_service_with_document(
        defectdojo_client=NotConfiguredDefectDojoClient()
    )

    app.dependency_overrides[get_service] = override_service(service)
    try:
        client = TestClient(app)
        response = client.post(f"{BASE_URL}/documents/doc-valid/import")

        assert response.status_code == 501
    finally:
        app.dependency_overrides.clear()


def test_import_document_to_defectdojo_client_error_returns_502():
    from app.dependencies import get_service

    service = build_service_with_document(
        defectdojo_client=FailingDefectDojoClient()
    )

    app.dependency_overrides[get_service] = override_service(service)
    try:
        client = TestClient(app)
        response = client.post(f"{BASE_URL}/documents/doc-valid/import")

        assert response.status_code == 502
    finally:
        app.dependency_overrides.clear()
