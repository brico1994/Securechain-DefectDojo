from app.services.generic_findings_service import GenericFindingsService


def test_service_save_and_get():
    service = GenericFindingsService()

    payload = {"findings": [{"id": "CVE-123"}]}

    doc = service.save_document_from_findings(
        repository_id="repo-service",
        findings_payload=payload,
    )

    loaded = service.get_document(doc.document_id)

    assert loaded.document_id == doc.document_id
    assert loaded.findings_count == 1
