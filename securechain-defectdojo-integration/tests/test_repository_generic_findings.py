import pytest

from app.domain.generic_findings.repository import GenericFindingsRepository
from app.schemas.generic_findings.generic_findings_schemas import (
    GenericFindingsDocument,
)


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

        results = []
        for document in self._documents:
            matched = True
            for key, value in filter.items():
                if document.get(key) != value:
                    matched = False
                    break
            if matched:
                results.append(dict(document))

        return results


@pytest.fixture
def repo():
    return GenericFindingsRepository(collection=InMemoryCollection())


def test_repository_insert_and_get(repo):
    doc = GenericFindingsDocument(
        document_id="doc-1",
        repository_id="repo-test",
        findings=[{"id": "CVE-1"}],
        findings_count=1,
    )

    repo.save(doc)

    loaded = repo.get_by_document_id(doc.document_id)

    assert loaded is not None
    assert loaded.document_id == doc.document_id
    assert loaded.findings_count == 1


def test_repository_list_by_repository(repo):
    doc = GenericFindingsDocument(
        document_id="doc-2",
        repository_id="repo-list",
        findings=[{"id": "CVE-2"}],
        findings_count=1,
    )

    repo.save(doc)

    results = repo.list_by_repository("repo-list")

    assert len(results) >= 1
    assert results[0].repository_id == "repo-list"
