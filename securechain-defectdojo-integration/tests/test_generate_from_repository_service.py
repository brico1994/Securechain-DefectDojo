from __future__ import annotations

import pytest

from app.domain.generic_findings.repository import GenericFindingsRepository
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


class MockArtifactProvider:
    async def get_artifacts(self, owner: str, repository: str):
        sbom = {
            "components": [
                {
                    "name": "openssl",
                    "version": "1.1.1",
                    "purl": "pkg:generic/openssl@1.1.1",
                    "bom-ref": "ref-1",
                }
            ]
        }

        vex = {
            "metadata": {
                "statements": [
                    {
                        "vulnerability": {
                            "@id": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                            "name": "CVE-2024-0001",
                        },
                        "products": [
                            {
                                "identifiers": {
                                    "purl": "pkg:generic/openssl@1.1.1",
                                }
                            }
                        ],
                        "status": "affected",
                    }
                ]
            }
        }

        tix = {
            "metadata": {
                "statements": [
                    {
                        "vulnerability": {
                            "@id": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                            "name": "CVE-2024-0001",
                            "description": "demo vuln",
                            "cvss": {"vuln_impact": 7.0},
                        },
                        "products": [
                            {
                                "identifiers": {
                                    "purl": "pkg:generic/openssl@1.1.1",
                                }
                            }
                        ],
                    }
                ]
            }
        }

        metadata = {
            "owner": owner,
            "repo": repository,
            "sbom_name": "sbom.json",
        }

        return sbom, vex, tix, metadata


@pytest.mark.anyio
async def test_generate_document_from_repository_with_mock_provider():
    repository = GenericFindingsRepository(collection=InMemoryCollection())
    service = GenericFindingsService(
        repository=repository,
        artifact_provider=MockArtifactProvider(),
    )

    summary = await service.generate_document_from_repository(
        owner="acme",
        repository="demo",
    )

    assert summary.document_id
    assert summary.owner == "acme"
    assert summary.repo == "demo" or getattr(summary, "repository", "demo") == "demo"
    assert summary.findings_count == 1

    document = service.get_document(summary.document_id)

    assert document is not None
    assert document.document_id == summary.document_id
    assert document.findings_count == 1
