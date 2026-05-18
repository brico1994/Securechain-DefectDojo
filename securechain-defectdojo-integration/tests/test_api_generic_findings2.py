from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.main import app

BASE_URL = "/api/defectdojo/generic-findings"


def build_test_client() -> TestClient:
    return TestClient(app)


def minimal_valid_payloads():
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
                    "justification": "demo",
                    "impact_statement": "demo impact",
                    "priority": 7.5,
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
                        "cvss": {
                            "vuln_impact": 7.0,
                            "attack_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                        "cwes": [{"name": "CWE-94"}],
                    },
                    "products": [
                        {
                            "identifiers": {
                                "purl": "pkg:generic/openssl@1.1.1",
                            }
                        }
                    ],
                    "reachable_code": [{"fn": "x"}],
                    "exploits": [],
                }
            ]
        }
    }

    return sbom, vex, tix


def test_upload_generic_findings_happy_path():
    client = build_test_client()
    sbom, vex, tix = minimal_valid_payloads()

    response = client.post(
        f"{BASE_URL}/upload",
        files={
            "sbom": ("sbom.json", json.dumps(sbom), "application/json"),
            "vex": ("vex.json", json.dumps(vex), "application/json"),
            "tix": ("tix.json", json.dumps(tix), "application/json"),
        },
        data={
            "owner": "acme",
            "repo": "demo",
            "sbom_name": "sbom.json",
        },
    )

    assert response.status_code == 200
    payload = response.json()

    assert "findings" in payload
    assert isinstance(payload["findings"], list)
    assert len(payload["findings"]) == 1

    finding = payload["findings"][0]
    assert "title" in finding
    assert "severity" in finding
    assert "unique_id_from_tool" in finding
    assert "duplicate" not in finding
    assert finding["component_name"] == "openssl"
    assert finding["component_version"] == "1.1.1"
    assert (
        finding["unique_id_from_tool"]
        == "acme/demo|sbom.json|pkg:generic/openssl@1.1.1|CVE-2024-0001"
    )


def test_upload_generic_findings_invalid_json_returns_400():
    client = build_test_client()

    response = client.post(
        f"{BASE_URL}/upload",
        files={
            "sbom": ("sbom.json", '{"components":[}', "application/json"),
            "vex": ("vex.json", "{}", "application/json"),
            "tix": ("tix.json", "{}", "application/json"),
        },
    )

    assert response.status_code == 400
    assert "invalid JSON" in response.json()["detail"]


def test_upload_generic_findings_empty_file_returns_400():
    client = build_test_client()

    response = client.post(
        f"{BASE_URL}/upload",
        files={
            "sbom": ("sbom.json", "", "application/json"),
            "vex": ("vex.json", "{}", "application/json"),
            "tix": ("tix.json", "{}", "application/json"),
        },
    )

    assert response.status_code == 400
    assert "empty file" in response.json()["detail"]


def test_upload_generic_findings_root_json_must_be_object():
    client = build_test_client()

    response = client.post(
        f"{BASE_URL}/upload",
        files={
            "sbom": ("sbom.json", "[]", "application/json"),
            "vex": ("vex.json", "{}", "application/json"),
            "tix": ("tix.json", "{}", "application/json"),
        },
    )

    assert response.status_code == 400
    assert "root JSON must be an object" in response.json()["detail"]
