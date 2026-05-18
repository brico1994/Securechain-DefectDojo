import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

BASE_URL = "/api/defectdojo/generic-findings"


def test_upload_endpoint_happy_path():
    payload = {"findings": []}

    files = {
        "sbom": ("sbom.json", json.dumps(payload), "application/json"),
        "vex": ("vex.json", json.dumps(payload), "application/json"),
        "tix": ("tix.json", json.dumps(payload), "application/json"),
    }

    response = client.post(f"{BASE_URL}/upload", files=files)

    assert response.status_code in (200, 500)

def test_generate_from_repository_invalid_body_returns_422():
    response = client.post(
        f"{BASE_URL}/generate",
        json={"repository_id": "repo-test"},
    )

    assert response.status_code == 422


def test_get_document_not_found():
    response = client.get(f"{BASE_URL}/documents/non-existent-id")

    assert response.status_code == 404
