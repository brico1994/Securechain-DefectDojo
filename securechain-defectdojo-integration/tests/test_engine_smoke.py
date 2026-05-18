from app.generic_findings.engine import generate_findings


def test_generate_findings_smoke_minimal():
    sbom = {
        "components": [
            {"name": "openssl", "version": "1.1.1", "purl": "pkg:generic/openssl@1.1.1", "bom-ref": "ref-1"}
        ]
    }

    vex = {
        "metadata": {
            "statements": [
                {
                    "vulnerability": {"@id": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001", "name": "CVE-2024-0001"},
                    "products": [{"identifiers": {"purl": "pkg:generic/openssl@1.1.1"}}],
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
                        "cvss": {"vuln_impact": 7.0, "attack_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                        "cwes": [{"name": "CWE-94"}],
                    },
                    "products": [{"identifiers": {"purl": "pkg:generic/openssl@1.1.1"}}],
                    "reachable_code": [{"fn": "x"}],
                    "exploits": [],
                }
            ]
        }
    }

    out = generate_findings(sbom, vex, tix, owner="acme", repo="demo", sbom_name="sbom.json")

    assert "findings" in out
    assert isinstance(out["findings"], list)
    assert len(out["findings"]) == 1

    f = out["findings"][0]
    assert f["severity"] in {"Info", "Low", "Medium", "High", "Critical"}
    assert "duplicate" not in f  # forbidden in your Dojo instance
    assert f["unique_id_from_tool"] == "acme/demo|sbom.json|pkg:generic/openssl@1.1.1|CVE-2024-0001"
    assert f["component_name"] == "openssl"
    assert f["component_version"] == "1.1.1"
