from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.domain.generic_findings.document_factory import build_generic_findings_document
from app.domain.generic_findings.repository import GenericFindingsRepository
from app.schemas.generic_findings.generic_findings_schemas import (
    GenericFindingsDocumentResponse,
    GenericFindingsSummaryResponse,
    DefectDojoImportResponse,
)
from app.exceptions.defectdojo_exceptions import (
    DocumentNotFoundError,
    InvalidGenericFindingsPayload,
    DefectDojoNotConfigured,
    DefectDojoImportError,
)
from app.domain.generic_findings.dojo_payload_validator import (
    sanitize_dojo_generic_findings_payload,
    validate_dojo_generic_findings_payload,
)
from app.domain.generic_findings.artifact_provider import (
    ArtifactProvider,
    ArtifactProviderNotImplemented,
    ArtifactResolutionError
)


def _statements_from_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if isinstance(payload.get("statements"), list):
        return payload["statements"]

    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("statements"), list):
        return metadata["statements"]

    return []


def _extract_component_index(sbom: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    components = sbom.get("components", [])
    if not isinstance(components, list):
        return {}

    index: Dict[str, Dict[str, Any]] = {}
    for component in components:
        if not isinstance(component, dict):
            continue
        purl = component.get("purl")
        if isinstance(purl, str) and purl:
            index[purl] = component

    return index


def _extract_vulnerability_id(statement: Dict[str, Any]) -> Optional[str]:
    vulnerability = statement.get("vulnerability")

    if isinstance(vulnerability, str):
        return vulnerability

    if isinstance(vulnerability, dict):
          for key in ("name", "id", "@id"):
            value = vulnerability.get(key)
            if isinstance(value, str) and value:
                if key == "@id" and value.rsplit("/", 1)[-1]:
                    return value.rsplit("/", 1)[-1]
                return value

    value = statement.get("vulnerability_id")
    if isinstance(value, str) and value:
        return value

    return None


def _extract_statement_purl(statement: Dict[str, Any]) -> Optional[str]:
    product = statement.get("product")
    if isinstance(product, dict):
        purl = product.get("purl")
        if isinstance(purl, str) and purl:
            return purl

    products = statement.get("products")
    if isinstance(products, list):
        for product_item in products:
            if not isinstance(product_item, dict):
                continue
            identifiers = product_item.get("identifiers")
            if isinstance(identifiers, dict):
                purl = identifiers.get("purl")
                if isinstance(purl, str) and purl:
                    return purl

    return None


def _extract_tix_by_key(tix: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for statement in _statements_from_payload(tix):
        if not isinstance(statement, dict):
            continue

        vulnerability_id = _extract_vulnerability_id(statement)
        purl = _extract_statement_purl(statement)

        if vulnerability_id and purl:
            index[(purl, vulnerability_id)] = statement

    return index


def _compute_severity(tix_statement: Optional[Dict[str, Any]]) -> str:
    if not isinstance(tix_statement, dict):
        return "INFO"

    explicit = tix_statement.get("severity")
    if isinstance(explicit, str) and explicit:
        return explicit.upper()

    vulnerability = tix_statement.get("vulnerability")
    if isinstance(vulnerability, dict):
        cvss = vulnerability.get("cvss")
        if isinstance(cvss, dict):
            impact = cvss.get("vuln_impact")
            if isinstance(impact, (int, float)):
                if impact >= 9.0:
                    return "CRITICAL"
                if impact >= 7.0:
                    return "HIGH"
                if impact >= 4.0:
                    return "MEDIUM"
                if impact > 0:
                    return "LOW"

    return "INFO"


def _compute_description(
    vulnerability_id: str,
    vex_statement: Dict[str, Any],
    tix_statement: Optional[Dict[str, Any]],
) -> str:
    if isinstance(tix_statement, dict):
        vulnerability = tix_statement.get("vulnerability")
        if isinstance(vulnerability, dict):
            description = vulnerability.get("description")
            if isinstance(description, str) and description.strip():
                return description.strip()

        description = tix_statement.get("description")
        if isinstance(description, str) and description.strip():
            return description.strip()

    impact_statement = vex_statement.get("impact_statement")
    if isinstance(impact_statement, str) and impact_statement.strip():
        return impact_statement.strip()

    return f"Generic finding generated for {vulnerability_id}"


def _compute_mitigation(vex_statement: Dict[str, Any]) -> Optional[str]:
    justification = vex_statement.get("justification")
    if isinstance(justification, str) and justification.strip():
        return justification.strip()

    return None


def _compute_cwe(tix_statement: Optional[Dict[str, Any]]) -> Optional[int]:
    if not isinstance(tix_statement, dict):
        return None

    vulnerability = tix_statement.get("vulnerability")
    if not isinstance(vulnerability, dict):
        return None

    cwes = vulnerability.get("cwes")
    if not isinstance(cwes, list) or not cwes:
        return None

    first = cwes[0]
    if not isinstance(first, dict):
        return None

    name = first.get("name")
    if not isinstance(name, str):
        return None

    if name.upper().startswith("CWE-"):
        suffix = name.split("-", 1)[1]
        if suffix.isdigit():
            return int(suffix)

    return None


def _compute_mitigated(vex_statement: Dict[str, Any]) -> Optional[bool]:
    status = vex_statement.get("status")
    if not isinstance(status, str):
        return None

    normalized = status.strip().lower()
    if normalized in {"not_affected", "fixed", "resolved"}:
        return True
    if normalized in {"affected", "under_investigation"}:
        return False

    return None


def _build_unique_id_from_tool(
    owner: Optional[str],
    repo: Optional[str],
    sbom_name: Optional[str],
    purl: str,
    vulnerability_id: str,
) -> str:
    owner_part = owner or "unknown-owner"
    repo_part = repo or "unknown-repo"
    sbom_part = sbom_name or "unknown-sbom"
    return f"{owner_part}/{repo_part}|{sbom_part}|{purl}|{vulnerability_id}"


def _build_finding(
    component: Dict[str, Any],
    purl: str,
    vulnerability_id: str,
    vex_statement: Dict[str, Any],
    tix_statement: Optional[Dict[str, Any]],
    owner: Optional[str],
    repo: Optional[str],
    sbom_name: Optional[str],
) -> Dict[str, Any]:
    finding: Dict[str, Any] = {
        "title": vulnerability_id,
        "severity": _compute_severity(tix_statement),
        "description": _compute_description(vulnerability_id, vex_statement, tix_statement),
        "component_name": component.get("name"),
        "component_version": component.get("version"),
        "file_path": purl,
        "unique_id_from_tool": _build_unique_id_from_tool(owner, repo, sbom_name, purl, vulnerability_id),
        "tags": ["generic-findings"],
    }

    mitigation = _compute_mitigation(vex_statement)
    if mitigation:
        finding["mitigation"] = mitigation

    cwe = _compute_cwe(tix_statement)
    if cwe is not None:
        finding["cwe"] = cwe

    mitigated = _compute_mitigated(vex_statement)
    if mitigated is not None:
        finding["mitigated"] = mitigated

    return finding


def _build_findings_from_payloads(
    sbom: Dict[str, Any],
    vex: Dict[str, Any],
    tix: Dict[str, Any],
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    sbom_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    component_index = _extract_component_index(sbom)
    tix_index = _extract_tix_by_key(tix)

    findings: List[Dict[str, Any]] = []

    for statement in _statements_from_payload(vex):
        if not isinstance(statement, dict):
            continue

        vulnerability_id = _extract_vulnerability_id(statement)
        purl = _extract_statement_purl(statement)

        if not vulnerability_id or not purl:
            continue

        component = component_index.get(purl)
        if not component:
            continue

        tix_statement = tix_index.get((purl, vulnerability_id))

        finding = _build_finding(
            component=component,
            purl=purl,
            vulnerability_id=vulnerability_id,
            vex_statement=statement,
            tix_statement=tix_statement,
            owner=owner,
            repo=repo,
            sbom_name=sbom_name,
        )
        findings.append(finding)

    return findings


def generate_generic_findings_from_upload_payloads(
    sbom: Dict[str, Any],
    vex: Dict[str, Any],
    tix: Dict[str, Any],
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    sbom_name: Optional[str] = None,
) -> Dict[str, Any]:
    findings = _build_findings_from_payloads(
        sbom=sbom,
        vex=vex,
        tix=tix,
        owner=owner,
        repo=repo,
        sbom_name=sbom_name,
    )
    return {"findings": findings}


class GenericFindingsService:
    
    def __init__(
        self,
        repository: Optional[GenericFindingsRepository] = None,
        artifact_provider=None,
        defectdojo_client=None,
    ):
        # Repository (persistencia)
        if repository is None:
            repository = GenericFindingsRepository(InMemoryCollection())
        self.repository = repository

        # Artifact provider (SBOM/VEX/TIX desde repo)
        self.artifact_provider = artifact_provider

        # DefectDojo client (import backend)
        self.defectdojo_client = defectdojo_client

    def generate_generic_findings_from_upload_payloads(
        self,
        sbom: Dict[str, Any],
        vex: Dict[str, Any],
        tix: Dict[str, Any],
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        sbom_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        return generate_generic_findings_from_upload_payloads(
            sbom=sbom,
            vex=vex,
            tix=tix,
            owner=owner,
            repo=repo,
            sbom_name=sbom_name,
        )

    def save_document_from_findings(
        self,
        repository_id: Optional[str] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        findings_payload: Optional[Dict[str, Any]] = None,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        sbom_name: Optional[str] = None,
    ):
        if self.repository is None:
            raise RuntimeError("repository is not configured")

        if findings_payload is not None:
            findings = findings_payload.get("findings", [])

        if findings is None:
            raise ValueError("findings are required")

        document = build_generic_findings_document(
            findings=findings,
            repository_id=repository_id,
            owner=owner,
            repo=repo,
            sbom_name=sbom_name,
        )

        return self.repository.save(document)

    def get_document(self, document_id: str) -> Optional[GenericFindingsDocumentResponse]:
        if self.repository is None:
            raise RuntimeError("repository is not configured")

        document = self.repository.get_by_document_id(document_id)
        if document is None:
            return None

        return document.to_document_response()

    def list_documents(self, repository_id: Optional[str] = None) -> List[GenericFindingsSummaryResponse]:
        if self.repository is None:
            raise RuntimeError("repository is not configured")

        if repository_id:
            return self.repository.list_by_repository(repository_id)

        return self.repository.list_all()

#    def generate_document_from_repository(
#        self,
#        repository_id: str,
#    ) -> GenericFindingsSummaryResponse:
#        raise NotImplementedError("repository-based generation is not implemented yet")
#

    async def generate_document_from_repository(
        self,
        owner: str,
        repository: str,
    ) -> GenericFindingsSummaryResponse:
        if not owner:
            raise ValueError("owner is required")

        if not repository:
            raise ValueError("repository is required")

        try:
            sbom, vex, tix, metadata = await self.artifact_provider.get_artifacts(
                owner=owner,
                repository=repository,
            )
        except ArtifactProviderNotImplemented as exc:
            raise NotImplementedError(
                "repository-based generation is not implemented yet"
            ) from exc
        except ArtifactResolutionError as exc:
            raise RuntimeError(str(exc)) from exc

        sbom_name = metadata.get("sbom_name") if isinstance(metadata, dict) else None
        repository_id = f"{owner}/{repository}"

        findings_payload = self.generate_generic_findings_from_upload_payloads(
            sbom=sbom,
            vex=vex,
            tix=tix,
            owner=owner,
            repo=repository,
            sbom_name=sbom_name,
        )

        document = self.save_document_from_findings(
            repository_id=repository_id,
            findings_payload=findings_payload,
            owner=owner,
            repo=repository,
            sbom_name=sbom_name,
        )

        return document#.to_summary_response()
    
    def import_document_to_defectdojo(
        self,
        document_id: str,
        product_name: Optional[str] = None,
        engagement_name: Optional[str] = None,
        test_title: Optional[str] = None
    ) -> DefectDojoImportResponse:

        if self.repository is None:
            raise RuntimeError("repository is not configured")

        if self.defectdojo_client is None:
            raise RuntimeError("defectdojo_client is not configured")

        document = self.repository.get_by_document_id(document_id)

        if document is None:
            raise DocumentNotFoundError(document_id)

        payload = {"findings": document.findings}

        validate_dojo_generic_findings_payload(payload)
        payload = sanitize_dojo_generic_findings_payload(payload)

        try:
            result = self.defectdojo_client.import_generic_findings(
                    payload,
                    product_name = product_name,
                    engagement_name = engagement_name,
                    test_title = test_title)

        except DefectDojoNotConfigured:
            raise

        except Exception as exc:
            raise DefectDojoImportError(f"failed to import into DefectDojo: {exc}") from exc

        return DefectDojoImportResponse(
            document_id=document_id,
            import_status="success",
            defectdojo_import_id=result.get("import_id") if isinstance(result, dict) else None,
            message="import completed",
        )

class InMemoryCollection:
    def __init__(self):
        self._docs = []

    def replace_one(self, filter, replacement, upsert=False):
        for i, d in enumerate(self._docs):
            if d["document_id"] == filter["document_id"]:
                self._docs[i] = replacement
                return
        self._docs.append(replacement)

    def find_one(self, filter):
        for d in self._docs:
            if d["document_id"] == filter["document_id"]:
                return d
        return None

    def find(self, filter=None):
        if not filter:
            return self._docs
        return [
            d for d in self._docs
            if all(d.get(k) == v for k, v in filter.items())
        ]

    
