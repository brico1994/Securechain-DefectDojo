from __future__ import annotations

import json
import traceback
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, UploadFile, status

from app.dependencies import get_service

from app.exceptions.defectdojo_exceptions import (
    DefectDojoImportError,
    DefectDojoNotConfigured,
    DocumentNotFoundError,
    InvalidGenericFindingsPayload,
)


from app.schemas.generic_findings.generic_findings_schemas import (
    DefectDojoImportRequest,
    DefectDojoImportResponse,
    GenerateGenericFindingsRequest,
    GenerateGenericFindingsResponse,
    GenericFindingsDocumentResponse,
    GenericFindingsSummaryResponse,
)

from app.services.generic_findings_service import GenericFindingsService


router = APIRouter(tags=["generic-findings"])


async def read_json_upload(upload: UploadFile) -> Dict[str, Any]:
    try:
        raw = await upload.read()

        if not raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{upload.filename or 'upload'}: empty file",
            )

        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{upload.filename or 'upload'}: invalid UTF-8",
            ) from exc

        try:
            data = json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{upload.filename or 'upload'}: invalid JSON",
            ) from exc

        if not isinstance(data, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{upload.filename or 'upload'}: root JSON must be an object",
            )

        return data

    finally:
        await upload.close()


@router.post("/upload", response_model=Dict[str, Any])
async def upload_generic_findings(
    sbom: UploadFile = File(..., description="CycloneDX SBOM JSON"),
    vex: UploadFile = File(..., description="VEX JSON"),
    tix: UploadFile = File(..., description="TIX JSON"),
    owner: Optional[str] = Form(default=None),
    repo: Optional[str] = Form(default=None),
    sbom_name: Optional[str] = Form(default=None),
    service: GenericFindingsService = Depends(get_service),
) -> Dict[str, Any]:
    try:
        sbom_data = await read_json_upload(sbom)
        vex_data = await read_json_upload(vex)
        tix_data = await read_json_upload(tix)

        resolved_sbom_name = sbom_name or sbom.filename or "sbom"

        response = service.generate_generic_findings_from_upload_payloads(
            sbom=sbom_data,
            vex=vex_data,
            tix=tix_data,
            owner=owner,
            repo=repo,
            sbom_name=resolved_sbom_name,
        )

        if not isinstance(response, dict):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="failed to generate generic findings: invalid engine response",
            )

        findings = response.get("findings")
        if not isinstance(findings, list):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="failed to generate generic findings: missing findings envelope",
            )

        return response

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to generate generic findings",
        ) from exc


@router.post(
    "/generate",
    response_model=GenerateGenericFindingsResponse,
)
async def generate_generic_findings_from_repository(
    request: GenerateGenericFindingsRequest,
    service: GenericFindingsService = Depends(get_service),
) -> GenerateGenericFindingsResponse:
    try:
        document = await service.generate_document_from_repository(
            owner=request.owner,
            repository=request.repository,
        )

        return GenerateGenericFindingsResponse(
            document_id=document.document_id,
            owner=document.owner or request.owner,
            repository=document.repo or request.repository,
            findings_count=document.findings_count,
            created_at=document.created_at,
        )

    except NotImplementedError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"failed to generate generic findings from repository: {exc}",
        ) from exc


@router.post(
    "/documents/from-findings",
    response_model=GenericFindingsSummaryResponse,
)
async def save_document_from_findings(
    findings: List[Dict[str, Any]],
    repository_id: Optional[str] = None,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    sbom_name: Optional[str] = None,
    service: GenericFindingsService = Depends(get_service),
) -> GenericFindingsSummaryResponse:
    try:
        document = service.save_document_from_findings(
            findings=findings,
            repository_id=repository_id,
            owner=owner,
            repo=repo,
            sbom_name=sbom_name,
        )

        return document.to_summary_response()

    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get(
    "/documents/{document_id}",
    response_model=GenericFindingsDocumentResponse,
)
async def get_document(
    document_id: str,
    service: GenericFindingsService = Depends(get_service),
) -> GenericFindingsDocumentResponse:
    try:
        document = service.get_document(document_id)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="generic findings document not found",
        )

    return document

@router.post(
    "/documents/{document_id}/import",
    response_model=DefectDojoImportResponse,
)
async def import_document_to_defectdojo(
    document_id: str,
    request: Optional[DefectDojoImportRequest] = Body(default=None),
    service: GenericFindingsService = Depends(get_service),
) -> DefectDojoImportResponse:
    import_request = request or DefectDojoImportRequest()
    try:
        return service.import_document_to_defectdojo(
                document_id = document_id,
                product_name = import_request.product_name,
                engagement_name = import_request.engagement_name,
                test_title = import_request.test_title,)

    except DocumentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    except InvalidGenericFindingsPayload as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except DefectDojoNotConfigured as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=str(exc),
        ) from exc

    except DefectDojoImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"failed to import generic findings document to DefectDojo{exc}",
        ) from exc

@router.get(
    "/documents",
    response_model=List[GenericFindingsSummaryResponse],
)
async def list_all_documents(
    service: GenericFindingsService = Depends(get_service),
) -> List[GenericFindingsSummaryResponse]:
    try:
        return service.list_documents()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.get(
    "/repositories/{repository_id}/documents",
    response_model=List[GenericFindingsSummaryResponse],
)
async def list_documents_by_repository(
    repository_id: str,
    service: GenericFindingsService = Depends(get_service),
) -> List[GenericFindingsSummaryResponse]:
    try:
        return service.list_documents(repository_id=repository_id)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
