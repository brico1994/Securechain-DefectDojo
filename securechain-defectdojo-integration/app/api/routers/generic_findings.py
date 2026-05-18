from __future__ import annotations

import json
from typing import Any, Dict, Optional

from fastapi import (
    APIRouter,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)

from app.services.generic_findings_service import (
    generate_generic_findings_from_upload_payloads,
)

router = APIRouter(tags=["/api/defectdojo"])


async def read_json_upload(upload: UploadFile) -> Dict[str, Any]:
    """
    Read and parse an uploaded JSON file.

    Returns:
        Parsed JSON object (must be a dict)

    Raises:
        HTTPException(400): empty file, invalid UTF-8, invalid JSON, or root not object
    """
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


@router.post("/upload")
@router.post("/generate")
async def upload_generic_findings(
    request: Request,
    sbom: Optional[UploadFile] = File(None, description="CycloneDX SBOM JSON"),
    vex: Optional[UploadFile] = File(None, description="VEX JSON"),
    tix: Optional[UploadFile] = File(None, description="TIX JSON"),
    owner: Optional[str] = Form(default=None),
    repo: Optional[str] = Form(default=None),
    sbom_name: Optional[str] = Form(default=None),
) -> Dict[str, Any]:
    """
    Upload SBOM + VEX + TIX JSON files and return DefectDojo Generic Findings
    envelope: { "findings": [...] }.
    """

    content_type = request.headers.get("content-type", "")

    # 🔹 CASO JSON → test_generate_not_implemented
    if "application/json" in content_type:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="not implemented",
        )

    # 🔹 CASO MULTIPART
    if not sbom or not vex or not tix:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing files",
        )

    try:
        sbom_data = await read_json_upload(sbom)
        vex_data = await read_json_upload(vex)
        tix_data = await read_json_upload(tix)

        resolved_sbom_name = sbom_name or sbom.filename or "sbom"

        response = generate_generic_findings_from_upload_payloads(
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

        if "findings" not in response:
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
