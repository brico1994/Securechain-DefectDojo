from __future__ import annotations

import json
import os
from tempfile import NamedTemporaryFile
from typing import Any, Dict, Optional

import requests

from app.exceptions.defectdojo_exceptions import (
    DefectDojoImportError,
    DefectDojoNotConfigured,
)


class DefectDojoClient:
    """
    Backend client for DefectDojo API v2.

    Responsibilities:
    - Keep API key only in backend
    - Validate configuration
    - Import Generic Findings payloads
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        enabled: Optional[bool] = None,
        product_name: Optional[str] = None,
        engagement_name: Optional[str] = None,
        test_title: Optional[str] = None,
        timeout_seconds: int = 30,
    ) -> None:
        self.base_url = (base_url or os.getenv("DEFECTDOJO_BASE_URL") or "").rstrip("/")
        self.api_key = api_key or os.getenv("DEFECTDOJO_API_KEY")
        self.enabled = (
            enabled
            if enabled is not None
            else os.getenv("DEFECTDOJO_ENABLED", "false").lower() == "true"
        )
        self.product_name = product_name or os.getenv("DEFECTDOJO_PRODUCT_NAME")
        self.engagement_name = engagement_name or os.getenv("DEFECTDOJO_ENGAGEMENT_NAME")
        self.test_title = test_title or os.getenv("DEFECTDOJO_TEST_TITLE", "SecureChain Generic Findings")
        self.timeout_seconds = timeout_seconds

    def _ensure_configured(
            self,
            product_name: Optional[str]=None,
            engagement_name: Optional[str]=None
            ) -> None:
        missing = []

        if not self.enabled:
            missing.append("DEFECTDOJO_ENABLED=true")
        if not self.base_url:
            missing.append("DEFECTDOJO_BASE_URL")
        if not self.api_key:
            missing.append("DEFECTDOJO_API_KEY")
        if not self.product_name:
            missing.append("DEFECTDOJO_PRODUCT_NAME or request.product_name")
        if not self.engagement_name:
            missing.append("DEFECTDOJO_ENGAGEMENT_NAME or request.engagement_name")

        if missing:
            raise DefectDojoNotConfigured(
                "DefectDojo is not configured. Missing: " + ", ".join(missing)
            )

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Token {self.api_key}",
        }

    def import_generic_findings(
            self,
            payload: Dict[str, Any],
            product_name: Optional[str] = None,
            engagement_name: Optional[str] = None,
            test_title: Optional[str] = None,
            ) -> Dict[str, Any]:
        """
        Imports a Generic Findings JSON payload into DefectDojo.

        Uses /api/v2/import-scan/ for first imports.

        DefectDojo import-scan expects multipart/form-data with:
        - file
        - scan_type
        - product_name
        - engagement_name
        """
        self._ensure_configured(
                product_name=product_name,
                engagement_name=engagement_name,
                )
        
        resolved_product_name = product_name or self.product_name
        resolved_engagement_name = engagement_name or self.engagement_name
        resolved_test_title = test_title or self.test_title


        url = f"{self.base_url}/api/v2/import-scan/"

        report_payload = dict(payload)
        report_payload.setdefault("name", self.test_title)

        with NamedTemporaryFile(mode="w+b", suffix=".json") as temp_file:
            encoded = json.dumps(report_payload).encode("utf-8")
            temp_file.write(encoded)
            temp_file.seek(0)

            files = {
                "file": ("generic_findings.json", temp_file, "application/json"),
            }

            data = {
                "scan_type": "Generic Findings Import",
                "product_name": resolved_product_name,
                "engagement_name": resolved_engagement_name,
                "test_title": resolved_test_title,
                "active": "true",
                "verified": "true",
                "close_old_findings": "false",
            }

            try:
                response = requests.post(
                    url,
                    headers=self._headers(),
                    files=files,
                    data=data,
                    timeout=self.timeout_seconds,
                )
            except requests.RequestException as exc:
                raise DefectDojoImportError("DefectDojo request failed") from exc

        if response.status_code not in {200, 201}:
            raise DefectDojoImportError(
                f"DefectDojo import failed: status={response.status_code}, body={response.text}"
            )

        try:
            return response.json()
        except ValueError:
            return {
                "status_code": response.status_code,
                "raw_response": response.text,
            }
