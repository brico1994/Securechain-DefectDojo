from __future__ import annotations

import json
import os
from io import BytesIO
from typing import Any, Dict, Optional, Tuple
from zipfile import ZipFile, BadZipFile

import requests


class VEXGenClientError(Exception):
    pass


class VEXGenNotConfiguredError(VEXGenClientError):
    pass


class VEXGenResponseError(VEXGenClientError):
    pass


class VEXGenZipError(VEXGenClientError):
    pass


class VEXGenClient:
    """
    Client HTTP para comunicarse con securechain-vexgen.

    Responsabilidades:
    - Llamar al endpoint de generación VEX/TIX
    - Recibir ZIP
    - Extraer VEX y TIX
    - Emparejar por sbom_path
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        generate_path: Optional[str] = None,
        api_key: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout_seconds: int = 180,
    ) -> None:
        self.base_url = (
            base_url
            or os.getenv("VEXGEN_BASE_URL")
            or "http://securechain-vexgen:8000"
        ).rstrip("/")

        self.generate_path = (
            generate_path
            or os.getenv("VEXGEN_GENERATE_PATH")
            or "/vex_tix/generate"
        )

        self.api_key = api_key or os.getenv("VEXGEN_API_KEY")
        self.bearer_token = bearer_token or os.getenv("VEXGEN_BEARER_TOKEN")
        self.timeout_seconds = timeout_seconds

    def generate_vex_tix_for_repository(
        self,
        owner: str,
        repository: str,
        sbom_relative_path: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        owner = owner.strip()
        repository = repository.strip()

        if not owner:
            raise ValueError("owner is required")

        if not repository:
            raise ValueError("repository is required")

        zip_bytes = self._request_vexgen_zip(owner=owner, repository=repository)

        return self._extract_vex_tix_from_zip(
            zip_bytes=zip_bytes,
            sbom_relative_path=sbom_relative_path,
        )

    def _request_vexgen_zip(
        self,
        owner: str,
        repository: str,
    ) -> bytes:
        if not self.base_url:
            raise VEXGenNotConfiguredError("VEXGEN_BASE_URL is not configured")

        url = f"{self.base_url}{self.generate_path}"

        headers = {
            "Accept": "application/zip, application/octet-stream",
            "Content-Type": "application/json",
        }

        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        if self.api_key:
            headers["X-API-Key"] = self.api_key

        payload = {
            "owner": owner,
            "name": repository,
        }

        try:
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise VEXGenResponseError(
                f"failed to call VEXGEN at {url}"
            ) from exc

        if response.status_code not in {200, 201}:
            raise VEXGenResponseError(
                f"VEXGEN returned status={response.status_code}, body={response.text}"
            )

        if not response.content:
            raise VEXGenResponseError("VEXGEN returned empty response")

        return response.content

    def _extract_vex_tix_from_zip(
        self,
        zip_bytes: bytes,
        sbom_relative_path: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        try:
            with ZipFile(BytesIO(zip_bytes)) as archive:
                names = archive.namelist()

                vex_name = self._find_zip_entry(
                    names=names,
                    prefix="vex_",
                    sbom_relative_path=sbom_relative_path,
                )
                tix_name = self._find_zip_entry(
                    names=names,
                    prefix="tix_",
                    sbom_relative_path=sbom_relative_path,
                )

                if vex_name is None:
                    raise VEXGenZipError(
                        f"VEX file not found in VEXGEN zip for SBOM: {sbom_relative_path}"
                    )

                if tix_name is None:
                    raise VEXGenZipError(
                        f"TIX file not found in VEXGEN zip for SBOM: {sbom_relative_path}"
                    )

                vex = self._read_json_entry(archive, vex_name)
                tix = self._read_json_entry(archive, tix_name)

                return vex, tix

        except BadZipFile as exc:
            raise VEXGenZipError("VEXGEN response is not a valid ZIP file") from exc

    @staticmethod
    def _find_zip_entry(
        names: list[str],
        prefix: str,
        sbom_relative_path: str,
    ) -> Optional[str]:
        expected = f"{prefix}{sbom_relative_path}.json"

        if expected in names:
            return expected

        normalized_expected = expected.replace("\\", "/")

        for name in names:
            if name.replace("\\", "/") == normalized_expected:
                return name

        sbom_filename = sbom_relative_path.split("/")[-1]
        fallback_suffix = f"{prefix}{sbom_filename}.json"

        for name in names:
            if name.endswith(fallback_suffix):
                return name

        return None

    @staticmethod
    def _read_json_entry(
        archive: ZipFile,
        entry_name: str,
    ) -> Dict[str, Any]:
        try:
            with archive.open(entry_name) as file:
                data = json.loads(file.read().decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise VEXGenZipError(
                f"ZIP entry is not valid JSON: {entry_name}"
            ) from exc

        if not isinstance(data, dict):
            raise VEXGenZipError(
                f"ZIP entry root must be an object: {entry_name}"
            )

        return data
