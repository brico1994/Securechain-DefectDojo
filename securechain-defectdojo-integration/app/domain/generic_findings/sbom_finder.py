from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


class SbomNotFoundError(Exception):
    """
    Raised when no valid SBOM file is found in a repository.
    """


class InvalidSbomError(Exception):
    """
    Raised when an SBOM file exists but is not valid enough for Generic Findings.
    """


class SBOMFinder:
    """
    Finds and reads SBOM files from a local repository directory.

    Mirrors VEXGEN's minimum discovery rule:
    - file extension: .json
    - filename contains: sbom
    """

    def __init__(
        self,
        sbom_file_extension: str = ".json",
        sbom_identifier: str = "sbom",
    ) -> None:
        self.sbom_file_extension = sbom_file_extension
        self.sbom_identifier = sbom_identifier.lower()

    def find_sbom_files(self, repository_directory: str) -> List[str]:
        root = Path(repository_directory)

        if not root.exists() or not root.is_dir():
            return []

        sbom_files: List[str] = []

        for path in root.rglob(f"*{self.sbom_file_extension}"):
            if self.sbom_identifier not in path.name.lower():
                continue

            if self.is_valid_sbom_file(path):
                sbom_files.append(str(path))

        return sbom_files

    def is_valid_sbom_file(self, path: Path) -> bool:
        try:
            self.read_sbom_file(str(path))
            return True
        except InvalidSbomError:
            return False

    def read_first_sbom(self, repository_directory: str) -> tuple[Dict[str, Any], str]:
        sbom_files = self.find_sbom_files(repository_directory)

        if not sbom_files:
            raise SbomNotFoundError(
                f"no valid SBOM files found in repository directory: {repository_directory}"
            )

        sbom_path = sbom_files[0]
        return self.read_sbom_file(sbom_path), sbom_path

    def read_sbom_file(self, sbom_path: str) -> Dict[str, Any]:
        path = Path(sbom_path)

        if not path.exists():
            raise InvalidSbomError(f"SBOM file does not exist: {sbom_path}")

        if not path.is_file():
            raise InvalidSbomError(f"SBOM path is not a file: {sbom_path}")

        try:
            with path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except json.JSONDecodeError as exc:
            raise InvalidSbomError(f"SBOM file is not valid JSON: {sbom_path}") from exc

        if not isinstance(data, dict):
            raise InvalidSbomError(f"SBOM root must be an object: {sbom_path}")

        self.validate_sbom_payload(data, sbom_path=sbom_path)

        return data

    def validate_sbom_payload(
        self,
        sbom: Dict[str, Any],
        sbom_path: str = "SBOM",
    ) -> None:
        components = sbom.get("components")

        if not isinstance(components, list):
            raise InvalidSbomError(f"{sbom_path}: SBOM must contain a components list")

        has_purl = False

        for component in components:
            if not isinstance(component, dict):
                continue

            purl = component.get("purl")
            if isinstance(purl, str) and purl.strip():
                has_purl = True
                break

            properties = component.get("properties")
            if isinstance(properties, list):
                for prop in properties:
                    if not isinstance(prop, dict):
                        continue

                    if (
                        prop.get("name")
                        == "spdx:external-reference:package-manager:purl"
                        and isinstance(prop.get("value"), str)
                        and prop["value"].strip()
                    ):
                        has_purl = True
                        break

            if has_purl:
                break

        if not has_purl:
            raise InvalidSbomError(
                f"{sbom_path}: SBOM must contain at least one component with purl"
            )

    @staticmethod
    def relative_path(file_path: str, repository_directory: str) -> str:
        try:
            return str(Path(file_path).relative_to(Path(repository_directory)))
        except ValueError:
            return Path(file_path).name
