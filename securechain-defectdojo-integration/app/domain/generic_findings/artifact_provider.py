from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from app.apis.vexgen_client import (
    VEXGenClient,
    VEXGenClientError,
)
from app.domain.generic_findings.infrastructure.repository_downloader import (
    RepositoryDownloader,
    RepositoryDownloadError,
)
from app.domain.generic_findings.sbom_finder import (
    InvalidSbomError,
    SBOMFinder,
    SbomNotFoundError,
)


class ArtifactProviderError(Exception):
    """
    Base error for artifact provider failures.
    """


class ArtifactProviderNotImplemented(ArtifactProviderError):
    """
    Kept for backward compatibility.

    The provider is now implemented, but this exception can still be used
    by tests or fallback implementations.
    """


class ArtifactResolutionError(ArtifactProviderError):
    """
    Raised when SBOM/VEX/TIX artifacts cannot be resolved for a repository.
    """


class ArtifactProvider:
    """
    Resolves SecureChain artifacts from a GitHub repository.

    Flow:
    1. Download repository
    2. Find/read SBOM locally
    3. Call VEXGEN to generate VEX/TIX ZIP
    4. Extract matching VEX/TIX for the SBOM
    5. Return sbom, vex, tix, metadata
    """

    def __init__(
        self,
        repository_downloader: Optional[RepositoryDownloader] = None,
        sbom_finder: Optional[SBOMFinder] = None,
        vexgen_client: Optional[VEXGenClient] = None,
    ) -> None:
        self.repository_downloader = repository_downloader or RepositoryDownloader()
        self.sbom_finder = sbom_finder or SBOMFinder()
        self.vexgen_client = vexgen_client or VEXGenClient()

    async def get_artifacts(
        self,
        owner: str,
        repository: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        owner = owner.strip()
        repository = repository.strip()

        if not owner:
            raise ValueError("owner is required")

        if not repository:
            raise ValueError("repository is required")

        repository_directory: Optional[str] = None

        try:
            repository_directory = self.repository_downloader.download_repository(
                owner=owner,
                repository=repository,
            )

            sbom, sbom_path = self.sbom_finder.read_first_sbom(repository_directory)

            sbom_relative_path = self.sbom_finder.relative_path(
                file_path=sbom_path,
                repository_directory=repository_directory,
            )

            vex, tix = self.vexgen_client.generate_vex_tix_for_repository(
                owner=owner,
                repository=repository,
                sbom_relative_path=sbom_relative_path,
            )

            metadata: Dict[str, Any] = {
                "owner": owner,
                "repo": repository,
                "repository": repository,
                "repository_id": f"{owner}/{repository}",
                "sbom_name": sbom_relative_path.split("/")[-1],
                "sbom_path": sbom_relative_path,
            }

            return sbom, vex, tix, metadata

        except (RepositoryDownloadError, SbomNotFoundError, InvalidSbomError, VEXGenClientError) as exc:
            raise ArtifactResolutionError(str(exc)) from exc

        finally:
            if repository_directory:
                self.repository_downloader.cleanup(repository_directory)
