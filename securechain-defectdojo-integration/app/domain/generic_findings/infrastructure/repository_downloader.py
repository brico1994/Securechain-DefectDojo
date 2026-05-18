from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


class RepositoryDownloadError(Exception):
    """
    Raised when a GitHub repository cannot be downloaded.
    """


class RepositoryDownloader:
    """
    Downloads a GitHub repository into a temporary local directory.

    Responsibilities:
    - Clone repository from GitHub
    - Return local path
    - Keep Git logic isolated from service/domain orchestration

    Caller is responsible for deleting the returned directory.
    """

    def __init__(
        self,
        github_base_url: str = "https://github.com",
        timeout_seconds: int = 120,
    ) -> None:
        self.github_base_url = github_base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def download_repository(self, owner: str, repository: str) -> str:
        owner = owner.strip()
        repository = repository.strip()

        if not owner:
            raise ValueError("owner is required")

        if not repository:
            raise ValueError("repository is required")

        if not self._git_available():
            raise RepositoryDownloadError("git is not installed or not available in PATH")

        temp_dir = tempfile.mkdtemp(prefix="sc-dojo-repo-")
        repo_url = f"{self.github_base_url}/{owner}/{repository}.git"

        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    repo_url,
                    temp_dir,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
            )

            return temp_dir

        except subprocess.TimeoutExpired as exc:
            self.cleanup(temp_dir)
            raise RepositoryDownloadError(
                f"repository clone timed out: {owner}/{repository}"
            ) from exc

        except subprocess.CalledProcessError as exc:
            self.cleanup(temp_dir)
            stderr = exc.stderr.strip() if exc.stderr else "unknown git error"
            raise RepositoryDownloadError(
                f"failed to clone repository {owner}/{repository}: {stderr}"
            ) from exc

        except Exception:
            self.cleanup(temp_dir)
            raise

    @staticmethod
    def cleanup(directory: str) -> None:
        if directory:
            shutil.rmtree(directory, ignore_errors=True)

    @staticmethod
    def _git_available() -> bool:
        return shutil.which("git") is not None

    @staticmethod
    def ensure_directory_exists(directory: str) -> Path:
        path = Path(directory)

        if not path.exists():
            raise RepositoryDownloadError(
                f"repository directory does not exist: {directory}"
            )

        if not path.is_dir():
            raise RepositoryDownloadError(
                f"repository path is not a directory: {directory}"
            )

        return path
