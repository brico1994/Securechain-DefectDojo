from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from pymongo import MongoClient

from app.apis.defectdojo_client import DefectDojoClient
from app.domain.generic_findings.artifact_provider import ArtifactProvider
from app.domain.generic_findings.repository import GenericFindingsRepository
from app.services.generic_findings_service import GenericFindingsService

_MONGO_URI_ENV = "MONGODB_URI"
_MONGO_DB_ENV = "MONGODB_DB_NAME"
_MONGO_COLLECTION_ENV = "MONGODB_GENERIC_FINDINGS_COLLECTION"

_DEFAULT_DB_NAME = "securechain"
_DEFAULT_COLLECTION_NAME = "generic_findings"


@lru_cache(maxsize=1)
def get_mongo_client() -> Optional[MongoClient]:
    mongo_uri = os.getenv(_MONGO_URI_ENV)
    if not mongo_uri:
        return None
    return MongoClient(mongo_uri)


def get_repository() -> Optional[GenericFindingsRepository]:
    client = get_mongo_client()
    if client is None:
        return None

    db_name = os.getenv(_MONGO_DB_ENV, _DEFAULT_DB_NAME)
    collection_name = os.getenv(_MONGO_COLLECTION_ENV, _DEFAULT_COLLECTION_NAME)

    collection = client[db_name][collection_name]
    return GenericFindingsRepository(collection=collection)


def get_artifact_provider() -> ArtifactProvider:
    # Stub controlado: /generate devolverá 501 hasta implementar obtención real SBOM/VEX/TIX.
    return ArtifactProvider()


def get_defectdojo_client() -> DefectDojoClient:
    # Lee DEFECTDOJO_* desde entorno dentro del cliente.
    return DefectDojoClient()


def get_service() -> GenericFindingsService:
    repository = get_repository()

    return GenericFindingsService(
        repository=repository,
        artifact_provider=get_artifact_provider(),
        defectdojo_client=get_defectdojo_client(),
    )
