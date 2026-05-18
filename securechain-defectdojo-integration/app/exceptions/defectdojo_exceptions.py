from __future__ import annotations


class DocumentNotFoundError(Exception):
    """
    Raised when a Generic Findings document is not found.
    """

    def __init__(self, document_id: str):
        super().__init__(f"generic findings document not found: {document_id}")
        self.document_id = document_id


class InvalidGenericFindingsPayload(Exception):
    """
    Raised when the payload does not comply with DefectDojo Generic Findings format.
    """

    def __init__(self, message: str):
        super().__init__(message)


class DefectDojoNotConfigured(Exception):
    """
    Raised when DefectDojo integration is not properly configured.
    """

    def __init__(self, message: str = "DefectDojo is not configured"):
        super().__init__(message)


class DefectDojoImportError(Exception):
    """
    Raised when DefectDojo returns an error during import.
    """

    def __init__(self, message: str = "DefectDojo import failed"):
        super().__init__(message)
