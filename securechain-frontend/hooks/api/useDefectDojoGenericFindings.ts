import { defectdojoAPI } from '@/lib/api/apiClient'
import type {
  DefectDojoImportResponse,
  GenerateGenericFindingsRequest,
  GenerateGenericFindingsResponse,
  GenericFindingsDocument,
  GenericFindingsDocumentSummary,
} from '@/types/DefectDojo'

export function useDefectDojoGenericFindings() {
  async function generateFromRepo(
    payload: GenerateGenericFindingsRequest,
  ): Promise<GenerateGenericFindingsResponse> {
    const response = await defectdojoAPI.generateFromRepo(
      payload.owner,
      payload.repository,
    )

    return response.data as GenerateGenericFindingsResponse
  }

  async function listDocuments(): Promise<GenericFindingsDocumentSummary[]> {
    const response = await defectdojoAPI.listDocuments()

    return response.data as GenericFindingsDocumentSummary[]
  }

  async function getDocument(documentId: string): Promise<GenericFindingsDocument> {
    const response = await defectdojoAPI.getDocument(documentId)

    return response.data as GenericFindingsDocument
  }

  async function importDocument(
    documentId: string,
  ): Promise<DefectDojoImportResponse> {
    const response = await defectdojoAPI.importToDojo(documentId)

    return response.data as DefectDojoImportResponse
  }

  return {
    generateFromRepo,
    listDocuments,
    getDocument,
    importDocument,
  }
}
