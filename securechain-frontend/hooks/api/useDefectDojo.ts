'use client'

import { useCallback, useState } from 'react'

import { defectdojoAPI } from '@/lib/api/apiClient'
import { useToast } from '@/hooks/ui/useToast'
import type {
  DefectDojoImportRequest,
  DefectDojoImportResponse,
  GenerateGenericFindingsResponse,
  GenericFindingsDocument,
  GenericFindingsDocumentSummary,
} from '@/types/DefectDojo'

type OperationStatus = 'idle' | 'loading' | 'success' | 'error'

interface UseDefectDojoState {
  documents: GenericFindingsDocumentSummary[]
  selectedDocument: GenericFindingsDocument | null
  lastGeneratedDocument: GenerateGenericFindingsResponse | null
  lastImportResult: DefectDojoImportResponse | null
  status: OperationStatus
  error: string | null
}

function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) {
    return error.message
  }

  return fallback
}

export function useDefectDojo() {
  const { toast } = useToast()

  const [state, setState] = useState<UseDefectDojoState>({
    documents: [],
    selectedDocument: null,
    lastGeneratedDocument: null,
    lastImportResult: null,
    status: 'idle',
    error: null,
  })

  const setLoading = useCallback(() => {
    setState(prev => ({
      ...prev,
      status: 'loading',
      error: null,
    }))
  }, [])

  const setError = useCallback((message: string) => {
    setState(prev => ({
      ...prev,
      status: 'error',
      error: message,
    }))

    toast({
      title: 'DefectDojo operation failed',
      description: message,
      variant: 'destructive',
    })
  }, [toast])

  const generateFindings = useCallback(
    async (owner: string, repo: string): Promise<GenerateGenericFindingsResponse | null> => {
      const normalizedOwner = owner.trim()
      const normalizedRepo = repo.trim()

      if (!normalizedOwner || !normalizedRepo) {
        const message = 'Owner and repository are required'
        setError(message)
        return null
      }

      setLoading()

      try {
        const response = await defectdojoAPI.generateFromRepo(normalizedOwner, normalizedRepo)
        const generated = response.data as GenerateGenericFindingsResponse

        setState(prev => ({
          ...prev,
          lastGeneratedDocument: generated,
          status: 'success',
          error: null,
        }))

        toast({
          title: 'Generic Findings generated',
          description: `Document ${generated.document_id} created successfully.`,
        })

        return generated
      } catch (error) {
        setError(getErrorMessage(error, 'Failed to generate Generic Findings'))
        return null
      }
    },
    [setError, setLoading, toast],
  )

  const fetchDocuments = useCallback(async (): Promise<GenericFindingsDocumentSummary[]> => {
    setLoading()

    try {
      const response = await defectdojoAPI.listDocuments()
      const documents = response.data as GenericFindingsDocumentSummary[]

      setState(prev => ({
        ...prev,
        documents,
        status: 'success',
        error: null,
      }))

      return documents
    } catch (error) {
      setError(getErrorMessage(error, 'Failed to fetch Generic Findings documents'))
      return []
    }
  }, [setError, setLoading])

  const fetchDocument = useCallback(
    async (documentId: string): Promise<GenericFindingsDocument | null> => {
      if (!documentId.trim()) {
        const message = 'Document id is required'
        setError(message)
        return null
      }

      setLoading()

      try {
        const response = await defectdojoAPI.getDocument(documentId)
        const document = response.data as GenericFindingsDocument

        setState(prev => ({
          ...prev,
          selectedDocument: document,
          status: 'success',
          error: null,
        }))

        return document
      } catch (error) {
        setError(getErrorMessage(error, 'Failed to fetch Generic Findings document'))
        return null
      }
    },
    [setError, setLoading],
  )

  const importToDojo = useCallback(
    async (
      documentId: string,
      payload?: DefectDojoImportRequest,
    ): Promise<DefectDojoImportResponse | null>=> {
      if (!documentId.trim()) {
        const message = 'Document id is required'
        setError(message)
        return null
      }

      setLoading()

      try {
        const response = await defectdojoAPI.importToDojo(documentId, payload)
        const result = response.data as DefectDojoImportResponse

        setState(prev => ({
          ...prev,
          lastImportResult: result,
          status: 'success',
          error: null,
        }))

        toast({
          title: 'Imported to DefectDojo',
          description: result.message || 'Generic Findings imported successfully.',
        })

        return result
      } catch (error) {
        setError(getErrorMessage(error, 'Failed to import Generic Findings to DefectDojo'))
        return null
      }
    },
    [setError, setLoading, toast],
  )

  const resetDefectDojoState = useCallback(() => {
    setState({
      documents: [],
      selectedDocument: null,
      lastGeneratedDocument: null,
      lastImportResult: null,
      status: 'idle',
      error: null,
    })
  }, [])

  return {
    documents: state.documents,
    selectedDocument: state.selectedDocument,
    lastGeneratedDocument: state.lastGeneratedDocument,
    lastImportResult: state.lastImportResult,
    status: state.status,
    error: state.error,
    isLoading: state.status === 'loading',

    generateFindings,
    fetchDocuments,
    fetchDocument,
    importToDojo,
    resetDefectDojoState,
  }
}
