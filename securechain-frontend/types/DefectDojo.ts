export interface GenericFinding {
  title: string
  severity: string
  description: string

  mitigation?: string
  impact?: string
  references?: string | string[]
  cwe?: number

  active?: boolean
  verified?: boolean
  false_p?: boolean
  out_of_scope?: boolean
  risk_accepted?: boolean
  under_review?: boolean
  is_mitigated?: boolean
  mitigated?: boolean | string

  component_name?: string
  component_version?: string
  file_path?: string

  unique_id_from_tool?: string

  tags?: string[]
}

export interface GenericFindingsResponse {
  findings: GenericFinding[]
}

export interface GenerateGenericFindingsRequest {
  owner: string
  repository: string
}

export interface GenerateGenericFindingsResponse {
  document_id: string
  owner: string
  repository: string
  findings_count: number
  created_at: string
}

export interface GenericFindingsDocumentSummary {
  document_id: string
  repository_id: string

  findings_count: number

  created_at: string
  updated_at: string

  owner?: string | null
  repo?: string | null
  sbom_name?: string | null
}

export interface GenericFindingsDocument {
  document_id: string
  repository_id: string

  findings_count: number

  created_at: string
  updated_at: string

  owner?: string | null
  repo?: string | null
  sbom_name?: string | null

  findings: GenericFinding[]
}

export interface DefectDojoImportResponse {
  document_id: string
  import_status: string
  defectdojo_import_id?: string | null
  message: string
}

export interface DefectDojoImportRequest {
  product_name?: string
  engagement_name?: string
  test_title?: string
}
