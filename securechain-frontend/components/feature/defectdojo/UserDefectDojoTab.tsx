'use client'

import { useEffect, useState } from 'react'
import { Button, Card } from '@/components/ui'
import { useDefectDojo } from '@/hooks/api/useDefectDojo'
import { ExternalLink, Upload } from 'lucide-react'

export const UserDefectDojoTab = () => {
  const [productName, setProductName] = useState('SecureChain')
  const [engagementName, setEngagementName] = useState('SecureChain Generic Findings')
  const [testTitle, setTestTitle] = useState('SecureChain Generic Findings')

  const {
    documents,
    selectedDocument,
    isLoading,
    error,
    fetchDocuments,
    fetchDocument,
    importToDojo,
  } = useDefectDojo()

  useEffect(() => {
    void fetchDocuments()
  }, [fetchDocuments])

  const handleImport = async () => {
    if (!selectedDocument?.document_id) {
      return
    }

    await importToDojo(selectedDocument.document_id, {
      product_name: productName,
      engagement_name: engagementName,
      test_title: testTitle,
    })
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-2 md:grid-cols-3">
        <input
          value={productName}
          onChange={event => setProductName(event.target.value)}
          placeholder="Product name"
          className="border rounded-md px-3 py-2 text-sm bg-background"
        />

        <input
          value={engagementName}
          onChange={event => setEngagementName(event.target.value)}
          placeholder="Engagement name"
          className="border rounded-md px-3 py-2 text-sm bg-background"
        />

        <input
          value={testTitle}
          onChange={event => setTestTitle(event.target.value)}
          placeholder="Test title"
          className="border rounded-md px-3 py-2 text-sm bg-background"
        />
      </div>

      <div className="flex gap-2">
        <Button
          onClick={handleImport}
          disabled={isLoading || !selectedDocument}
        >
          <Upload className="w-4 h-4 mr-2" />
          Export to DefectDojo
        </Button>

        <a
          href="http://localhost:8080"
          target="_blank"
          rel="noopener noreferrer"
        >
          <Button variant="outline">
            <ExternalLink className="w-4 h-4 mr-2" />
            Open DefectDojo
          </Button>
        </a>
      </div>

      {isLoading && <p>Loading documents...</p>}

      {error && <p className="text-red-500">{error}</p>}

      {!isLoading && documents.length === 0 && (
        <p className="text-muted-foreground">No Generic Findings documents available</p>
      )}

      <div className="grid gap-3">
        {documents.map(document => (
          <Card
            key={document.document_id}
            className="p-3 cursor-pointer hover:bg-muted/50"
            onClick={() => void fetchDocument(document.document_id)}
          >
            <div className="font-semibold">
              {document.owner}/{document.repo}
            </div>
            <div className="text-sm text-muted-foreground">
              Findings: {document.findings_count}
            </div>
            <div className="text-xs mt-2">
              Document ID: {document.document_id}
            </div>
          </Card>
        ))}
      </div>

      {selectedDocument && (
        <div className="space-y-3">
          <h3 className="font-semibold">
            Findings for {selectedDocument.owner}/{selectedDocument.repo}
          </h3>

          {selectedDocument.findings.map((finding, index) => (
            <Card key={finding.unique_id_from_tool ?? index} className="p-3">
              <div className="font-semibold">{finding.title}</div>
              <div className="text-sm text-muted-foreground">
                Severity: {finding.severity}
              </div>
              <div className="text-xs mt-2">{finding.description}</div>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
