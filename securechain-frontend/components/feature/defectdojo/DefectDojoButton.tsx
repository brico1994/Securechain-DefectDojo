'use client'

import { Button } from '@/components/ui'
import { useDefectDojo } from '@/hooks/api/useDefectDojo'

interface DefectDojoButtonProps {
  owner: string
  repo: string
  size?: 'default' | 'sm' | 'lg' | 'icon'
  variant?: 'default' | 'outline' | 'secondary' | 'ghost' | 'link' | 'destructive'
}

export function DefectDojoButton({
  owner,
  repo,
  size = 'sm',
  variant = 'outline',
}: DefectDojoButtonProps) {
  const { generateFindings, isLoading } = useDefectDojo()

  const handleGenerate = async () => {
    await generateFindings(owner, repo)
  }

  return (
    <Button
      type="button"
      size={size}
      variant={variant}
      onClick={handleGenerate}
      disabled={isLoading || !owner || !repo}
    >
      {isLoading ? 'Generating...' : 'Generate Generic Findings'}
    </Button>
  )
}
