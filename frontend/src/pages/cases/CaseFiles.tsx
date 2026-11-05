import { Download, Paperclip, Trash2, Upload } from "lucide-react"
import { useRef } from "react"
import { toast } from "sonner"

import type { Case } from "@/api/client"
import { useAttachFile, useDownloadAttachment, useRemoveAttachment } from "@/api/queries"
import { useUser } from "@/auth/context"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { formatDateTime, formatRelative } from "@/lib/format"

const MAX_MB = 8

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/** Evidence kept with the case: emails, screenshots, logs. */
export function CaseFiles({ item }: { item: Case }) {
  const me = useUser()
  const input = useRef<HTMLInputElement>(null)
  const attach = useAttachFile(item.id)
  const download = useDownloadAttachment(item.id)
  const remove = useRemoveAttachment(item.id)
  const files = item.attachments ?? []

  function upload(file: File | undefined) {
    if (!file) return
    if (file.size > MAX_MB * 1024 * 1024) {
      toast.error(`Files can be at most ${MAX_MB} MB`)
      return
    }
    attach.mutate(file, {
      onSuccess: (added) => toast.success(`Attached ${added.name}`),
      onError: (error) => toast.error(error.message),
      onSettled: () => {
        if (input.current) input.current.value = ""
      },
    })
  }

  return (
    <Card
      title="Files"
      description="Evidence kept with the case. Each file's SHA-256 shows it has not changed; files are always downloaded, never opened here."
    >
      {files.length > 0 && (
        <ul className="mb-3 divide-y divide-border" aria-label="Files">
          {files.map((file) => (
            <li key={file.id} className="flex items-center gap-2 py-2 text-sm">
              <Paperclip className="size-4 shrink-0 text-muted" aria-hidden />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium">{file.name}</span>
                <span className="block truncate text-xs text-muted" title={`SHA-256 ${file.sha256}`}>
                  {size(file.size)} · {String(file.uploaded_by?.name ?? "someone")} ·{" "}
                  <span title={formatDateTime(file.uploaded_at)}>{formatRelative(file.uploaded_at)}</span>
                </span>
              </span>
              <Button
                size="sm"
                variant="ghost"
                aria-label={`Download ${file.name}`}
                onClick={() => download.mutate({ id: file.id, name: file.name }, { onError: (error) => toast.error(error.message) })}
              >
                <Download className="size-3.5" aria-hidden />
              </Button>
              {(me.role === "admin" || file.uploaded_by?.id === me.id) && (
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label={`Remove ${file.name}`}
                  disabled={remove.isPending}
                  onClick={() => remove.mutate(file.id, { onError: (error) => toast.error(error.message) })}
                >
                  <Trash2 className="size-3.5" aria-hidden />
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      <input ref={input} type="file" className="sr-only" aria-label="File to attach" onChange={(event) => upload(event.target.files?.[0])} />
      <Button size="sm" loading={attach.isPending} onClick={() => input.current?.click()}>
        <Upload className="size-3.5" aria-hidden /> Attach a file
      </Button>
    </Card>
  )
}
