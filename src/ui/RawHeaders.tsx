import type { HttpHeader } from '../shared/types'

export function RawHeaders({ headers }: { headers: HttpHeader[] }) {
  return (
    <details className="raw-headers">
      <summary>Raw headers ({headers.length})</summary>
      <pre>{headers.length ? headers.map((h) => `${h.name}: ${h.value ?? ''}`).join('\n') : '(none)'}</pre>
    </details>
  )
}
