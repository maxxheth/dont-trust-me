import https from 'node:https'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { AddressInfo } from 'node:net'

export interface FixtureServer {
  port: number
  /** Beacon hit count for parameter p (e.g. 'no-csp'). */
  hits(p: string): number
  reset(): void
  close(): Promise<void>
}

function makeCert(): { key: string; cert: string } {
  const dir = mkdtempSync(join(tmpdir(), 'dtm-cert-'))
  try {
    execFileSync(
      'openssl',
      [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'),
        '-days', '2', '-subj', '/CN=site.dtm.example',
        '-addext', 'subjectAltName=DNS:site.dtm.example,DNS:*.dtm.example,IP:127.0.0.1',
      ],
      { stdio: 'ignore' },
    )
    return { key: readFileSync(join(dir, 'key.pem'), 'utf8'), cert: readFileSync(join(dir, 'cert.pem'), 'utf8') }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

const page = (title: string, script: string, nonce?: string) =>
  `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body><h1 id="h">${title}</h1>` +
  `<script${nonce ? ` nonce="${nonce}"` : ''}>${script}</script></body></html>`

const BEACON_NO_CSP =
  "navigator.sendBeacon('/beacon?p=no-csp');fetch('/beacon?p=no-csp-fetch');"

export async function startFixtureServer(): Promise<FixtureServer> {
  const counts = new Map<string, number>()
  const { key, cert } = makeCert()

  const server = https.createServer({ key, cert }, (req, res) => {
    const url = new URL(req.url ?? '/', 'https://x')
    const html = (body: string, headers: Record<string, string> = {}) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...headers })
      res.end(body)
    }
    const beaconScript = (p: string) => `navigator.sendBeacon('/beacon?p=${p}');`
    switch (url.pathname) {
      case '/no-csp':
        return html(page('no-csp', BEACON_NO_CSP))
      case '/strict':
        return html(page('strict', beaconScript('strict'), 'abc123'), {
          'Content-Security-Policy':
            "default-src 'self'; script-src 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'none'; connect-src 'self'; frame-src 'none'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; report-to default",
          'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'strict-origin-when-cross-origin',
          'Permissions-Policy': 'camera=()',
          'Cross-Origin-Opener-Policy': 'same-origin',
        })
      case '/weak':
        return html(page('weak', beaconScript('weak')), {
          'Content-Security-Policy': "script-src 'self' cdn.optimizely.com 'unsafe-inline'",
        })
      case '/frame-ancestors-only':
        return html(page('frame-ancestors-only', beaconScript('frame-ancestors-only')), {
          'Content-Security-Policy': "frame-ancestors 'self'",
        })
      case '/report-only':
        return html(page('report-only', beaconScript('report-only')), {
          'Content-Security-Policy-Report-Only': "script-src 'self'",
        })
      case '/redirect':
        res.writeHead(301, { Location: '/strict' })
        return res.end()
      case '/download':
        res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename=x.txt' })
        return res.end('hello')
      case '/data.json':
        res.writeHead(200, { 'Content-Type': 'application/json' })
        return res.end('{"ok":true}')
      case '/beacon': {
        const p = url.searchParams.get('p') ?? ''
        counts.set(p, (counts.get(p) ?? 0) + 1)
        res.writeHead(204)
        return res.end()
      }
      default:
        res.writeHead(404, { 'Content-Type': 'text/plain' })
        return res.end('not found')
    }
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  return {
    port,
    hits: (p) => counts.get(p) ?? 0,
    reset: () => counts.clear(),
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections()
        server.close(() => resolve())
      }),
  }
}
