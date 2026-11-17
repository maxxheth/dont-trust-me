// Non-CSP header checks. Pure TypeScript, never throws on malformed input.
import type { FindingId, HttpHeader } from '../shared/types'

export interface Hit {
  id: FindingId
  evidence?: string
}

export const MAX_EVIDENCE = 200
/** Header values longer than this are truncated before parsing. */
export const MAX_VALUE_LEN = 65536

export function truncate(s: string, max: number = MAX_EVIDENCE): string {
  return s.length > max ? s.slice(0, max) + '…' : s
}

/** All values of a header (case-insensitive name). A header with no value yields ''. */
export function getHeaderValues(headers: unknown, name: string): string[] {
  if (!Array.isArray(headers)) return []
  const out: string[] = []
  for (const h of headers) {
    if (!h || typeof h !== 'object') continue
    const n = (h as HttpHeader).name
    if (typeof n !== 'string' || n.trim().toLowerCase() !== name) continue
    const v = (h as HttpHeader).value
    const s = typeof v === 'string' ? v : ''
    out.push(s.length > MAX_VALUE_LEN ? s.slice(0, MAX_VALUE_LEN) : s)
  }
  return out
}

// --- HSTS -----------------------------------------------------------------

export interface Hsts {
  maxAge?: number
  includeSubDomains: boolean
  preload: boolean
}

export function parseHsts(value: string): Hsts {
  const out: Hsts = { includeSubDomains: false, preload: false }
  for (const part of value.split(';')) {
    const p = part.trim().toLowerCase()
    if (p === 'includesubdomains') out.includeSubDomains = true
    else if (p === 'preload') out.preload = true
    else if (out.maxAge === undefined) {
      const m = /^max-age\s*=\s*"?(\d{1,15})"?$/.exec(p)
      if (m) out.maxAge = Number(m[1])
    }
  }
  return out
}

export const ONE_YEAR = 31536000

// --- Referrer-Policy ------------------------------------------------------

const REFERRER_TOKENS = new Set([
  'no-referrer',
  'no-referrer-when-downgrade',
  'origin',
  'origin-when-cross-origin',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
  'unsafe-url',
])

/** Last valid token across all Referrer-Policy headers wins (browser behaviour). */
export function effectiveReferrerPolicy(values: string[]): string | undefined {
  let result: string | undefined
  for (const v of values) {
    for (const tok of v.split(',')) {
      const t = tok.trim().toLowerCase()
      if (REFERRER_TOKENS.has(t)) result = t
    }
  }
  return result
}

// --- Cookies --------------------------------------------------------------

export interface Cookie {
  name: string
  secure: boolean
  httpOnly: boolean
}

function splitCookieLines(values: string[]): string[] {
  const lines: string[] = []
  for (const v of values) for (const l of v.split(/\r?\n/)) if (l.trim()) lines.push(l)
  return lines
}

export function parseCookie(line: string): Cookie {
  const parts = line.split(';')
  const first = parts[0] ?? ''
  const eq = first.indexOf('=')
  const rawName = eq < 0 ? '' : first.slice(0, eq).trim()
  let secure = false
  let httpOnly = false
  for (let i = 1; i < parts.length; i++) {
    const attr = (parts[i] ?? '').split('=')[0]!.trim().toLowerCase()
    if (attr === 'secure') secure = true
    else if (attr === 'httponly') httpOnly = true
  }
  return { name: truncate(rawName || '(unnamed)', 60), secure, httpOnly }
}

/** Replace the cookie value with "…", keep attributes. */
export function redactSetCookie(line: string): string {
  const parts = line.split(';')
  const first = parts[0] ?? ''
  const eq = first.indexOf('=')
  const name = eq < 0 ? '' : first.slice(0, eq).trim()
  const rest = parts.slice(1).map((p) => p.trim()).filter(Boolean)
  return truncate([`${truncate(name, 60)}=…`, ...rest].join('; '), 300)
}

export function redactedCookieHeaders(values: string[]): string[] {
  return splitCookieLines(values).map(redactSetCookie)
}

function nameList(names: string[]): string {
  const uniq = [...new Set(names)]
  const shown = uniq.slice(0, 10).join(', ')
  return truncate(uniq.length > 10 ? `${shown}, +${uniq.length - 10} more` : shown)
}

// --- Main -----------------------------------------------------------------

export interface HeaderResult {
  hits: Hit[]
  /** True when X-Frame-Options is DENY or SAMEORIGIN. */
  xfoProtected: boolean
}

export function checkHeaders(headers: unknown, https: boolean): HeaderResult {
  const hits: Hit[] = []

  // HSTS (first header wins). Only meaningful on https.
  if (https) {
    const hstsValues = getHeaderValues(headers, 'strict-transport-security')
    const hsts = hstsValues.length ? parseHsts(hstsValues[0]!) : undefined
    if (!hsts || !hsts.maxAge) {
      hits.push({ id: 'H2', evidence: hsts ? truncate(`Ignored: ${hstsValues[0]}`) : undefined })
    } else {
      if (hsts.maxAge < ONE_YEAR) hits.push({ id: 'H3', evidence: `max-age=${hsts.maxAge}` })
      if (hsts.includeSubDomains && hsts.preload && hsts.maxAge >= ONE_YEAR) hits.push({ id: 'B3' })
    }
  }

  // X-Frame-Options
  const xfo = getHeaderValues(headers, 'x-frame-options')
  const xfoValue = (xfo[0] ?? '').split(',')[0]!.trim().toLowerCase()
  const xfoProtected = xfoValue === 'deny' || xfoValue === 'sameorigin'

  // X-Content-Type-Options
  const xcto = getHeaderValues(headers, 'x-content-type-options')
  if (!xcto.some((v) => v.split(',').some((t) => t.trim().toLowerCase() === 'nosniff'))) {
    hits.push({ id: 'H4', evidence: xcto.length ? truncate(xcto[0]!) : undefined })
  }

  // Referrer-Policy
  const rp = effectiveReferrerPolicy(getHeaderValues(headers, 'referrer-policy'))
  if (rp === undefined) hits.push({ id: 'H5', evidence: 'missing' })
  else if (rp === 'unsafe-url' || rp === 'no-referrer-when-downgrade') hits.push({ id: 'H5', evidence: rp })

  // Permissions-Policy
  const pp = getHeaderValues(headers, 'permissions-policy')
  if (!pp.some((v) => v.trim().length > 0)) hits.push({ id: 'H6' })

  // COOP
  const coop = getHeaderValues(headers, 'cross-origin-opener-policy')
  const coopValue = (coop[0] ?? '').split(';')[0]!.trim().toLowerCase()
  if (!['same-origin', 'same-origin-allow-popups', 'noopener-allow-popups'].includes(coopValue)) {
    hits.push({ id: 'H7', evidence: coop.length ? truncate(coop[0]!) : undefined })
  }

  // Cookies
  const cookies = splitCookieLines(getHeaderValues(headers, 'set-cookie')).map(parseCookie)
  if (https) {
    const noSecure = cookies.filter((c) => !c.secure).map((c) => c.name)
    if (noSecure.length) hits.push({ id: 'K1', evidence: nameList(noSecure) })
  }
  const noHttpOnly = cookies.filter((c) => !c.httpOnly).map((c) => c.name)
  if (noHttpOnly.length) hits.push({ id: 'K2', evidence: nameList(noHttpOnly) })

  // Info: CORP / COEP
  const corp = getHeaderValues(headers, 'cross-origin-resource-policy')
  const coep = getHeaderValues(headers, 'cross-origin-embedder-policy')
  if (corp.length || coep.length) {
    const bits: string[] = []
    if (corp.length) bits.push(`CORP: ${truncate(corp[0]!, 60)}`)
    if (coep.length) bits.push(`COEP: ${truncate(coep[0]!, 60)}`)
    hits.push({ id: 'I2', evidence: bits.join('; ') })
  }

  // Info: server / framework disclosure (Server only when it carries a version)
  const server = getHeaderValues(headers, 'server')[0]
  const powered = getHeaderValues(headers, 'x-powered-by')[0]
  const disclosure: string[] = []
  if (server && /\d/.test(server)) disclosure.push(`Server: ${truncate(server, 80)}`)
  if (powered) disclosure.push(`X-Powered-By: ${truncate(powered, 80)}`)
  if (disclosure.length) hits.push({ id: 'I3', evidence: disclosure.join('; ') })

  // Info: X-XSS-Protection
  const xxp = getHeaderValues(headers, 'x-xss-protection')
  if (xxp.length) hits.push({ id: 'I4', evidence: truncate(xxp[0]!, 60) })

  return { hits, xfoProtected }
}
