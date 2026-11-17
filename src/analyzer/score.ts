// Combines CSP and header checks into a Report. Pure and synchronous; never throws.
import type { AnalyzeInput, Finding, FindingId, HttpHeader, Report, Verdict } from '../shared/types'
import { analyzeCsp } from './csp'
import { CATALOG, FINDING_ORDER } from './findings'
import { checkHeaders, getHeaderValues, redactedCookieHeaders, truncate, type Hit, MAX_VALUE_LEN } from './headers'
import { BASE_SCORE, HARD_FAIL_IDS, HARD_FAIL_SCORE_CAP, WEIGHTS, gradeFor } from './policy'

const KEPT_HEADERS = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'server',
  'x-powered-by',
  'x-xss-protection',
  'content-type',
  'location',
])

export function makeFinding(id: FindingId, evidence?: string): Finding {
  const c = CATALOG[id]
  const f: Finding = {
    id,
    severity: c.severity,
    category: c.category,
    title: c.title,
    why: c.why,
    fix: c.fix,
    points: WEIGHTS[id],
    mdn: c.mdn,
  }
  if (evidence) f.evidence = truncate(evidence)
  return f
}

function safeHeaders(headers: unknown): HttpHeader[] {
  const out: HttpHeader[] = []
  if (!Array.isArray(headers)) return out
  for (const h of headers) {
    if (!h || typeof h !== 'object') continue
    const name = (h as HttpHeader).name
    if (typeof name !== 'string') continue
    const lower = name.trim().toLowerCase()
    const value = (h as HttpHeader).value
    if (lower === 'set-cookie') {
      for (const v of redactedCookieHeaders([typeof value === 'string' ? value : ''])) {
        out.push({ name, value: v })
      }
    } else if (KEPT_HEADERS.has(lower)) {
      const entry: HttpHeader = { name }
      if (typeof value === 'string') entry.value = value.length > MAX_VALUE_LEN ? value.slice(0, MAX_VALUE_LEN) : value
      out.push(entry)
    }
  }
  return out
}

function parseHost(url: string): { host: string; https: boolean } {
  try {
    const u = new URL(url)
    return { host: u.hostname.toLowerCase(), https: u.protocol === 'https:' }
  } catch {
    return { host: '', https: false }
  }
}

function analyzeUnsafe(input: AnalyzeInput, now: number): Report {
  const url = typeof input?.url === 'string' ? input.url : String(input?.url ?? '')
  const { host, https } = parseHost(url)
  const headers = input?.headers
  const statusCode = Number(input?.statusCode) || 0

  const hits: Hit[] = []
  if (!https) hits.push({ id: 'T1', evidence: truncate(url.split(':')[0] ? `${url.split(':')[0]}:` : 'unknown scheme') })

  const csp = analyzeCsp(getHeaderValues(headers, 'content-security-policy'))
  if (!csp.governsScripts) hits.push({ id: 'C1' })
  hits.push(...csp.hits)

  const ro = getHeaderValues(headers, 'content-security-policy-report-only')
  if (ro.length) hits.push({ id: 'I1', evidence: truncate(ro[0]!) })

  const hdr = checkHeaders(headers, https)
  if (!csp.frameAncestors && !hdr.xfoProtected) hits.push({ id: 'H1' })
  hits.push(...hdr.hits)
  for (const id of csp.bonuses) hits.push({ id })

  const order = new Map(FINDING_ORDER.map((id, i) => [id, i]))
  hits.sort((a, b) => (order.get(a.id) ?? 0) - (order.get(b.id) ?? 0))
  const findings = hits.map((h) => makeFinding(h.id, h.evidence))

  const hardFail = findings.some((f) => HARD_FAIL_IDS.includes(f.id))
  let score = BASE_SCORE
  let bonus = 0
  for (const f of findings) {
    if (HARD_FAIL_IDS.includes(f.id)) continue
    score += f.points
    if (f.points > 0) bonus += f.points
  }
  score = Math.max(0, Math.min(BASE_SCORE + bonus, Math.round(score)))
  if (hardFail) score = Math.min(score, HARD_FAIL_SCORE_CAP)
  const grade = hardFail ? 'F' : gradeFor(score)

  let verdict: Exclude<Verdict, 'unverified'>
  if (hardFail) verdict = 'not-secure'
  else if (findings.some((f) => f.id === 'C3' || f.id === 'C4') || grade === 'D' || grade === 'F') verdict = 'weak'
  else if (grade === 'B' || grade === 'C') verdict = 'partial'
  else verdict = 'secure'

  return {
    url,
    host,
    statusCode,
    analyzedAt: now,
    score,
    grade,
    verdict,
    hardFail,
    findings,
    headers: safeHeaders(headers),
  }
}

export function analyze(input: AnalyzeInput, now: number = Date.now()): Report {
  try {
    return analyzeUnsafe(input, now)
  } catch {
    // Defensive: should be unreachable. Zero-trust: fail closed (treat as Not Secure) rather than throw.
    let url = ''
    try {
      url = String(input?.url ?? '')
    } catch {
      /* ignore */
    }
    return {
      url,
      host: parseHost(url).host,
      statusCode: 0,
      analyzedAt: now,
      score: 0,
      grade: 'F',
      verdict: 'not-secure',
      hardFail: true,
      findings: [],
      headers: [],
    }
  }
}
