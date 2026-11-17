// Shared data contracts. Every module (analyzer, background, UI, content) imports
// from here; change these deliberately, since all components depend on them.

export type Verdict = 'not-secure' | 'weak' | 'partial' | 'secure' | 'unverified'

export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'bonus'

export type FindingCategory =
  | 'script-control'
  | 'exfiltration'
  | 'framing'
  | 'transport'
  | 'cookies'
  | 'other'

/** Catalogue IDs from plans/dont-trust-me-extension.md §3.2, plus bonuses and info. */
export type FindingId =
  | 'T1' | 'C1' | 'C3' | 'C4' | 'C5' | 'C6' | 'C7' | 'C8'
  | 'E1' | 'E2' | 'E3' | 'E4' | 'R1'
  | 'H1' | 'H2' | 'H3' | 'H4' | 'H5' | 'H6' | 'H7'
  | 'K1' | 'K2'
  | 'B1' // bonus: strict CSP
  | 'B2' // bonus: Trusted Types
  | 'B3' // bonus: HSTS includeSubDomains; preload
  | 'I1' // info: CSP Report-Only present (not enforced)
  | 'I2' // info: CORP / COEP status
  | 'I3' // info: server/framework disclosure
  | 'I4' // info: deprecated X-XSS-Protection

export interface Finding {
  id: FindingId
  severity: Severity
  category: FindingCategory
  title: string
  /** Plain-language explanation for users. */
  why: string
  /** What a site owner should change. */
  fix: string
  /** Negative for penalties, positive for bonuses, 0 for info. */
  points: number
  /** Optional evidence, e.g. offending source expression or cookie names. Untrusted text. */
  evidence?: string
  mdn?: string
}

export interface HttpHeader {
  name: string
  value?: string
}

export interface AnalyzeInput {
  url: string
  statusCode: number
  headers: HttpHeader[]
}

export interface Report {
  url: string
  host: string
  statusCode: number
  analyzedAt: number
  score: number
  grade: Grade
  verdict: Exclude<Verdict, 'unverified'>
  /** True when a hard-fail finding (T1 or C1) is present. */
  hardFail: boolean
  findings: Finding[]
  /** Raw headers as received (security-relevant subset is fine). Untrusted text. */
  headers: HttpHeader[]
}

/** Per-tab state kept by the background in storage.session. */
export interface TabState {
  tabId: number
  url: string
  verdict: Verdict
  report?: Report
  /** Set when the gate redirected this tab to the interstitial. */
  blockedUrl?: string
  /** Set when the user chose to proceed for this tab. */
  bypass?: 'unsafe' | 'no-js'
}
