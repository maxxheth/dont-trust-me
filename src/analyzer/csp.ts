// Content-Security-Policy parser and per-policy checks. Pure, never throws.
import type { FindingId } from '../shared/types'
import { MAX_VALUE_LEN, truncate, type Hit } from './headers'

export interface CspPolicy {
  raw: string
  /** Lower-cased directive name -> source tokens (first occurrence wins). */
  directives: Map<string, string[]>
}

/** Parse one policy (no top-level commas). */
export function parsePolicy(text: string): CspPolicy {
  const directives = new Map<string, string[]>()
  for (const part of text.split(';')) {
    const tokens = part.trim().split(/[ \t\r\n\f]+/).filter(Boolean)
    const name = tokens.shift()?.toLowerCase()
    if (!name || !/^[a-z0-9-]+$/.test(name)) continue
    if (!directives.has(name)) directives.set(name, tokens)
  }
  return { raw: text, directives }
}

/**
 * Parse every policy found in a list of header values. Each header value may hold
 * several comma-joined policies; each is a separate enforced policy. Empty policies
 * (no directives) are dropped.
 */
export function parseCspValues(values: string[]): CspPolicy[] {
  const out: CspPolicy[] = []
  for (const v of values) {
    const s = typeof v === 'string' ? (v.length > MAX_VALUE_LEN ? v.slice(0, MAX_VALUE_LEN) : v) : ''
    for (const piece of s.split(',')) {
      const p = parsePolicy(piece)
      if (p.directives.size > 0) out.push(p)
    }
  }
  return out
}

// --- Fetch-directive fallbacks --------------------------------------------

export type FetchKind = 'script' | 'connect' | 'img' | 'frame' | 'object'

const CHAINS: Record<FetchKind, string[]> = {
  script: ['script-src-elem', 'script-src', 'default-src'],
  connect: ['connect-src', 'default-src'],
  img: ['img-src', 'default-src'],
  frame: ['frame-src', 'child-src', 'default-src'],
  object: ['object-src', 'default-src'],
}

export function effectiveDirective(
  policy: CspPolicy,
  kind: FetchKind,
): { name: string; sources: string[] } | undefined {
  for (const name of CHAINS[kind]) {
    const sources = policy.directives.get(name)
    if (sources) return { name, sources }
  }
  return undefined
}

export function governsScripts(policy: CspPolicy): boolean {
  return effectiveDirective(policy, 'script') !== undefined
}

export function hasScriptGoverningPolicy(policies: CspPolicy[]): boolean {
  return policies.some(governsScripts)
}

// --- Source list analysis -------------------------------------------------

export interface SourceInfo {
  none: boolean
  self: boolean
  wildcard: boolean
  unsafeInline: boolean
  unsafeEval: boolean
  wasmUnsafeEval: boolean
  strictDynamic: boolean
  nonces: number
  hashes: number
  /** Lower-case scheme sources such as "https:". */
  schemes: string[]
  /** Host sources (everything that is not a keyword, scheme or wildcard). */
  hosts: string[]
  hasNonceOrHash: boolean
  /** strict-dynamic together with a nonce/hash: host and scheme allowlists are ignored. */
  strictDynamicActive: boolean
  /** 'unsafe-inline' only counts when no nonce/hash/strict-dynamic is present. */
  effectiveUnsafeInline: boolean
}

const WILDCARD_RE = /^([a-z][a-z0-9+.-]*:\/\/)?\*(:(\*|\d+))?$/i
const SCHEME_RE = /^[a-z][a-z0-9+.-]*:$/i

export function analyzeSources(sources: string[]): SourceInfo {
  const info: SourceInfo = {
    none: sources.length === 0 || sources.every((t) => t.toLowerCase() === "'none'"),
    self: false,
    wildcard: false,
    unsafeInline: false,
    unsafeEval: false,
    wasmUnsafeEval: false,
    strictDynamic: false,
    nonces: 0,
    hashes: 0,
    schemes: [],
    hosts: [],
    hasNonceOrHash: false,
    strictDynamicActive: false,
    effectiveUnsafeInline: false,
  }
  for (const tok of sources) {
    const lower = tok.toLowerCase()
    if (lower.length >= 2 && lower.startsWith("'") && lower.endsWith("'")) {
      const k = lower.slice(1, -1)
      if (k === 'self') info.self = true
      else if (k === 'unsafe-inline') info.unsafeInline = true
      else if (k === 'unsafe-eval') info.unsafeEval = true
      else if (k === 'wasm-unsafe-eval') info.wasmUnsafeEval = true
      else if (k === 'strict-dynamic') info.strictDynamic = true
      else if (k.startsWith('nonce-')) info.nonces++
      else if (/^sha(256|384|512)-/.test(k)) info.hashes++
    } else if (WILDCARD_RE.test(tok)) {
      info.wildcard = true
    } else if (SCHEME_RE.test(tok)) {
      info.schemes.push(lower)
    } else {
      info.hosts.push(tok)
    }
  }
  info.hasNonceOrHash = info.nonces + info.hashes > 0
  info.strictDynamicActive = info.strictDynamic && info.hasNonceOrHash
  info.effectiveUnsafeInline = info.unsafeInline && !info.hasNonceOrHash && !info.strictDynamic
  return info
}

// --- Per-policy checks ----------------------------------------------------

export interface PolicyCheck {
  governsScripts: boolean
  /** Weaknesses of this policy (finding id -> evidence). */
  fails: Map<FindingId, string | undefined>
  strict: boolean
  trustedTypes: boolean
  frameAncestors: boolean
}

function show(dir: string, sources: string[]): string {
  return truncate(`${dir}: ${sources.join(' ')}`)
}

function unrestricted(info: SourceInfo): boolean {
  return !info.none && (info.wildcard || info.schemes.includes('http:') || info.schemes.includes('https:'))
}

export function checkPolicy(policy: CspPolicy): PolicyCheck {
  const fails = new Map<FindingId, string | undefined>()
  const d = policy.directives

  const script = effectiveDirective(policy, 'script')
  let strict = false
  if (script) {
    const s = analyzeSources(script.sources)
    if (!s.strictDynamicActive) {
      const bad = [...(s.wildcard ? ['*'] : []), ...s.schemes.filter((x) => ['http:', 'https:', 'data:'].includes(x))]
      if (bad.length) fails.set('C3', truncate(`${script.name}: ${bad.join(' ')}`))
    }
    if (s.effectiveUnsafeInline) fails.set('C4', `'unsafe-inline' in ${script.name}`)
    if (s.unsafeEval) fails.set('C5', `'unsafe-eval' in ${script.name}`)
    if (!s.strictDynamicActive && !s.hasNonceOrHash && s.hosts.length > 0) {
      fails.set('C6', truncate(`${script.name}: ${s.hosts.join(' ')}`))
    }
    strict = s.strictDynamicActive && s.hosts.length === 0
  }

  const obj = effectiveDirective(policy, 'object')
  if (!obj) fails.set('C7', 'object-src not set')
  else if (!analyzeSources(obj.sources).none) fails.set('C7', show(obj.name, obj.sources))

  if (!d.has('base-uri')) fails.set('C8', undefined)

  const loose = (kind: FetchKind, id: FindingId, label: string) => {
    const eff = effectiveDirective(policy, kind)
    if (!eff) fails.set(id, `${label} not set`)
    else if (unrestricted(analyzeSources(eff.sources))) fails.set(id, show(eff.name, eff.sources))
  }
  loose('connect', 'E1', 'connect-src')
  loose('frame', 'E2', 'frame-src')
  loose('img', 'E4', 'img-src')

  if (!d.has('form-action')) fails.set('E3', undefined)
  if (!d.has('report-to') && !d.has('report-uri')) fails.set('R1', undefined)

  const fa = d.get('frame-ancestors')
  return {
    governsScripts: script !== undefined,
    fails,
    strict,
    trustedTypes: (d.get('require-trusted-types-for') ?? []).some((t) => t.toLowerCase() === "'script'"),
    frameAncestors: fa !== undefined && !analyzeSources(fa).wildcard,
  }
}

export interface CspAnalysis {
  policyCount: number
  governsScripts: boolean
  hits: Hit[]
  bonuses: FindingId[]
  frameAncestors: boolean
}

const SCRIPT_CHECKS: FindingId[] = ['C3', 'C4', 'C5', 'C6']
const OTHER_CHECKS: FindingId[] = ['C7', 'C8', 'E1', 'E2', 'E3', 'E4', 'R1']

/**
 * Combine enforced policies. All policies are enforced simultaneously, so a weakness
 * only counts if EVERY relevant policy has it (the strictest policy wins).
 * Script checks consider only policies that govern scripts. With no policies at all
 * nothing is reported here (the caller reports C1).
 */
export function analyzeCsp(enforcedValues: string[]): CspAnalysis {
  const policies = parseCspValues(enforcedValues)
  const checks = policies.map(checkPolicy)
  const scriptChecks = checks.filter((c) => c.governsScripts)
  const hits: Hit[] = []

  if (checks.length > 0) {
    const everyFails = (set: PolicyCheck[], id: FindingId): boolean =>
      set.length > 0 && set.every((c) => c.fails.has(id))
    for (const id of SCRIPT_CHECKS) {
      if (everyFails(scriptChecks, id)) hits.push({ id, evidence: scriptChecks[0]!.fails.get(id) })
    }
    for (const id of OTHER_CHECKS) {
      if (everyFails(checks, id)) hits.push({ id, evidence: checks[0]!.fails.get(id) })
    }
  }

  const bonuses: FindingId[] = []
  if (checks.some((c) => c.strict)) bonuses.push('B1')
  if (checks.some((c) => c.trustedTypes)) bonuses.push('B2')

  return {
    policyCount: checks.length,
    governsScripts: scriptChecks.length > 0,
    hits,
    bonuses,
    frameAncestors: checks.some((c) => c.frameAncestors),
  }
}
