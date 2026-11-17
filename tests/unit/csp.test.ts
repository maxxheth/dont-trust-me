import { describe, expect, it } from 'vitest'
import { analyzeCsp, analyzeSources, effectiveDirective, parseCspValues, parsePolicy } from '../../src/analyzer/csp'

const eff = (csp: string, kind: Parameters<typeof effectiveDirective>[1]) =>
  effectiveDirective(parsePolicy(csp), kind)?.name

describe('parsePolicy', () => {
  it('is case-insensitive on names and first duplicate wins', () => {
    const p = parsePolicy("SCRIPT-SRC 'self'; script-src *; Img-Src data:")
    expect(p.directives.get('script-src')).toEqual(["'self'"])
    expect(p.directives.get('img-src')).toEqual(['data:'])
  })
  it('ignores junk', () => {
    expect(parsePolicy(';;; ===').directives.size).toBe(0)
  })
})

describe('parseCspValues', () => {
  it('splits comma-joined policies and multiple headers', () => {
    const ps = parseCspValues(["script-src 'self', default-src 'none'", "object-src 'none'", ''])
    expect(ps).toHaveLength(3)
  })
})

describe('effective directive fallbacks', () => {
  it('script chain', () => {
    expect(eff("script-src-elem 'self'; script-src *; default-src 'none'", 'script')).toBe('script-src-elem')
    expect(eff("script-src *; default-src 'none'", 'script')).toBe('script-src')
    expect(eff("default-src 'none'", 'script')).toBe('default-src')
    expect(eff('img-src *', 'script')).toBeUndefined()
  })
  it('connect/img', () => {
    expect(eff("connect-src 'self'; default-src *", 'connect')).toBe('connect-src')
    expect(eff('default-src *', 'img')).toBe('default-src')
  })
  it('frame chain', () => {
    expect(eff("frame-src 'none'; child-src *; default-src *", 'frame')).toBe('frame-src')
    expect(eff("child-src 'none'; default-src *", 'frame')).toBe('child-src')
    expect(eff('default-src *', 'frame')).toBe('default-src')
  })
})

describe('analyzeSources', () => {
  it('detects keywords, nonce, hash, schemes, hosts', () => {
    const s = analyzeSources(["'Self'", "'nonce-abc'", "'sha256-xyz='", "'strict-dynamic'", "'unsafe-eval'", "'wasm-unsafe-eval'", 'https:', 'data:', '*', 'cdn.example.com', '*.foo.com'])
    expect(s.self && s.wildcard && s.unsafeEval && s.wasmUnsafeEval).toBe(true)
    expect(s.nonces).toBe(1)
    expect(s.hashes).toBe(1)
    expect(s.schemes).toEqual(['https:', 'data:'])
    expect(s.hosts).toEqual(['cdn.example.com', '*.foo.com'])
  })
  it("'none' and empty", () => {
    expect(analyzeSources(["'none'"]).none).toBe(true)
    expect(analyzeSources([]).none).toBe(true)
    expect(analyzeSources(["'none'", "'self'"]).none).toBe(false)
  })
  it('nonce/hash neutralise unsafe-inline', () => {
    expect(analyzeSources(["'unsafe-inline'"]).effectiveUnsafeInline).toBe(true)
    expect(analyzeSources(["'unsafe-inline'", "'nonce-a'"]).effectiveUnsafeInline).toBe(false)
    expect(analyzeSources(["'unsafe-inline'", "'sha256-a'"]).effectiveUnsafeInline).toBe(false)
  })
  it('strict-dynamic only active with nonce/hash', () => {
    expect(analyzeSources(["'strict-dynamic'"]).strictDynamicActive).toBe(false)
    expect(analyzeSources(["'strict-dynamic'", "'nonce-a'"]).strictDynamicActive).toBe(true)
  })
})

const ids = (csp: string[]) => analyzeCsp(csp).hits.map((h) => h.id)

describe('analyzeCsp', () => {
  it('flags allowlist + unsafe-inline', () => {
    const r = ids(["script-src 'self' cdn.optimizely.com 'unsafe-inline'"])
    expect(r).toEqual(expect.arrayContaining(['C4', 'C6', 'C7', 'C8', 'E1', 'E2', 'E3', 'E4', 'R1']))
    expect(r).not.toContain('C3')
  })
  it('strict-dynamic with nonce ignores wildcard/https and host allowlist', () => {
    const a = analyzeCsp(["script-src 'nonce-a' 'strict-dynamic' https: 'unsafe-inline'"])
    expect(a.hits.map((h) => h.id)).not.toEqual(expect.arrayContaining(['C3']))
    expect(a.hits.map((h) => h.id)).not.toContain('C4')
    expect(a.bonuses).toContain('B1')
    const b = analyzeCsp(["script-src 'nonce-a' 'strict-dynamic' cdn.example.com"])
    expect(b.bonuses).not.toContain('B1')
    expect(b.hits.map((h) => h.id)).not.toContain('C6')
  })
  it('C3 on wildcard, http:, https:, data:', () => {
    for (const s of ['*', 'http:', 'https:', 'data:']) expect(ids([`script-src ${s}`])).toContain('C3')
    expect(ids(["script-src 'nonce-a' https:"])).toContain('C3')
  })
  it('C5 unsafe-eval', () => {
    expect(ids(["script-src 'self' 'unsafe-eval'"])).toContain('C5')
  })
  it('default-src fallback covers connect/img/frame/object', () => {
    const r = ids(["default-src 'none'; base-uri 'none'; form-action 'none'; report-uri /r"])
    expect(r).toEqual([])
  })
  it('comma-joined: strictest wins', () => {
    const a = analyzeCsp(["script-src * 'unsafe-inline', script-src 'nonce-a' 'strict-dynamic'"])
    const r = a.hits.map((h) => h.id)
    expect(r).not.toContain('C3')
    expect(r).not.toContain('C4')
    expect(a.bonuses).toContain('B1')
    expect(a.policyCount).toBe(2)
  })
  it('policy without script directive does not mask weak policy', () => {
    const r = ids(["script-src *", "frame-ancestors 'none'"])
    expect(r).toContain('C3')
  })
  it('trusted types and frame-ancestors', () => {
    const a = analyzeCsp(["default-src 'self'; require-trusted-types-for 'script'; frame-ancestors 'self'"])
    expect(a.bonuses).toContain('B2')
    expect(a.frameAncestors).toBe(true)
    expect(analyzeCsp(['frame-ancestors *']).frameAncestors).toBe(false)
  })
  it('reports nothing for no policies', () => {
    const a = analyzeCsp([])
    expect(a.hits).toEqual([])
    expect(a.governsScripts).toBe(false)
  })
})
