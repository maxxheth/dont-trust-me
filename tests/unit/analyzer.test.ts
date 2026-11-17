import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { analyze, isScriptGoverningCspPresent } from '../../src/analyzer'
import type { AnalyzeInput, FindingId, Grade, Verdict } from '../../src/shared/types'

interface Fixture {
  input: AnalyzeInput
  expect: {
    verdict: Verdict
    grade?: Grade
    minGrade?: Grade
    maxGrade?: Grade
    hasFindings?: FindingId[]
    lacksFindings?: FindingId[]
  }
}

const ORDER: Grade[] = ['F', 'D', 'C', 'B', 'A', 'A+']
const rank = (g: Grade) => ORDER.indexOf(g)

const dir = join(__dirname, '..', 'fixtures', 'headers')
const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort()

describe('fixtures', () => {
  it('has the required fixtures', () => {
    for (const n of ['none', 'report-only', 'frame-ancestors-only', 'upgrade-insecure-only', 'optimjack-allowlist', 'optimjack-hardened', 'http', 'default-src-star', 'multiple-policies', 'malformed']) {
      expect(files).toContain(n + '.json')
    }
  })

  for (const file of files) {
    it(file, () => {
      const fx = JSON.parse(readFileSync(join(dir, file), 'utf8')) as Fixture
      const r = analyze(fx.input, 1234)
      const ids = r.findings.map((f) => f.id)
      const e = fx.expect
      expect(r.verdict).toBe(e.verdict)
      if (e.grade) expect(r.grade).toBe(e.grade)
      if (e.minGrade) expect(rank(r.grade)).toBeGreaterThanOrEqual(rank(e.minGrade))
      if (e.maxGrade) expect(rank(r.grade)).toBeLessThanOrEqual(rank(e.maxGrade))
      for (const id of e.hasFindings ?? []) expect(ids, `expected ${id}`).toContain(id)
      for (const id of e.lacksFindings ?? []) expect(ids, `unexpected ${id}`).not.toContain(id)
      expect(r.analyzedAt).toBe(1234)
    })
  }
})

describe('analyze', () => {
  const base = (headers: { name: string; value?: string }[], url = 'https://Example.com/p') =>
    analyze({ url, statusCode: 200, headers })

  it('lowercases host and flags hardFail', () => {
    const r = base([])
    expect(r.host).toBe('example.com')
    expect(r.hardFail).toBe(true)
    expect(r.grade).toBe('F')
  })

  it('never leaks cookie values and strips unrelated headers', () => {
    const r = base([
      { name: 'Set-Cookie', value: 'session=topsecret; Path=/' },
      { name: 'Set-Cookie', value: 'b=alsosecret; HttpOnly' },
      { name: 'X-Custom', value: 'x' },
    ])
    const dump = JSON.stringify(r)
    expect(dump).not.toContain('topsecret')
    expect(dump).not.toContain('alsosecret')
    expect(r.headers.map((h) => h.value)).toContain('session=…; Path=/')
    expect(r.headers.some((h) => h.name === 'X-Custom')).toBe(false)
    const k1 = r.findings.find((f) => f.id === 'K1')!
    expect(k1.evidence).toBe('session, b')
    expect(r.findings.find((f) => f.id === 'K2')!.evidence).toBe('session')
  })

  it('skips HSTS and cookie Secure checks on http', () => {
    const r = base([{ name: 'Set-Cookie', value: 'a=1' }], 'http://example.com/')
    const ids = r.findings.map((f) => f.id)
    expect(ids).toContain('T1')
    expect(ids).not.toContain('H2')
    expect(ids).not.toContain('K1')
  })

  it('HSTS short max-age gives H3', () => {
    const r = base([{ name: 'strict-transport-security', value: 'max-age=3600' }])
    expect(r.findings.map((f) => f.id)).toContain('H3')
    expect(r.findings.map((f) => f.id)).not.toContain('H2')
  })

  it('Referrer-Policy: last valid token wins', () => {
    const bad = base([{ name: 'Referrer-Policy', value: 'strict-origin, unsafe-url' }])
    expect(bad.findings.map((f) => f.id)).toContain('H5')
    const good = base([{ name: 'Referrer-Policy', value: 'unsafe-url, nonsense, same-origin' }])
    expect(good.findings.map((f) => f.id)).not.toContain('H5')
  })

  it('X-Frame-Options satisfies H1', () => {
    expect(base([{ name: 'X-Frame-Options', value: 'deny' }]).findings.map((f) => f.id)).not.toContain('H1')
    expect(base([]).findings.map((f) => f.id)).toContain('H1')
  })

  it('emits info findings', () => {
    const ids = base([
      { name: 'Server', value: 'nginx/1.2.3' },
      { name: 'X-XSS-Protection', value: '1; mode=block' },
      { name: 'Cross-Origin-Embedder-Policy', value: 'require-corp' },
    ]).findings.map((f) => f.id)
    expect(ids).toEqual(expect.arrayContaining(['I2', 'I3', 'I4']))
  })

  it('nonce neutralises unsafe-inline (no C4)', () => {
    const r = base([{ name: 'Content-Security-Policy', value: "script-src 'unsafe-inline' 'nonce-a' 'strict-dynamic'" }])
    // unsafe-inline ignored with nonce
    expect(r.findings.map((f) => f.id)).not.toContain('C4')
  })

  it('does not throw on garbage input and truncates evidence', () => {
    const huge = 'x'.repeat(500000)
    const inputs: unknown[] = [
      null,
      undefined,
      {},
      { url: 5, statusCode: 'a', headers: 'nope' },
      { url: 'not a url', statusCode: 200, headers: [null, 1, { name: 5 }, { name: 'content-security-policy', value: huge }] },
      { url: 'https://a.test/', statusCode: 200, headers: [{ name: 'Content-Security-Policy', value: `script-src ${huge}` }, { name: 'Set-Cookie', value: huge }] },
    ]
    for (const i of inputs) {
      const r = analyze(i as AnalyzeInput)
      expect(r.grade).toBeTruthy()
      for (const f of r.findings) expect((f.evidence ?? '').length).toBeLessThanOrEqual(205)
    }
  })
})

describe('isScriptGoverningCspPresent', () => {
  const h = (value?: string, name = 'Content-Security-Policy') => [{ name, value }]
  it('detects script-governing directives', () => {
    expect(isScriptGoverningCspPresent(h("script-src 'self'"))).toBe(true)
    expect(isScriptGoverningCspPresent(h("script-src-elem 'self'"))).toBe(true)
    expect(isScriptGoverningCspPresent(h("default-src 'self'"))).toBe(true)
    expect(isScriptGoverningCspPresent(h("img-src 'self', default-src 'none'"))).toBe(true)
  })
  it('rejects non-governing', () => {
    expect(isScriptGoverningCspPresent(h("frame-ancestors 'none'"))).toBe(false)
    expect(isScriptGoverningCspPresent(h('upgrade-insecure-requests'))).toBe(false)
    expect(isScriptGoverningCspPresent(h("script-src 'self'", 'Content-Security-Policy-Report-Only'))).toBe(false)
    expect(isScriptGoverningCspPresent(h(undefined))).toBe(false)
    expect(isScriptGoverningCspPresent([])).toBe(false)
    expect(isScriptGoverningCspPresent(null as never)).toBe(false)
  })
})
