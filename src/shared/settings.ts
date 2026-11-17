// Settings schema, defaults, and validation. Stored in chrome.storage.local under SETTINGS_KEY.

export type InterstitialThreshold = 'not-secure' | 'weak' | 'never'
export type BypassScope = 'tab' | '24h' | 'always'

export interface TrustedSite {
  host: string
  /** Epoch ms; undefined means permanent. */
  expiresAt?: number
  addedAt: number
}

export interface Settings {
  version: 1
  threshold: InterstitialThreshold
  defaultBypassScope: BypassScope
  trustedSites: TrustedSite[]
  excludedHosts: string[]
  showWarningBar: boolean
  showFieldWarnings: boolean
  recheckUnverified: boolean
}

export const SETTINGS_KEY = 'settings'

export const DEFAULT_EXCLUDED_HOSTS = ['localhost', '127.0.0.1', '[::1]', 'localhost.localdomain', 'test']

export const DEFAULT_SETTINGS: Settings = {
  version: 1,
  threshold: 'not-secure',
  defaultBypassScope: 'tab',
  trustedSites: [],
  excludedHosts: [...DEFAULT_EXCLUDED_HOSTS],
  showWarningBar: true,
  showFieldWarnings: true,
  recheckUnverified: false,
}

const HOST_RE = /^(\[[0-9a-f:]+\]|[a-z0-9-]+(\.[a-z0-9-]+)*)$/i

export function isValidHost(host: string): boolean {
  return host.length > 0 && host.length <= 253 && HOST_RE.test(host)
}

/** Validates untrusted input (storage or JSON import) and fills defaults. Never throws. */
export function normalizeSettings(raw: unknown): Settings {
  const s = { ...DEFAULT_SETTINGS }
  if (!raw || typeof raw !== 'object') return s
  const r = raw as Record<string, unknown>
  if (r.threshold === 'not-secure' || r.threshold === 'weak' || r.threshold === 'never') s.threshold = r.threshold
  if (r.defaultBypassScope === 'tab' || r.defaultBypassScope === '24h' || r.defaultBypassScope === 'always') {
    s.defaultBypassScope = r.defaultBypassScope
  }
  if (Array.isArray(r.trustedSites)) {
    s.trustedSites = r.trustedSites
      .filter((t): t is Record<string, unknown> => !!t && typeof t === 'object')
      .filter((t) => typeof t.host === 'string' && isValidHost(t.host))
      .map((t) => ({
        host: (t.host as string).toLowerCase(),
        expiresAt: typeof t.expiresAt === 'number' ? t.expiresAt : undefined,
        addedAt: typeof t.addedAt === 'number' ? t.addedAt : Date.now(),
      }))
  }
  if (Array.isArray(r.excludedHosts)) {
    s.excludedHosts = r.excludedHosts.filter((h): h is string => typeof h === 'string' && isValidHost(h)).map((h) => h.toLowerCase())
  }
  for (const k of ['showWarningBar', 'showFieldWarnings', 'recheckUnverified'] as const) {
    if (typeof r[k] === 'boolean') s[k] = r[k] as boolean
  }
  return s
}

/** Trusted sites that have not expired at `now`. */
export function activeTrustedHosts(settings: Settings, now = Date.now()): string[] {
  return settings.trustedSites.filter((t) => t.expiresAt === undefined || t.expiresAt > now).map((t) => t.host)
}

/** True if host equals or is a subdomain of any entry (DNR requestDomains semantics). */
export function hostMatches(host: string, entries: string[]): boolean {
  const h = host.toLowerCase()
  return entries.some((e) => h === e || h.endsWith('.' + e))
}
