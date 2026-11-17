// URL helpers. Treat every URL from a page, hash, or header as untrusted.

/** Parses and returns the URL only if it is http(s). Blocks javascript:, data:, etc. */
export function safeHttpUrl(input: unknown): URL | null {
  if (typeof input !== 'string' || input.length > 8192) return null
  try {
    const u = new URL(input)
    return u.protocol === 'http:' || u.protocol === 'https:' ? u : null
  } catch {
    return null
  }
}

export function hostOf(input: string): string {
  return safeHttpUrl(input)?.hostname.toLowerCase() ?? ''
}

export const INTERSTITIAL_PATH = 'pages/interstitial.html'
