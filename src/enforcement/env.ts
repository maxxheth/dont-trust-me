// Runtime/browser detection shared by the enforcement modules.

import { INTERSTITIAL_PATH } from '../shared/url'

const FIREFOX_LIKE = ['firefox', 'gecko-based', 'waterfox', 'librewolf', 'firefox-based', 'zen', 'floorp']

/** True on Firefox-like browsers. Build-time flag OR runtime URL scheme (works synchronously). */
export function isFirefox(): boolean {
  try {
    if (FIREFOX_LIKE.includes(import.meta.env.EXTENSION_PUBLIC_BROWSER)) return true
  } catch {
    // import.meta.env unavailable: fall through to runtime check.
  }
  try {
    return chrome.runtime.getURL('').startsWith('moz-extension:')
  } catch {
    return false
  }
}

export function interstitialUrl(): string {
  return chrome.runtime.getURL(INTERSTITIAL_PATH)
}

/**
 * True if `u` is this extension's interstitial page. With use_dynamic_url, Chromium may serve
 * the page under the per-session dynamic origin OR the static extension origin (DNR redirects
 * resolve to the static one), so both origins are accepted — never any other origin.
 */
export function isInterstitialUrl(u: string | undefined): boolean {
  if (typeof u !== 'string') return false
  try {
    const parsed = new URL(u)
    const origins = [new URL(chrome.runtime.getURL('')).origin, new URL(interstitialUrl()).origin]
    return origins.includes(parsed.origin) && parsed.pathname === '/' + INTERSTITIAL_PATH
  } catch {
    return false
  }
}

/** Headers/exclusions that mirror the DNR gate's excludedResponseHeaders. */
export function headerValue(headers: { name: string; value?: string }[] | undefined, name: string): string | undefined {
  const n = name.toLowerCase()
  const h = headers?.find((x) => x.name.toLowerCase() === n)
  return h?.value
}

/** CSP appended by "Continue without JavaScript". Multiple CSPs intersect, so this can only tighten. */
export const NO_JS_CSP = "script-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'"
