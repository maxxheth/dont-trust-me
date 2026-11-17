// Finding catalogue: static text for every FindingId. Points come from policy.ts.
import type { FindingCategory, FindingId, Severity } from '../shared/types'

export interface CatalogEntry {
  severity: Severity
  category: FindingCategory
  title: string
  why: string
  fix: string
  mdn: string
}

const CSP = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy'
const H = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/'

const OPTIMJACK =
  'In the Nov 2026 Optimizely (OPTIMJACK) supply-chain attack, a poisoned script served from a trusted CDN loaded a second stage from an attacker domain, sent card data out through requests, and used hidden iframes.'

export const CATALOG: Record<FindingId, CatalogEntry> = {
  T1: {
    severity: 'critical',
    category: 'transport',
    title: 'Page served over plain HTTP',
    why: 'Anyone on the network path can read or rewrite this page, including injecting scripts. There is no integrity at all, so no header can make it trustworthy.',
    fix: 'Serve the site over HTTPS only and redirect all HTTP traffic to HTTPS.',
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS',
  },
  C1: {
    severity: 'critical',
    category: 'script-control',
    title: 'No enforced Content-Security-Policy governing scripts',
    why: `Without a CSP that sets script-src (or default-src), any script that reaches the page runs with full power. ${OPTIMJACK} A Report-Only policy, or one that only sets frame-ancestors or upgrade-insecure-requests, does not restrict scripts.`,
    fix: "Send an enforced Content-Security-Policy header with at least script-src (for example a nonce plus 'strict-dynamic'), object-src 'none' and base-uri 'none'.",
    mdn: CSP,
  },
  C3: {
    severity: 'high',
    category: 'script-control',
    title: 'Script sources allow any origin',
    why: `A wildcard, http:, https: or data: in the script sources lets a script load code from anywhere. ${OPTIMJACK}`,
    fix: "Replace broad sources with a nonce or hash plus 'strict-dynamic', or list exact script hosts.",
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src',
  },
  C4: {
    severity: 'high',
    category: 'script-control',
    title: "'unsafe-inline' without a nonce or hash",
    why: 'Inline scripts and event handlers are allowed, so any injected markup can run code. This defeats the main purpose of a CSP.',
    fix: "Remove 'unsafe-inline' and use per-response nonces or hashes for the inline scripts you need.",
    mdn: CSP + '#unsafe_inline_script',
  },
  C5: {
    severity: 'medium',
    category: 'script-control',
    title: "'unsafe-eval' allowed",
    why: 'Strings can be turned into code with eval() or new Function(). Attackers use this to unpack obfuscated payloads, for example Base64 decoded with atob() and then evaluated.',
    fix: "Remove 'unsafe-eval'. Replace eval-style code and pre-compile templates.",
    mdn: CSP + '#unsafe_eval_expressions',
  },
  C6: {
    severity: 'medium',
    category: 'script-control',
    title: 'Host allowlist without nonce, hash or strict-dynamic',
    why: `Allowlisting a host trusts every file that host serves. That was the OPTIMJACK vector: the poisoned snippet came from an allowlisted, trusted CDN. ${OPTIMJACK}`,
    fix: "Switch to a nonce or hash plus 'strict-dynamic' so that trust attaches to specific scripts, not whole hosts.",
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP#strict_csp',
  },
  C7: {
    severity: 'medium',
    category: 'script-control',
    title: "object-src is not 'none'",
    why: 'Plugin content (object, embed) can be used to execute script and bypass script-src.',
    fix: "Add object-src 'none'.",
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src',
  },
  C8: {
    severity: 'low',
    category: 'script-control',
    title: 'base-uri is not set',
    why: 'An injected <base> tag can redirect every relative script URL to an attacker host.',
    fix: "Add base-uri 'none' (or 'self').",
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri',
  },
  E1: {
    severity: 'high',
    category: 'exfiltration',
    title: 'connect-src is unrestricted',
    why: `Scripts can send data to any server with fetch or XHR. ${OPTIMJACK}`,
    fix: "Set connect-src (or default-src) to 'self' plus only the APIs you use.",
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/connect-src',
  },
  E2: {
    severity: 'medium',
    category: 'exfiltration',
    title: 'frame-src / child-src is unrestricted',
    why: `Injected code can load hidden iframes from any origin, for example exploit kits. ${OPTIMJACK}`,
    fix: "Set frame-src to 'none' or an explicit list of embedded origins.",
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-src',
  },
  E3: {
    severity: 'low',
    category: 'exfiltration',
    title: 'form-action is not set',
    why: 'An injected or modified form can post entered data (passwords, card numbers) to an attacker host.',
    fix: "Add form-action 'self' (or the exact hosts your forms post to).",
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action',
  },
  E4: {
    severity: 'low',
    category: 'exfiltration',
    title: 'img-src is unrestricted',
    why: 'Data can be leaked by requesting an image from an attacker URL with the data in the query string.',
    fix: "Set img-src to 'self' plus the image hosts you need.",
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/img-src',
  },
  R1: {
    severity: 'low',
    category: 'other',
    title: 'No CSP violation reporting',
    why: 'Without report-to or report-uri the site owner never learns that a policy blocked something, which is often the first sign of an attack such as OPTIMJACK.',
    fix: 'Add report-to (with a Reporting-Endpoints header) or report-uri pointing at a collector you monitor.',
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to',
  },
  H1: {
    severity: 'medium',
    category: 'framing',
    title: 'Page can be framed by any site (clickjacking)',
    why: 'Neither frame-ancestors nor X-Frame-Options restricts who may embed this page, so another site can overlay it invisibly and trick users into clicking.',
    fix: "Add frame-ancestors 'none' (or 'self') to the CSP; X-Frame-Options: DENY or SAMEORIGIN covers old browsers.",
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors',
  },
  H2: {
    severity: 'high',
    category: 'transport',
    title: 'Strict-Transport-Security is missing',
    why: 'Browsers will still try plain HTTP first, so an attacker on the network can downgrade the connection (SSL stripping).',
    fix: 'Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload.',
    mdn: H + 'Strict-Transport-Security',
  },
  H3: {
    severity: 'medium',
    category: 'transport',
    title: 'HSTS max-age is under one year',
    why: 'A short HSTS lifetime leaves returning visitors exposed to downgrade attacks once it expires.',
    fix: 'Set max-age to at least 31536000 (one year), ideally 63072000.',
    mdn: H + 'Strict-Transport-Security',
  },
  H4: {
    severity: 'medium',
    category: 'other',
    title: 'X-Content-Type-Options: nosniff is missing',
    why: 'Browsers may guess a file type and execute an uploaded or injected file as a script.',
    fix: 'Send X-Content-Type-Options: nosniff.',
    mdn: H + 'X-Content-Type-Options',
  },
  H5: {
    severity: 'low',
    category: 'other',
    title: 'Referrer-Policy is missing or leaks full URLs',
    why: 'Full page URLs (which may contain tokens or personal data) can be sent to other sites.',
    fix: 'Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).',
    mdn: H + 'Referrer-Policy',
  },
  H6: {
    severity: 'low',
    category: 'other',
    title: 'Permissions-Policy is missing',
    why: 'Powerful features such as camera, microphone, geolocation and payment stay available to the page and any embedded frames.',
    fix: 'Send a Permissions-Policy that disables features you do not use, e.g. camera=(), microphone=(), geolocation=().',
    mdn: H + 'Permissions-Policy',
  },
  H7: {
    severity: 'low',
    category: 'other',
    title: 'Cross-Origin-Opener-Policy is missing',
    why: 'Pages that open or are opened by this page keep a reference to its window, enabling cross-window attacks.',
    fix: 'Send Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups if you need popups).',
    mdn: H + 'Cross-Origin-Opener-Policy',
  },
  K1: {
    severity: 'medium',
    category: 'cookies',
    title: 'Cookie set without the Secure flag',
    why: 'Without Secure the browser may send the cookie over plain HTTP, where it can be stolen.',
    fix: 'Add the Secure attribute to every cookie.',
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#block_access_to_your_cookies',
  },
  K2: {
    severity: 'low',
    category: 'cookies',
    title: 'Cookie set without the HttpOnly flag',
    why: 'Scripts can read this cookie. OPTIMJACK collected cookies this way; HttpOnly keeps session cookies out of injected code.',
    fix: 'Add the HttpOnly attribute to cookies that scripts do not need.',
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#block_access_to_your_cookies',
  },
  B1: {
    severity: 'bonus',
    category: 'script-control',
    title: 'Strict CSP (nonce or hash with strict-dynamic)',
    why: 'Trust is attached to individual scripts instead of whole hosts, the approach that would have stopped the OPTIMJACK second-stage loader.',
    fix: 'Keep it. Make sure nonces are random per response.',
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP#strict_csp',
  },
  B2: {
    severity: 'bonus',
    category: 'script-control',
    title: 'Trusted Types enforced',
    why: 'Dangerous DOM sinks only accept values created by approved policies, which blocks most DOM XSS.',
    fix: 'Keep require-trusted-types-for \'script\'.',
    mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-trusted-types-for',
  },
  B3: {
    severity: 'bonus',
    category: 'transport',
    title: 'HSTS with includeSubDomains and preload',
    why: 'The whole domain is protected from downgrade attacks and is eligible for browser preload lists.',
    fix: 'Keep it, and submit the domain to hstspreload.org if you have not.',
    mdn: H + 'Strict-Transport-Security',
  },
  I1: {
    severity: 'info',
    category: 'script-control',
    title: 'CSP is Report-Only (not enforced)',
    why: 'A Content-Security-Policy-Report-Only header only reports violations; it blocks nothing, so it gives no protection.',
    fix: 'Once the reports look clean, send the same policy as an enforced Content-Security-Policy.',
    mdn: H + 'Content-Security-Policy-Report-Only',
  },
  I2: {
    severity: 'info',
    category: 'other',
    title: 'Cross-origin isolation headers present',
    why: 'CORP and COEP limit who can load this site\'s resources and which cross-origin resources it can load. Informational only.',
    fix: 'No action needed unless you want cross-origin isolation.',
    mdn: H + 'Cross-Origin-Resource-Policy',
  },
  I3: {
    severity: 'info',
    category: 'other',
    title: 'Server software disclosed',
    why: 'Server or X-Powered-By reveals software and versions, which helps attackers pick known exploits.',
    fix: 'Remove or genericise Server and X-Powered-By.',
    mdn: H + 'Server',
  },
  I4: {
    severity: 'info',
    category: 'other',
    title: 'Deprecated X-XSS-Protection header',
    why: 'Browsers removed the XSS auditor; the header does nothing in modern browsers and can introduce issues in old ones.',
    fix: 'Remove it, or send X-XSS-Protection: 0, and rely on CSP.',
    mdn: H + 'X-XSS-Protection',
  },
}

/** Display order of findings. */
export const FINDING_ORDER: FindingId[] = Object.keys(CATALOG) as FindingId[]
