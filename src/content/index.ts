// Content script: advisory in-page warnings (top frame only). Plain TypeScript, no framework, no external
// requests. A page can tamper with its own DOM, so the toolbar icon remains the trustworthy indicator.
// This script only ever sends the read-only 'getMyVerdict' message and receives verdict pushes.

import type { Response, VerdictPush } from '../shared/messages'

const BAR_TAG = 'dont-trust-me-bar'
const TIP_TAG = 'dont-trust-me-tip'
const MAX_REATTACH = 3
const SENSITIVE_NAME = /card|cvc|cvv|iban|wallet|address/i
const NON_TEXT_TYPES = new Set(['hidden', 'checkbox', 'radio', 'button', 'submit', 'reset', 'file', 'image', 'range', 'color'])

let push: VerdictPush | null = null
let barHost: HTMLElement | null = null
let barDismissed = false
let reattachCount = 0
let observer: MutationObserver | null = null
let tipHost: HTMLElement | null = null

function main(): void {
  if (window !== window.top) return

  chrome.runtime.onMessage.addListener((msg: unknown, sender) => {
    if (sender.id !== chrome.runtime.id) return
    if (isVerdictPush(msg)) apply(msg)
  })

  chrome.runtime
    .sendMessage({ type: 'getMyVerdict' })
    .then((res: Response<VerdictPush | null> | undefined) => {
      if (res && res.ok && res.data && isVerdictPush(res.data)) apply(res.data)
    })
    .catch(() => undefined) // background not ready or extension reloaded

  document.addEventListener('focusin', onFocusIn, true)
  document.addEventListener('focusout', hideTip, true)
  window.addEventListener('scroll', hideTip, { passive: true, capture: true })
}

function isVerdictPush(m: unknown): m is VerdictPush {
  if (!m || typeof m !== 'object') return false
  const p = m as Partial<VerdictPush>
  return p.type === 'verdict' && !!p.state && typeof p.state === 'object' && typeof p.state.verdict === 'string'
}

function isRisky(p: VerdictPush | null): boolean {
  return !!p && (p.state.verdict === 'weak' || p.state.verdict === 'not-secure' || !!p.state.bypass)
}

function apply(p: VerdictPush): void {
  push = p
  const wantBar = p.showWarningBar && (p.state.verdict === 'weak' || !!p.state.bypass)
  if (wantBar && !barDismissed) showBar()
  else removeBar()
  if (!p.showFieldWarnings) hideTip()
}

function hostName(): string {
  try {
    return new URL(push?.state.url ?? location.href).hostname
  } catch {
    return location.hostname
  }
}

// ---- Warning bar ----------------------------------------------------------------------------

function showBar(): void {
  if (barHost?.isConnected) return
  if (document.body) attachBar()
  else {
    const wait = new MutationObserver(() => {
      if (document.body) {
        wait.disconnect()
        if (push && !barDismissed) attachBar()
      }
    })
    wait.observe(document.documentElement, { childList: true })
  }
}

function buildBar(): HTMLElement {
  const host = document.createElement(BAR_TAG)
  const root = host.attachShadow({ mode: 'closed' })
  const bar = document.createElement('div')
  bar.setAttribute('role', 'alert')
  bar.setAttribute(
    'style',
    'all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;display:flex;align-items:center;gap:12px;' +
      'padding:8px 14px;background:#a50e0e;color:#fff;font:600 13px/1.4 system-ui,sans-serif;box-shadow:0 2px 6px rgba(0,0,0,.35);',
  )
  const text = document.createElement('span')
  text.setAttribute('style', 'flex:1')
  text.textContent = `Not secure: ${hostName()} doesn’t restrict which scripts can run. Avoid entering passwords, card numbers or wallet addresses.`
  const close = document.createElement('button')
  close.type = 'button'
  close.textContent = 'Dismiss'
  close.setAttribute(
    'style',
    'all:initial;cursor:pointer;color:#fff;border:1px solid #fff;border-radius:4px;padding:3px 10px;font:600 12px system-ui,sans-serif;',
  )
  close.addEventListener('click', () => {
    barDismissed = true
    removeBar()
  })
  bar.append(text, close)
  root.append(bar)
  return host
}

function attachBar(): void {
  if (barHost?.isConnected) return
  barHost = buildBar()
  document.documentElement.appendChild(barHost)
  if (!observer) {
    observer = new MutationObserver(() => {
      if (barHost && !barHost.isConnected && !barDismissed && push && reattachCount < MAX_REATTACH) {
        reattachCount++
        document.documentElement.appendChild(barHost)
      }
    })
    observer.observe(document.documentElement, { childList: true })
  }
}

function removeBar(): void {
  observer?.disconnect()
  observer = null
  barHost?.remove()
  barHost = null
}

// ---- Sensitive-field tooltip ----------------------------------------------------------------

function isSensitive(el: Element): el is HTMLInputElement {
  if (!(el instanceof HTMLInputElement)) return false
  const type = (el.type || 'text').toLowerCase()
  if (type === 'password') return true
  if (NON_TEXT_TYPES.has(type)) return false
  const ac = (el.getAttribute('autocomplete') ?? '').toLowerCase()
  if (ac.startsWith('cc-')) return true
  return SENSITIVE_NAME.test(el.name) || SENSITIVE_NAME.test(el.id)
}

function onFocusIn(e: FocusEvent): void {
  if (!push || !push.showFieldWarnings || !isRisky(push)) return
  const target = (e.composedPath()[0] ?? e.target) as Element | null
  if (!target || !isSensitive(target)) return
  showTip(target)
}

function showTip(field: Element): void {
  hideTip()
  const rect = field.getBoundingClientRect()
  const host = document.createElement(TIP_TAG)
  const root = host.attachShadow({ mode: 'closed' })
  const tip = document.createElement('div')
  tip.setAttribute('role', 'tooltip')
  const below = rect.bottom + 76 < window.innerHeight
  const top = below ? rect.bottom + 6 : Math.max(4, rect.top - 70)
  const left = Math.max(4, Math.min(rect.left, window.innerWidth - 284))
  tip.setAttribute(
    'style',
    `all:initial;position:fixed;z-index:2147483647;top:${top}px;left:${left}px;width:272px;box-sizing:border-box;` +
      'padding:8px 10px;background:#fff8e1;color:#3c2a00;border:2px solid #a50e0e;border-radius:6px;' +
      'font:500 12px/1.4 system-ui,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.3);pointer-events:none;',
  )
  tip.textContent = 'Not secure — scripts on this page aren’t restricted and could read what you type here.'
  root.append(tip)
  document.documentElement.appendChild(host)
  tipHost = host
}

function hideTip(): void {
  tipHost?.remove()
  tipHost = null
}

main()
