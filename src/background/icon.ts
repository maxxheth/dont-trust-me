// Per-tab toolbar icon, badge and title. Icons are drawn at runtime with a canvas so each state has
// a distinct SHAPE (not just a colour): circle+tick, circle+!, triangle+!, octagon+x, circle+?, slashed circle.

import type { Grade, TabState, Verdict } from '../shared/types'

export type IconState = 'secure' | 'partial' | 'weak' | 'not-secure' | 'unverified' | 'off'

const COLORS: Record<IconState, string> = {
  secure: '#1e8e3e',
  partial: '#b06000',
  weak: '#c5221f',
  'not-secure': '#a50e0e',
  unverified: '#5f6368',
  off: '#80868b',
}

const LABELS: Record<IconState, string> = {
  secure: 'Secure',
  partial: 'Partially Secure',
  weak: 'Weak',
  'not-secure': 'Not Secure',
  unverified: 'Unverified',
  off: 'Protection off',
}

type Ctx = OffscreenCanvasRenderingContext2D | CanvasRenderingContext2D

function makeContext(size: number): Ctx | null {
  try {
    if (typeof OffscreenCanvas !== 'undefined') {
      return new OffscreenCanvas(size, size).getContext('2d') as OffscreenCanvasRenderingContext2D | null
    }
    if (typeof document !== 'undefined') {
      const c = document.createElement('canvas')
      c.width = c.height = size
      return c.getContext('2d')
    }
  } catch {
    // fall through
  }
  return null
}

function polygon(ctx: Ctx, pts: [number, number][]): void {
  ctx.beginPath()
  pts.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)))
  ctx.closePath()
}

function draw(state: IconState, size: number): ImageData | null {
  const ctx = makeContext(size)
  if (!ctx) return null
  const u = size / 32
  const c = 16 * u
  ctx.clearRect(0, 0, size, size)
  ctx.fillStyle = COLORS[state]
  ctx.strokeStyle = '#fff'
  ctx.lineCap = 'round'
  ctx.lineJoin = 'round'
  ctx.lineWidth = 4 * u

  // Background shape
  if (state === 'weak') {
    ctx.beginPath()
    polygon(ctx, [[c, 2 * u], [30 * u, 28 * u], [2 * u, 28 * u]])
    ctx.fill()
  } else if (state === 'not-secure') {
    const r = 15 * u
    const k = r * 0.414
    polygon(ctx, [
      [c - k, c - r], [c + k, c - r], [c + r, c - k], [c + r, c + k],
      [c + k, c + r], [c - k, c + r], [c - r, c + k], [c - r, c - k],
    ])
    ctx.fill()
  } else {
    ctx.beginPath()
    ctx.arc(c, c, 15 * u, 0, Math.PI * 2)
    ctx.fill()
  }

  // Glyph
  ctx.beginPath()
  switch (state) {
    case 'secure':
      ctx.moveTo(9 * u, 16.5 * u)
      ctx.lineTo(14 * u, 21.5 * u)
      ctx.lineTo(23 * u, 10.5 * u)
      ctx.stroke()
      break
    case 'partial':
      ctx.moveTo(c, 8 * u)
      ctx.lineTo(c, 18 * u)
      ctx.stroke()
      ctx.fillStyle = '#fff'
      ctx.beginPath()
      ctx.arc(c, 23.5 * u, 2.4 * u, 0, Math.PI * 2)
      ctx.fill()
      break
    case 'weak':
      ctx.lineWidth = 3.5 * u
      ctx.moveTo(c, 11 * u)
      ctx.lineTo(c, 19 * u)
      ctx.stroke()
      ctx.fillStyle = '#fff'
      ctx.beginPath()
      ctx.arc(c, 23.5 * u, 2.1 * u, 0, Math.PI * 2)
      ctx.fill()
      break
    case 'not-secure':
      ctx.moveTo(10 * u, 10 * u)
      ctx.lineTo(22 * u, 22 * u)
      ctx.moveTo(22 * u, 10 * u)
      ctx.lineTo(10 * u, 22 * u)
      ctx.stroke()
      break
    case 'unverified':
      ctx.lineWidth = 3.5 * u
      ctx.arc(c, 13 * u, 5 * u, Math.PI * 1.1, Math.PI * 2.4)
      ctx.lineTo(c, 19 * u)
      ctx.stroke()
      ctx.fillStyle = '#fff'
      ctx.beginPath()
      ctx.arc(c, 24 * u, 2.2 * u, 0, Math.PI * 2)
      ctx.fill()
      break
    case 'off':
      ctx.lineWidth = 3.5 * u
      ctx.arc(c, c, 8 * u, 0, Math.PI * 2)
      ctx.moveTo(10 * u, 22 * u)
      ctx.lineTo(22 * u, 10 * u)
      ctx.stroke()
      break
  }
  return ctx.getImageData(0, 0, size, size)
}

const imageCache = new Map<string, ImageData | null>()

function imagesFor(state: IconState): Record<string, ImageData> | null {
  const out: Record<string, ImageData> = {}
  for (const size of [16, 32]) {
    const key = `${state}:${size}`
    if (!imageCache.has(key)) imageCache.set(key, draw(state, size))
    const img = imageCache.get(key)
    if (!img) return null
    out[String(size)] = img
  }
  return out
}

export function iconStateFor(verdict: Verdict): IconState {
  return verdict === 'not-secure' || verdict === 'weak' || verdict === 'partial' || verdict === 'secure'
    ? verdict
    : 'unverified'
}

function badgeText(state: IconState, grade?: Grade): string {
  if (state === 'off') return ''
  if (state === 'unverified') return '?'
  return grade ?? '!'
}

/** Applies icon, badge and title for one tab. `protectionOff` forces the grey slashed icon. */
export async function updateIcon(tabId: number, tab: TabState | null | undefined, protectionOff = false): Promise<void> {
  const state: IconState = protectionOff ? 'off' : tab ? iconStateFor(tab.verdict) : 'unverified'
  const grade = tab?.report?.grade
  const text = tab || protectionOff ? badgeText(state, grade) : ''
  const title = protectionOff
    ? "Don't Trust Me — Protection off (site access not granted)"
    : tab
      ? `Don't Trust Me — ${LABELS[state]}${grade ? ` (${grade})` : ''}`
      : "Don't Trust Me"
  try {
    const imageData = imagesFor(state)
    if (imageData) await chrome.action.setIcon({ tabId, imageData: imageData as unknown as Record<string, ImageData> })
    await chrome.action.setBadgeText({ tabId, text })
    await chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS[state] })
    // Firefox only: keep badge text readable.
    const a = chrome.action as unknown as { setBadgeTextColor?: (d: { tabId: number; color: string }) => Promise<void> }
    await a.setBadgeTextColor?.({ tabId, color: '#ffffff' })
    await chrome.action.setTitle({ tabId, title })
  } catch {
    // Tab closed mid-update.
  }
}

/** Page with no tracked state (chrome://, about:...): neutral packaged icon, no badge. */
export async function resetIcon(tabId: number, protectionOff = false): Promise<void> {
  if (protectionOff) return updateIcon(tabId, null, true)
  try {
    await chrome.action.setIcon({ tabId, path: { 16: 'images/icon-16.png', 32: 'images/icon-32.png' } })
    await chrome.action.setBadgeText({ tabId, text: '' })
    await chrome.action.setTitle({ tabId, title: "Don't Trust Me" })
  } catch {
    // ignore
  }
}
