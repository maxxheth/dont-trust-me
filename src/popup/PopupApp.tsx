import { useCallback, useEffect, useState } from 'react'
import './styles.css'
import { send } from '../shared/messages'
import type { BypassScope, Settings } from '../shared/settings'
import { activeTrustedHosts } from '../shared/settings'
import { safeHttpUrl } from '../shared/url'
import type { TabState } from '../shared/types'
import { FindingList, GradeBadge, RawHeaders, VerdictLabel } from '../ui'

function summaryFor(s: TabState): string {
  const r = s.report
  switch (s.verdict) {
    case 'not-secure': return 'No Content-Security-Policy restricts scripts on this page.'
    case 'weak': return 'The policy has gaps that let injected scripts run or send data out.'
    case 'partial': return 'Script control is in place, with some weaknesses.'
    case 'secure': return 'A strict policy limits what scripts can do.'
    default: return r ? '' : 'No header data for this page.'
  }
}

export function PopupApp() {
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<chrome.tabs.Tab | null>(null)
  const [state, setState] = useState<TabState | null>(null)
  const [settings, setSettings] = useState<Settings | null>(null)
  const [scope, setScope] = useState<BypassScope>('24h')
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const [t] = await chrome.tabs.query({ active: true, currentWindow: true })
      setTab(t ?? null)
      const st = await send<Settings>({ type: 'getSettings' })
      if (st.ok) setSettings(st.data)
      if (t?.id !== undefined && safeHttpUrl(t.url)) {
        const r = await send<TabState | null>({ type: 'getTabState', tabId: t.id })
        setState(r.ok ? r.data : null)
      }
    } catch (e) {
      setError(String(e))
    }
    setLoading(false)
  }, [])
  useEffect(() => { void load() }, [load])

  const act = async (msg: Parameters<typeof send>[0]) => {
    setError('')
    try {
      const r = await send<void>(msg)
      if (!r.ok) setError(r.error)
    } catch (e) {
      setError(String(e))
    }
    await load()
  }

  const footer = (
    <footer>
      <span className="muted">Analysed locally — nothing leaves your browser</span>
      <button className="link" onClick={() => chrome.runtime.openOptionsPage()}>Options</button>
    </footer>
  )

  if (loading) return <div className="popup"><p className="muted">Loading…</p></div>

  const url = tab?.url ? safeHttpUrl(tab.url) : null
  if (!tab || !url) {
    return <div className="popup"><p><strong>Not a web page</strong></p><p className="muted">Don&rsquo;t Trust Me only checks http and https pages.</p>{footer}</div>
  }
  const host = url.hostname.toLowerCase()
  const tabId = tab.id
  const trusted = settings ? activeTrustedHosts(settings).includes(host) : false
  const verdict = state?.verdict ?? 'unverified'
  const report = state?.report

  return (
    <div className="popup">
      <div className="top">
        <GradeBadge verdict={verdict} grade={report?.grade} />
        <div>
          <div className="host">{host}</div>
          <div><VerdictLabel verdict={verdict} /></div>
          {state && verdict !== 'unverified' ? <p className="summary">{summaryFor(state)}</p> : null}
        </div>
      </div>
      {verdict === 'unverified' || !report ? (
        <p>No header data for this page (opened before install, or served from cache). Use Re-check to analyse it now.</p>
      ) : (
        <>
          <FindingList findings={report.findings} />
          <RawHeaders headers={report.headers} />
        </>
      )}
      <div className="row">
        {trusted ? (
          <button onClick={() => act({ type: 'revokeTrust', host })}>Revoke trust</button>
        ) : (
          <>
            <button className="primary" onClick={() => act({ type: 'trustSite', host, scope })}>Trust this site</button>
            <label className="sr-only" htmlFor="trust-scope">Trust duration</label>
            <select id="trust-scope" value={scope} onChange={(e) => setScope(e.target.value as BypassScope)}>
              <option value="tab">This tab only</option>
              <option value="24h">24 hours</option>
              <option value="always">Always</option>
            </select>
          </>
        )}
        <button disabled={tabId === undefined} onClick={() => tabId !== undefined && act({ type: 'recheck', tabId })}>Re-check</button>
      </div>
      {error ? <p className="err" role="alert">{error}</p> : null}
      {footer}
    </div>
  )
}
