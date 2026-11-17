import { useEffect, useRef, useState } from 'react'
import './styles.css'
import { send, type BlockedInfo } from '../shared/messages'
import type { BypassScope, Settings } from '../shared/settings'
import { safeHttpUrl } from '../shared/url'
import { FindingList } from '../ui'

function displayHostFromHash(): string {
  // DISPLAY ONLY. Never navigate to this value.
  const raw = decodeURIComponent(location.hash.replace(/^#/, ''))
  return safeHttpUrl(raw)?.hostname ?? ''
}

function goBack() {
  if (history.length > 1) history.back()
  else chrome.tabs.getCurrent().then((t) => {
      if (t?.id !== undefined) void chrome.tabs.remove(t.id)
    })
}

export function InterstitialApp() {
  const [info, setInfo] = useState<BlockedInfo | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [advanced, setAdvanced] = useState(false)
  const [scope, setScope] = useState<BypassScope>('tab')
  const [error, setError] = useState('')
  const backRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    send<BlockedInfo | null>({ type: 'getBlocked' }).then((r) => {
      if (r.ok) setInfo(r.data)
      setLoaded(true)
    }).catch(() => setLoaded(true))
    send<Settings>({ type: 'getSettings' }).then((r) => {
      if (r.ok) setScope(r.data.defaultBypassScope)
    }).catch(() => {})
  }, [])

  const host = info?.host || displayHostFromHash() || 'this site'
  useEffect(() => {
    document.title = `Not Secure — ${host}`
  }, [host])
  useEffect(() => {
    backRef.current?.focus()
  }, [])

  const proceed = async (mode: 'unsafe' | 'no-js') => {
    setError('')
    try {
      const r = await send<void>({ type: 'proceed', mode, scope })
      if (!r.ok) setError(r.error)
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <main className="wrap">
      <div className="hero">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" aria-hidden="true">
          <path d="M12 2L2 21h20L12 2z" />
          <path d="M12 9v5M12 17.5v.5" />
        </svg>
      </div>
      <h1>This site doesn&rsquo;t protect you from malicious scripts</h1>
      <p className="sub">
        <strong>{host}</strong> sent no Content-Security-Policy that restricts scripts. If any script it loads, even one from a trusted vendor, is compromised, it can read what you type: passwords, card numbers and more.
      </p>
      {loaded && !info ? <p className="muted">No details are available for this page.</p> : null}
      <div className="actions">
        <button ref={backRef} className="primary" onClick={goBack}>Back to safety</button>
        <button className="link" aria-expanded={advanced} onClick={() => setAdvanced(!advanced)}>Advanced</button>
      </div>
      {advanced ? (
        <section className="advanced" aria-label="Advanced">
          <h2>What we found</h2>
          {info?.report ? <FindingList findings={info.report.findings} /> : <p className="muted">No findings available.</p>}
          <p className="muted">
            Sites that set their Content-Security-Policy only through a &lt;meta&gt; tag are also flagged, because a meta policy cannot cover everything a header can and can be injected or arrive too late.
          </p>

          <h2>Learn more</h2>
          <p>
            On 16 November 2026, attackers wrote a malicious loader into Optimizely snippets used by 178 organisations. It was served from Optimizely&rsquo;s own trusted CDN, so sites and visitors had no reason to doubt it. It skimmed payment cards, swapped cryptocurrency addresses and loaded exploit kits through hidden frames. A strict Content-Security-Policy limits this kind of damage by controlling which scripts run and where data can be sent.
          </p>

          <div className="scope">
            <label htmlFor="scope">Remember my choice:</label>
            <select id="scope" value={scope} onChange={(e) => setScope(e.target.value as BypassScope)}>
              <option value="tab">This tab only</option>
              <option value="24h">24 hours</option>
              <option value="always">Always</option>
            </select>
          </div>
          <div className="proceed">
            <button onClick={() => proceed('no-js')}>Continue without JavaScript</button>
            <button className="link" onClick={() => proceed('unsafe')}>Proceed to {host} (unsafe)</button>
          </div>
          {error ? <p className="err" role="alert">{error}</p> : null}
        </section>
      ) : null}
    </main>
  )
}
