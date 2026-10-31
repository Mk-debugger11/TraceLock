import { useState } from 'react'
import {
  ShieldAlert,
  MessageCircleQuestion,
  ChevronDown,
  ShieldCheck,
  CircleHelp,
  Download,
  FileJson,
  Check,
  X,
  TriangleAlert,
  Clock,
  GitCommitHorizontal,
  Package,
  Zap,
} from 'lucide-react'
import { downloadUrl } from './api'

// Display only: every verdict, path and checklist comes from the backend's ScanResult JSON.
const ORDER = { REACHABLE: 0, UNCERTAIN: 1, NOT_REACHABLE: 2 }

const VERDICTS = {
  REACHABLE: { label: 'Reachable', cls: 'reachable', Icon: ShieldAlert },
  UNCERTAIN: { label: 'Uncertain', cls: 'uncertain', Icon: CircleHelp },
  NOT_REACHABLE: { label: 'Not reachable', cls: 'not-reachable', Icon: ShieldCheck },
}

const TIERS = {
  curated: 'curated',
  ecosystem_specific: 'ecosystem',
  fix_commit: 'fix commit',
  llm_verified: 'LLM verified',
  none: 'no function data',
}

const humanize = (key) => key.replaceAll('_', ' ')

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

const formatSeconds = (s) => (typeof s !== 'number' ? '–' : s < 0.01 ? '<0.01s' : `${s}s`)

// Only http(s) links from advisory data become clickable.
const safeUrl = (url) => (typeof url === 'string' && /^https?:\/\//.test(url) ? url : null)

function downloadJson(scanId, result) {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `tracelock-${scanId}.json`
  a.click()
  URL.revokeObjectURL(url)
}

function SummaryBar({ result }) {
  const count = (verdict) => result.findings.filter((f) => f.verdict === verdict).length
  const stats = result.stats || {}
  return (
    <div className="summary-bar">
      <div className="summary-stat reachable">
        <span className="summary-num">{count('REACHABLE')}</span>
        <span>reachable</span>
      </div>
      <div className="summary-stat not-reachable">
        <span className="summary-num">{count('NOT_REACHABLE')}</span>
        <span>not reachable</span>
      </div>
      <div className="summary-stat uncertain">
        <span className="summary-num">{count('UNCERTAIN')}</span>
        <span>uncertain</span>
      </div>
      <div className="summary-meta">
        <Clock size={13} />
        <span>
          {formatSeconds(stats.seconds)} · {plural(result.dependencies.length, 'dependency', 'dependencies')} ·{' '}
          {plural(stats.python_files ?? 0, 'Python file')}
        </span>
      </div>
    </div>
  )
}

function PathStepper({ path, entryKind, runtime }) {
  return (
    <div className="finding-section">
      <div className="section-title">
        <span>Call path</span>
        <span className="tag">entry: {entryKind || 'unknown'}</span>
        {runtime?.executed && (
          <span className="tag runtime">
            <Zap size={11} /> runtime confirmed
          </span>
        )}
      </div>
      <ol className="stepper">
        {path.map((step, i) => {
          const isTarget = !step.file
          return (
            <li key={i} className={`step ${isTarget ? 'target' : ''}`}>
              <div className="step-head">
                {isTarget ? (
                  <>
                    <code className="step-qualname">{step.qualname}</code>
                    <span className="tag danger">vulnerable symbol</span>
                  </>
                ) : (
                  <>
                    <code className="step-loc">
                      {step.file}:{step.line}
                    </code>
                    <code className="step-qualname">{step.qualname}</code>
                  </>
                )}
              </div>
              {step.code && <pre className="step-code">{step.code}</pre>}
            </li>
          )
        })}
      </ol>
    </div>
  )
}

function Checklist({ checklist }) {
  const items = Object.entries(checklist).filter(([, value]) => typeof value === 'boolean')
  if (items.length === 0) return null
  return (
    <div className="finding-section">
      <div className="section-title">
        <span>Checklist</span>
      </div>
      <ul className="checklist">
        {items.map(([key, ok]) => (
          <li key={key} className={ok ? 'ok' : 'no'}>
            {ok ? <Check size={13} /> : <X size={13} />}
            <span>{humanize(key)}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function Reasons({ reasons, title }) {
  return (
    <div className="finding-section">
      <div className="section-title">
        <span>{title}</span>
      </div>
      <ul className="reasons">
        {reasons.map((r, i) => (
          <li key={i}>
            <div className="reason-head">
              <span className="tag">{humanize(r.kind)}</span>
              {r.file && (
                <code className="step-loc">
                  {r.file}
                  {r.line ? `:${r.line}` : ''}
                </code>
              )}
            </div>
            <div className="reason-detail">{r.detail}</div>
            {r.check && <div className="reason-check">{r.check}</div>}
          </li>
        ))}
      </ul>
    </div>
  )
}

function ConfidenceFactors({ factors }) {
  if (!factors?.length) return null
  return (
    <ul className="factors">
      {factors.map((c, i) => (
        <li key={i}>
          <span className="factor-name">{c.factor}</span>
          <code className="factor-effect">{c.effect}</code>
          <span className="factor-note">{c.note}</span>
        </li>
      ))}
    </ul>
  )
}

function Why({ finding }) {
  const [open, setOpen] = useState(false)
  const explanation = finding.explanation
  const factors = finding.confidence_factors
  if (!explanation && !factors?.length) return null
  return (
    <div className="why">
      <button type="button" className="why-toggle" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <MessageCircleQuestion size={14} />
        Why?
        <ChevronDown size={13} className={`chev ${open ? 'open' : ''}`} />
      </button>
      {open && (
        <div className="why-body">
          {explanation && <p className="why-text">{explanation}</p>}
          {factors?.length > 0 && (
            <>
              <div className="section-title">
                <span>How confidence {finding.confidence.toFixed(2)} was built</span>
              </div>
              <ConfidenceFactors factors={factors} />
            </>
          )}
        </div>
      )}
    </div>
  )
}

function FindingCard({ finding }) {
  const { advisory, dependency, spec, verdict } = finding
  const v = VERDICTS[verdict] || VERDICTS.UNCERTAIN
  const aliases = advisory.aliases.filter((a) => a !== advisory.id)
  const funcs = spec.entry_api.length ? spec.entry_api : spec.vulnerable_funcs
  const fixUrl = safeUrl(spec.fix_commit) || safeUrl(advisory.fix_urls[0])

  return (
    <article className={`finding ${v.cls}`}>
      <header className="finding-head">
        <span className={`pill ${v.cls}`}>
          <v.Icon size={13} />
          {v.label}
        </span>
        <div className="finding-ids">
          <span className="adv-id">{advisory.id}</span>
          {aliases.length > 0 && <span className="aliases">{aliases.join(' · ')}</span>}
        </div>
        {finding.accepted && <span className="tag accepted">accepted</span>}
        <span
          className="confidence"
          title={(finding.confidence_factors || []).map((c) => `${c.factor} (${c.effect})`).join(' · ') || undefined}
        >
          confidence {finding.confidence.toFixed(2)}
        </span>
      </header>

      <div className="pkg-line">
        <Package size={14} />
        <code>
          {dependency.name} {dependency.version || '(unpinned)'}
        </code>
        {advisory.fixed_in && (
          <>
            <span className="arrow">→</span>
            <code className="fixed">{advisory.fixed_in}</code>
          </>
        )}
      </div>
      {advisory.summary && <p className="adv-summary">{advisory.summary}</p>}

      <div className="functions-line">
        <span className="functions-label">functions</span>
        <code>
          {funcs.length ? funcs.slice(0, 6).join(', ') : '—'}
          {funcs.length > 6 ? ' …' : ''}
        </code>
        <span className={`tier tier-${spec.tier}`}>{TIERS[spec.tier] || spec.tier}</span>
      </div>

      {verdict === 'REACHABLE' && finding.path.length > 0 && (
        <PathStepper path={finding.path} entryKind={finding.entry_kind} runtime={finding.runtime} />
      )}
      {verdict === 'NOT_REACHABLE' && <Checklist checklist={finding.checklist} />}
      {finding.reasons.length > 0 && (
        <Reasons reasons={finding.reasons} title={verdict === 'UNCERTAIN' ? 'Why uncertain' : 'Notes'} />
      )}

      {finding.accepted && (
        <p className="accepted-line">
          Accepted in .tracelock.yml: {finding.accepted.reason}
          {finding.accepted.by ? ` (by ${finding.accepted.by})` : ''}
          {finding.accepted.until ? `, until ${finding.accepted.until}` : ''} — not counted in the exit code; OpenVEX records it as not_affected.
        </p>
      )}

      <div className="finding-foot">
        <Why finding={finding} />
        {fixUrl && (
          <a className="fix-link" href={fixUrl} target="_blank" rel="noreferrer">
            <GitCommitHorizontal size={14} />
            fix commit
          </a>
        )}
      </div>
    </article>
  )
}

export default function Results({ scanId, result }) {
  const findings = [...result.findings].sort(
    (a, b) => (ORDER[a.verdict] ?? 9) - (ORDER[b.verdict] ?? 9) || a.dependency.name.localeCompare(b.dependency.name)
  )

  return (
    <section className="results">
      <SummaryBar result={result} />

      <div className="downloads">
        <button type="button" className="btn-secondary" onClick={() => downloadJson(scanId, result)}>
          <FileJson size={14} /> JSON
        </button>
        <a className="btn-secondary" href={downloadUrl(scanId, 'result.vex.json')}>
          <Download size={14} /> OpenVEX
        </a>
        <a className="btn-secondary" href={downloadUrl(scanId, 'result.sarif')}>
          <Download size={14} /> SARIF
        </a>
      </div>

      {result.warnings.length > 0 && (
        <ul className="warnings">
          {result.warnings.map((w, i) => (
            <li key={i}>
              <TriangleAlert size={13} />
              <span>{w}</span>
            </li>
          ))}
        </ul>
      )}

      {findings.length === 0 ? (
        <div className="card empty-state">
          <ShieldCheck size={20} />
          <span>No known advisories for the {result.dependencies.length} pinned dependencies.</span>
        </div>
      ) : (
        findings.map((f) => <FindingCard key={`${f.advisory.id}:${f.dependency.name}`} finding={f} />)
      )}
    </section>
  )
}
