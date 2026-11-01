import { useMemo, useState, useEffect } from 'react'
import { Check, X, ChevronDown, ChevronLeft, Download, Search, TriangleAlert, Zap } from 'lucide-react'
import { downloadUrl } from './api'

// Display only: every verdict, path and checklist comes from the backend's ScanResult JSON.
const ORDER = { REACHABLE: 0, UNCERTAIN: 1, NOT_REACHABLE: 2 }

const VERDICTS = {
  REACHABLE: { label: 'Reachable', cls: 'reachable' },
  UNCERTAIN: { label: 'Uncertain', cls: 'uncertain' },
  NOT_REACHABLE: { label: 'Not reachable', cls: 'not-reachable' },
}

const TIERS = {
  curated: 'hand-verified knowledge base',
  ecosystem_specific: 'advisory import data',
  fix_commit: 'the fix commit',
  llm_verified: 'LLM proposal, verified against source',
  native_mapped: 'the native (C/Rust) fix, mapped to its Python wrappers',
  none: 'no function data',
}

const ENTRY = {
  main: 'a script entry point',
  route: 'a web route',
  module: 'module import',
  test: 'a test',
  runtime: 'a traced run',
  orphan: 'a function nothing calls statically',
}

const CHECKS = {
  imported: 'The package is imported',
  no_call_to_vulnerable_api: 'No call reaches the vulnerable functions',
  all_call_sites_safe: 'Every call uses a safe argument',
  no_unresolved_call_with_same_name: 'No untyped call with the same name',
  no_dynamic_markers: 'No getattr, eval, importlib or pickle loads',
  no_string_reference: 'No string names the function',
  no_star_import: 'No star import of the package',
  function_data_available: 'The affected functions are known',
  not_transitively_required: 'Not pulled in by another package the app uses',
}

const humanize = (key) => {
  const s = key.replaceAll('_', ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`
const keyOf = (f) => `${f.advisory.id}:${f.dependency.name}`
const safeUrl = (url) => (typeof url === 'string' && /^https?:\/\//.test(url) ? url : null)
const topPackage = (qualname) => qualname.split('.')[0]

function downloadJson(scanId, result) {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `tracelock-${scanId}.json`
  a.click()
  URL.revokeObjectURL(url)
}

/* ---------- summary ---------- */

function Ledger({ result, project, counts, filter, setFilter }) {
  const total = result.findings.length
  const stats = result.stats || {}
  const segments = ['REACHABLE', 'UNCERTAIN', 'NOT_REACHABLE']
  return (
    <section className="ledger">
      <div className="ledger-head">
        <h1>{project || 'Scan result'}</h1>
        <ul className="facts">
          <li>{plural(total, 'advisory', 'advisories')}</li>
          <li>{plural(result.dependencies.length, 'dependency', 'dependencies')}</li>
          <li>{plural(stats.python_files ?? 0, 'Python file')}</li>
          {typeof stats.seconds === 'number' && <li>{stats.seconds < 0.01 ? 'under 0.01' : stats.seconds} s</li>}
        </ul>
      </div>

      {total > 0 && (
        <div className="ratio" role="img" aria-label={segments.map((v) => `${counts[v]} ${VERDICTS[v].label}`).join(', ')}>
          {segments.map((v) =>
            counts[v] ? (
              <span key={v} className={`ratio-seg ${VERDICTS[v].cls}`} style={{ flexGrow: counts[v] }} />
            ) : null
          )}
        </div>
      )}

      <div className="filters" role="tablist" aria-label="Filter by verdict">
        {segments.map((v) => (
          <button
            key={v}
            type="button"
            role="tab"
            aria-selected={filter === v}
            className={`filter ${VERDICTS[v].cls} ${filter === v ? 'active' : ''}`}
            onClick={() => setFilter(filter === v ? 'ALL' : v)}
          >
            <span className="filter-num">{counts[v]}</span>
            <span className="filter-label">{VERDICTS[v].label}</span>
          </button>
        ))}
        <button
          type="button"
          role="tab"
          aria-selected={filter === 'ALL'}
          className={`filter all ${filter === 'ALL' ? 'active' : ''}`}
          onClick={() => setFilter('ALL')}
        >
          <span className="filter-num">{total}</span>
          <span className="filter-label">All</span>
        </button>
      </div>
    </section>
  )
}

function Warnings({ warnings }) {
  const [open, setOpen] = useState(false)
  if (!warnings.length) return null
  return (
    <div className="warnings">
      <button type="button" className="warnings-toggle" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <TriangleAlert size={15} />
        {plural(warnings.length, 'scan warning')}
        <ChevronDown size={14} className={`chev ${open ? 'open' : ''}`} />
      </button>
      {open && (
        <ul>
          {warnings.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

/* ---------- list ---------- */

function FindingRow({ finding, selected, onSelect }) {
  const v = VERDICTS[finding.verdict] || VERDICTS.UNCERTAIN
  return (
    <li>
      <button
        type="button"
        className={`row ${v.cls} ${selected ? 'selected' : ''}`}
        onClick={onSelect}
        aria-current={selected ? 'true' : undefined}
      >
        <span className="row-top">
          <span className="row-pkg">
            {finding.dependency.name} <span className="row-ver">{finding.dependency.version || 'unpinned'}</span>
          </span>
          <span className={`row-verdict ${v.cls}`}>{v.label}</span>
        </span>
        <span className="row-summary">{finding.advisory.summary || finding.advisory.id}</span>
        <span className="row-id">
          {finding.advisory.aliases.find((a) => a.startsWith('CVE-')) || finding.advisory.id}
          {finding.accepted && <span className="row-accepted">Accepted</span>}
        </span>
      </button>
    </li>
  )
}

/* ---------- detail ---------- */

// App frames carry a file; library frames do not. The last frame is the vulnerable symbol.
function buildTrace(path) {
  const groups = []
  path.forEach((step, i) => {
    const isLast = i === path.length - 1
    if (step.file) {
      groups.push({ kind: 'app', steps: [step] })
    } else if (isLast) {
      groups.push({ kind: 'target', steps: [step] })
    } else {
      const pkg = topPackage(step.qualname)
      const prev = groups[groups.length - 1]
      if (prev && prev.kind === 'lib' && prev.pkg === pkg) prev.steps.push(step)
      else groups.push({ kind: 'lib', pkg, steps: [step] })
    }
  })
  return groups
}

function LibraryGroup({ group }) {
  const [open, setOpen] = useState(false)
  const long = group.steps.length > 3
  const shown = long && !open ? [group.steps[0], group.steps[group.steps.length - 1]] : group.steps
  return (
    <li className="frame lib">
      <span className="frame-node" aria-hidden="true" />
      <div className="frame-body">
        <div className="frame-pkg">Inside {group.pkg}</div>
        <ol className="lib-steps">
          {shown.map((s, i) => (
            <li key={i}>
              {long && !open && i === 1 && (
                <button type="button" className="lib-more" onClick={() => setOpen(true)}>
                  {group.steps.length - 2} more steps
                </button>
              )}
              <code>{s.qualname}</code>
            </li>
          ))}
        </ol>
      </div>
    </li>
  )
}

function Trace({ finding }) {
  const groups = buildTrace(finding.path)
  return (
    <section className="block">
      <h3>
        Call path
        <span className="block-note">starts at {ENTRY[finding.entry_kind] || 'an unknown entry point'}</span>
        {finding.runtime?.executed && (
          <span className="badge runtime">
            <Zap size={12} /> Confirmed at runtime
          </span>
        )}
      </h3>
      <ol className="trace">
        {groups.map((g, i) => {
          if (g.kind === 'lib') return <LibraryGroup key={i} group={g} />
          const step = g.steps[0]
          if (g.kind === 'target') {
            return (
              <li key={i} className="frame target">
                <span className="frame-node" aria-hidden="true" />
                <div className="frame-body">
                  <code className="frame-symbol">{step.qualname}</code>
                  <div className="frame-caption">The vulnerable function</div>
                </div>
              </li>
            )
          }
          return (
            <li key={i} className="frame app">
              <span className="frame-node" aria-hidden="true" />
              <div className="frame-body">
                <div className="frame-loc">
                  <code className="frame-file">
                    {step.file}:{step.line}
                  </code>
                  <code className="frame-fn">{step.qualname.split('.').slice(-1)[0]}</code>
                </div>
                {step.code && <pre className="frame-code">{step.code}</pre>}
              </div>
            </li>
          )
        })}
      </ol>
    </section>
  )
}

function Checklist({ checklist, dependency }) {
  // `imported` is a fact about the app, not a pass/fail check: never importing the package is the strongest "safe".
  const items = Object.entries(checklist).filter(([key, value]) => typeof value === 'boolean' && key !== 'imported')
  if (!items.length) return null
  const passed = items.filter(([, ok]) => ok).length
  return (
    <section className="block">
      <h3>
        Why it is not reachable
        <span className="block-note">
          {passed} of {items.length} checks passed
        </span>
      </h3>
      {checklist.imported === false && (
        <p className="check-lead">
          Your code never imports {dependency.name}
          {checklist.not_transitively_required ? ', and no package it imports pulls it in.' : '.'}
        </p>
      )}
      <ul className="checks">
        {items.map(([key, ok]) => (
          <li key={key} className={ok ? 'ok' : 'no'}>
            {ok ? <Check size={14} /> : <X size={14} />}
            <span>{CHECKS[key] || humanize(key)}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

function Reasons({ reasons, verdict }) {
  const also = reasons.filter((r) => r.kind === 'also_called_at')
  const rest = reasons.filter((r) => r.kind !== 'also_called_at')
  return (
    <>
      {rest.length > 0 && (
        <section className="block">
          <h3>{verdict === 'UNCERTAIN' ? 'What to check' : 'Notes'}</h3>
          <ul className="reasons">
            {rest.map((r, i) => (
              <li key={i}>
                <div className="reason-head">
                  <span className="reason-kind">{humanize(r.kind)}</span>
                  {r.file && (
                    <code>
                      {r.file}
                      {r.line ? `:${r.line}` : ''}
                    </code>
                  )}
                </div>
                {r.detail && <p>{r.detail}</p>}
                {r.check && <p className="reason-check">{r.check}</p>}
              </li>
            ))}
          </ul>
        </section>
      )}
      {also.length > 0 && (
        <section className="block">
          <h3>Also called at</h3>
          <ul className="also">
            {also.map((r, i) => (
              <li key={i}>
                <code className="frame-file">
                  {r.file}:{r.line}
                </code>
                <code>{r.detail}</code>
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  )
}

function Why({ finding }) {
  const [open, setOpen] = useState(false)
  const factors = finding.confidence_factors || []
  if (!finding.explanation && !factors.length) return null
  return (
    <section className="why">
      <button type="button" className="why-toggle" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        How TraceLock decided
        <ChevronDown size={15} className={`chev ${open ? 'open' : ''}`} />
      </button>
      {open && (
        <div className="why-body">
          {finding.explanation && <p>{finding.explanation}</p>}
          {factors.length > 0 && (
            <table className="factors">
              <caption>Confidence {finding.confidence.toFixed(2)}, built from</caption>
              <tbody>
                {factors.map((c, i) => (
                  <tr key={i}>
                    <th scope="row">{c.factor}</th>
                    <td className="code">{c.effect}</td>
                    <td>{c.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </section>
  )
}

const LLM_STATUS = {
  used: 'ran for this finding',
  cached: 'answer reused from cache',
  not_needed: 'not needed: deterministic analysis mapped the code',
  disabled: 'off (TRACELOCK_LLM_ENABLED is not set)',
  unavailable: 'unavailable',
  model_missing: 'model not pulled',
  timeout: 'timed out',
  bad_response: 'reply rejected (invalid output)',
  http_error: 'server error',
  skipped_budget: 'skipped: scan inference budget used up',
}

/* How function data was found: deterministic native mapping and, where it left gaps, the local LLM.
   Model output is shown only as verified / rejected candidates, never as evidence on its own. */
function Discovery({ discovery, verdict }) {
  if (!discovery || (!discovery.native && !discovery.llm)) return null
  const llm = discovery.llm || {}
  const nat = discovery.native || {}
  const checks = discovery.checks || {}
  const failed = ['unavailable', 'model_missing', 'timeout', 'http_error', 'bad_response'].includes(llm.status)
  const wrappers = nat.python_wrappers || []
  return (
    <section className="discovery">
      <h3>Function discovery</h3>
      {failed ? (
        <p className="discovery-warn">
          Local LLM {LLM_STATUS[llm.status]}. Deterministic analysis completed.
          {verdict === 'UNCERTAIN' ? ' The finding remains UNCERTAIN.' : ''}
        </p>
      ) : null}
      <dl className="discovery-facts">
        <div><dt>Method</dt><dd>{discovery.method === 'deterministic+llm' ? 'deterministic + local LLM' : 'deterministic'}</dd></div>
        {llm.provider && (
          <div>
            <dt>Local LLM</dt>
            <dd>
              {llm.provider === 'ollama' ? 'Ollama' : llm.provider}, <code>{llm.model}</code>
              {llm.execution === 'docker' ? ', Docker container' : ''}: {LLM_STATUS[llm.status] || llm.status}
              {llm.latency_ms ? ` (${(llm.latency_ms / 1000).toFixed(1)} s)` : ''}
            </dd>
          </div>
        )}
        {llm.candidates_suggested > 0 && (
          <div>
            <dt>Candidates</dt>
            <dd>{llm.candidates_suggested} suggested, {llm.candidates_verified} verified, {llm.candidates_rejected} rejected</dd>
          </div>
        )}
        {checks.source_verification && <div><dt>Source verification</dt><dd>{checks.source_verification}</dd></div>}
        {checks.package_version_verification && <div><dt>Pinned version check</dt><dd>{checks.package_version_verification}</dd></div>}
        {checks.native_api_mapping && <div><dt>Native API mapping</dt><dd>{checks.native_api_mapping}</dd></div>}
      </dl>
      {(nat.changed_functions || []).length > 0 && (
        <p className="discovery-line">
          Fix changes native <code>{nat.changed_functions.map((c) => c.name).slice(0, 4).join(', ')}</code>
          {wrappers.length > 0 && (
            <>, reached from Python by <code>{wrappers.slice(0, 3).map((w) => w.symbol).join(', ')}</code>
              {wrappers.length > 3 ? ` and ${wrappers.length - 3} more` : ''}</>
          )}
        </p>
      )}
      {(llm.candidates || []).length > 0 && (
        <ul className="discovery-candidates">
          {llm.candidates.map((c, i) => (
            <li key={i} className={c.accepted ? 'ok' : 'rejected'}>
              <code>{c.resolved || c.symbol}</code> {c.accepted ? 'verified' : 'rejected'}
              <span>{c.reason}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function Detail({ finding, onBack }) {
  const { advisory, dependency, spec, verdict } = finding
  const v = VERDICTS[verdict] || VERDICTS.UNCERTAIN
  const aliases = advisory.aliases.filter((a) => a !== advisory.id)
  const funcs = spec.entry_api.length ? spec.entry_api : spec.vulnerable_funcs
  const fixUrl = safeUrl(spec.fix_commit) || safeUrl(advisory.fix_urls[0])
  const advisoryUrl = `https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}`

  return (
    <article className={`detail ${v.cls}`} aria-label={`${advisory.id} in ${dependency.name}`}>
      <button type="button" className="back" onClick={onBack}>
        <ChevronLeft size={16} /> All findings
      </button>

      <header className="detail-head">
        <div className="detail-verdict">
          <span className={`verdict-word ${v.cls}`}>{v.label}</span>
          <span className="confidence" title="How exact the evidence is. It orders findings and never changes a verdict.">
            confidence {finding.confidence.toFixed(2)}
          </span>
        </div>
        <h2>{advisory.summary || advisory.id}</h2>
        <p className="detail-ids">
          <a href={advisoryUrl} target="_blank" rel="noreferrer">
            {advisory.id}
          </a>
          {aliases.map((a) => (
            <span key={a}>{a}</span>
          ))}
        </p>
      </header>

      <dl className="detail-facts">
        <div>
          <dt>Package</dt>
          <dd>
            <code>
              {dependency.name} {dependency.version || '(unpinned)'}
            </code>
          </dd>
        </div>
        <div>
          <dt>Fixed in</dt>
          <dd>{advisory.fixed_in ? <code>{advisory.fixed_in}</code> : 'no fixed release yet'}</dd>
        </div>
        <div className="wide">
          <dt>Affected functions, from {TIERS[spec.tier] || spec.tier}</dt>
          <dd>
            {funcs.length ? (
              <code>
                {funcs.slice(0, 5).join(', ')}
                {funcs.length > 5 ? `, and ${funcs.length - 5} more` : ''}
              </code>
            ) : (
              'The advisory does not say which functions are affected.'
            )}
          </dd>
        </div>
      </dl>

      {finding.accepted && (
        <div className="accepted">
          <strong>Accepted in .tracelock.yml</strong>
          {finding.accepted.by ? ` by ${finding.accepted.by}` : ''}
          {finding.accepted.until ? `, until ${finding.accepted.until}` : ''}: {finding.accepted.reason}. It does not
          count toward the exit code, and OpenVEX records it as not affected.
        </div>
      )}

      {verdict === 'REACHABLE' && finding.path.length > 0 && <Trace finding={finding} />}
      {verdict === 'NOT_REACHABLE' && <Checklist checklist={finding.checklist} dependency={dependency} />}
      {finding.reasons.length > 0 && <Reasons reasons={finding.reasons} verdict={verdict} />}

      <Discovery discovery={spec.discovery} verdict={verdict} />
      <Why finding={finding} />

      {(fixUrl || advisory.fixed_in) && (
        <footer className="detail-foot">
          {advisory.fixed_in && (
            <span>
              Upgrade with <code>{`${dependency.name}>=${advisory.fixed_in}`}</code>
            </span>
          )}
          {fixUrl && (
            <a href={fixUrl} target="_blank" rel="noreferrer">
              View the fix commit
            </a>
          )}
        </footer>
      )}
    </article>
  )
}

/* ---------- page ---------- */

export default function Results({ scanId, result, project }) {
  const counts = useMemo(() => {
    const c = { REACHABLE: 0, UNCERTAIN: 0, NOT_REACHABLE: 0 }
    result.findings.forEach((f) => (c[f.verdict] = (c[f.verdict] || 0) + 1))
    return c
  }, [result])

  const [filter, setFilter] = useState('ALL')
  const [query, setQuery] = useState('')
  const [selectedKey, setSelectedKey] = useState(null)
  const [showDetailOnMobile, setShowDetailOnMobile] = useState(false)

  const findings = useMemo(() => {
    const q = query.trim().toLowerCase()
    return [...result.findings]
      .filter((f) => filter === 'ALL' || f.verdict === filter)
      .filter(
        (f) =>
          !q ||
          f.dependency.name.toLowerCase().includes(q) ||
          f.advisory.id.toLowerCase().includes(q) ||
          f.advisory.aliases.some((a) => a.toLowerCase().includes(q)) ||
          (f.advisory.summary || '').toLowerCase().includes(q)
      )
      .sort(
        (a, b) =>
          (ORDER[a.verdict] ?? 9) - (ORDER[b.verdict] ?? 9) ||
          b.confidence - a.confidence ||
          a.dependency.name.localeCompare(b.dependency.name)
      )
  }, [result, filter, query])

  const selected = findings.find((f) => keyOf(f) === selectedKey) || findings[0]

  useEffect(() => {
    setShowDetailOnMobile(false)
  }, [filter])

  return (
    <div className="results">
      <Ledger result={result} project={project} counts={counts} filter={filter} setFilter={setFilter} />

      <div className="toolbar">
        <label className="search">
          <Search size={15} aria-hidden="true" />
          <input
            type="search"
            placeholder="Filter by package, CVE or summary"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Filter findings"
          />
        </label>
        <div className="exports">
          <span className="muted">Export</span>
          <button type="button" className="btn btn-quiet" onClick={() => downloadJson(scanId, result)}>
            <Download size={14} /> JSON
          </button>
          <a className="btn btn-quiet" href={downloadUrl(scanId, 'result.vex.json')}>
            <Download size={14} /> OpenVEX
          </a>
          <a className="btn btn-quiet" href={downloadUrl(scanId, 'result.sarif')}>
            <Download size={14} /> SARIF
          </a>
        </div>
      </div>

      <Warnings warnings={result.warnings} />

      {result.findings.length === 0 ? (
        <p className="empty">
          No known advisories affect the {plural(result.dependencies.length, 'pinned dependency', 'pinned dependencies')}.
        </p>
      ) : (
        <div className={`workspace ${showDetailOnMobile ? 'show-detail' : ''}`}>
          <div className="list-pane">
            {findings.length === 0 ? (
              <p className="empty">No findings match “{query}”.</p>
            ) : (
              <ul className="rows">
                {findings.map((f) => (
                  <FindingRow
                    key={keyOf(f)}
                    finding={f}
                    selected={selected && keyOf(f) === keyOf(selected)}
                    onSelect={() => {
                      setSelectedKey(keyOf(f))
                      setShowDetailOnMobile(true)
                    }}
                  />
                ))}
              </ul>
            )}
          </div>
          <div className="detail-pane">
            {selected && <Detail key={keyOf(selected)} finding={selected} onBack={() => setShowDetailOnMobile(false)} />}
          </div>
        </div>
      )}
    </div>
  )
}
