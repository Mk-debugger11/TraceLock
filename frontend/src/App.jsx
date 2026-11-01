import { useState, useRef, useEffect } from 'react'
import { Loader2, AlertCircle, RefreshCw, Upload, FolderOpen, GitBranch } from 'lucide-react'
import { listScans, fetchBranches, getResult, getScan, submitScan } from './api'
import Results from './Results'

const POLL_MS = 1000

// The worker's stages, in order. Shown as a sequence while a scan runs.
const STAGES = [
  { key: 'queued', label: 'Queued' },
  { key: 'repository_fetch', label: 'Fetching project' },
  { key: 'analysis', label: 'Tracing call paths' },
  { key: 'analyzed', label: 'Done' },
]
const stageIndex = (stage) => {
  if (stage === 'repository_fetched') return 1
  const i = STAGES.findIndex((s) => s.key === stage)
  return i < 0 ? 0 : i
}

const SOURCES = [
  { key: 'github', label: 'GitHub' },
  { key: 'upload', label: 'Zip file' },
  { key: 'local', label: 'Server folder' },
]

// ?scan=<id> in the URL, so a refresh or a shared link reopens the same result.
const initialScanId = () => new URLSearchParams(window.location.search).get('scan')

function Mark() {
  return (
    <svg className="mark" viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="7" fill="currentColor" />
      <circle cx="10" cy="9" r="3" fill="#fff" />
      <circle cx="10" cy="23" r="3" fill="none" stroke="#fff" strokeWidth="2" />
      <circle cx="22" cy="23" r="3.4" fill="#E5484D" />
      <path d="M10 12v8M13 23h5.5" stroke="#fff" strokeWidth="2" />
    </svg>
  )
}

function projectLabel(scan) {
  if (!scan) return ''
  const url = scan.repository_url || ''
  if (scan.source_type === 'local' || scan.source_type === 'upload' || url.startsWith('/')) {
    return url.split(/[\\/]/).filter(Boolean).pop() || 'Uploaded project'
  }
  return url.replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, '') || 'project'
}

function Progress({ scan }) {
  const current = stageIndex(scan?.stage)
  return (
    <section className="progress" aria-live="polite">
      <ol className="stages">
        {STAGES.map((s, i) => (
          <li key={s.key} className={i < current ? 'done' : i === current ? 'current' : ''}>
            <span className="stage-dot" aria-hidden="true">
              {i === current && <Loader2 size={12} className="spin" />}
            </span>
            {s.label}
          </li>
        ))}
      </ol>
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${scan?.progress ?? 4}%` }} />
      </div>
    </section>
  )
}

function History({ history, scanId, onRefresh }) {
  if (history.length === 0) {
    return (
      <section className="history">
        <p className="empty">No scans yet. Scans you run appear here, with their verdict counts.</p>
      </section>
    )
  }
  return (
    <section className="history">
      <div className="history-head">
        <h2>Recent scans</h2>
        <button type="button" className="btn btn-quiet" onClick={onRefresh}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>
      <div className="table-scroll">
        <table className="history-table">
          <thead>
            <tr>
              <th>Project</th>
              <th>Ref</th>
              <th>Started</th>
              <th>Status</th>
              <th className="num">Reachable</th>
              <th className="num">Uncertain</th>
              <th className="num">Not reachable</th>
            </tr>
          </thead>
          <tbody>
            {history.map((h) => (
              <tr key={h.scan_id} className={h.scan_id === scanId ? 'current' : ''}>
                <td>
                  <a href={`?scan=${encodeURIComponent(h.scan_id)}`} title={h.repository_url}>
                    {projectLabel(h).slice(0, 56)}
                  </a>
                </td>
                <td className="code">{h.ref || ''}</td>
                <td>{h.created_at ? new Date(h.created_at).toLocaleString() : ''}</td>
                <td>
                  <span className={`status status-${h.status}`}>{h.status}</span>
                </td>
                <td className="num v-reachable">{h.counts ? h.counts.reachable : '–'}</td>
                <td className="num v-uncertain">{h.counts ? h.counts.uncertain : '–'}</td>
                <td className="num v-not-reachable">{h.counts ? h.counts.not_reachable : '–'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function Intro() {
  return (
    <dl className="intro">
      <div>
        <dt className="v-reachable">Reachable</dt>
        <dd>Your code calls the vulnerable function. You get the call path, line by line.</dd>
      </div>
      <div>
        <dt className="v-uncertain">Uncertain</dt>
        <dd>Something can't be ruled out. You get the line to look at, never a guess.</dd>
      </div>
      <div>
        <dt className="v-not-reachable">Not reachable</dt>
        <dd>Every check that could make it reachable passed. You get the checklist as proof.</dd>
      </div>
    </dl>
  )
}

function App() {
  const [view, setView] = useState('scan')
  const [repoType, setRepoType] = useState('github')
  const [repoUrl, setRepoUrl] = useState('')
  const [repoFile, setRepoFile] = useState(null)
  const [localPath, setLocalPath] = useState('')
  const [branch, setBranch] = useState('main')
  const [branches, setBranches] = useState([])
  const [fetchingBranches, setFetchingBranches] = useState(false)
  const [branchError, setBranchError] = useState(null)

  const [submitting, setSubmitting] = useState(false)
  const [scanId, setScanId] = useState(initialScanId)
  const [scan, setScan] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])

  const fileInputRef = useRef(null)
  const scanning = Boolean(scanId) && !result && !error

  const refreshHistory = async () => {
    try {
      const data = await listScans(20)
      setHistory(data.scans || [])
    } catch {
      /* history is a convenience; never block the page on it */
    }
  }

  useEffect(() => {
    refreshHistory()
  }, [result, error])

  useEffect(() => {
    if (!scanId) return
    let cancelled = false
    let timer

    const poll = async () => {
      try {
        const status = await getScan(scanId)
        if (cancelled) return
        setScan(status)
        if (status.status === 'done') {
          const data = await getResult(scanId)
          if (!cancelled) setResult(data)
        } else if (status.status === 'failed') {
          setError(status.error || 'The scan failed without an error message.')
        } else {
          timer = setTimeout(poll, POLL_MS)
        }
      } catch (err) {
        if (!cancelled) setError(err.message)
      }
    }

    poll()
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [scanId])

  const handleFetchBranches = async () => {
    if (!repoUrl) return
    setFetchingBranches(true)
    setBranchError(null)
    try {
      const names = (await fetchBranches(repoUrl)).branches || []
      if (names.length === 0) throw new Error('This repository has no branches.')
      setBranches(names)
      setBranch(names.includes('main') ? 'main' : names.includes('master') ? 'master' : names[0])
    } catch (err) {
      setBranchError(err.message)
      setBranches([])
    } finally {
      setFetchingBranches(false)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    setScan(null)
    setResult(null)
    setScanId(null)
    setView('scan')

    const formData = new FormData()
    formData.append('repo_type', repoType)
    if (repoType === 'github') {
      formData.append('repo_url', repoUrl)
      formData.append('branch', branch)
    } else if (repoType === 'upload' && repoFile) {
      formData.append('repo_file', repoFile)
    } else if (repoType === 'local') {
      formData.append('path', localPath)
    }
    formData.append('scan_mode', 'full')

    try {
      const { scan_id } = await submitScan(formData)
      window.history.replaceState(null, '', `?scan=${encodeURIComponent(scan_id)}`)
      setScanId(scan_id)
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const busy = submitting || scanning

  return (
    <div className="app">
      <header className="topbar">
        <a className="wordmark" href="/" aria-label="TraceLock home">
          <Mark />
          <span>TraceLock</span>
        </a>
        <nav className="nav" aria-label="Main">
          <button type="button" className={view === 'scan' ? 'active' : ''} onClick={() => setView('scan')}>
            Scan
          </button>
          <button
            type="button"
            className={view === 'history' ? 'active' : ''}
            onClick={() => {
              setView('history')
              refreshHistory()
            }}
          >
            History
            {history.length > 0 && <span className="nav-count">{history.length}</span>}
          </button>
        </nav>
      </header>

      <main className="page">
        {view === 'history' ? (
          <History history={history} scanId={scanId} onRefresh={refreshHistory} />
        ) : (
          <>
            <section className={`composer ${result || scanning ? 'compact' : ''}`}>
              {!result && !scanning && (
                <>
                  <h1>Which vulnerabilities can your code actually reach?</h1>
                  <p className="lede">
                    TraceLock reads your Python project and its dependencies' source, then follows the calls from
                    your code to each known vulnerable function. Nothing you submit is executed.
                  </p>
                </>
              )}

              <form className="scanbar" onSubmit={handleSubmit}>
                <div className="segmented" role="tablist" aria-label="Project source">
                  {SOURCES.map((s) => (
                    <button
                      key={s.key}
                      type="button"
                      role="tab"
                      aria-selected={repoType === s.key}
                      className={repoType === s.key ? 'active' : ''}
                      onClick={() => setRepoType(s.key)}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>

                <div className="scanbar-row">
                  {repoType === 'github' && (
                    <>
                      <label className="field grow">
                        <span className="field-label">Repository URL</span>
                        <input
                          type="url"
                          required
                          placeholder="https://github.com/owner/repo"
                          value={repoUrl}
                          onChange={(e) => {
                            setRepoUrl(e.target.value)
                            setBranches([])
                          }}
                        />
                      </label>
                      <label className="field branch">
                        <span className="field-label">Branch or commit</span>
                        <span className="with-action">
                          {branches.length > 0 ? (
                            <select value={branch} onChange={(e) => setBranch(e.target.value)}>
                              {branches.map((b) => (
                                <option key={b} value={b}>
                                  {b}
                                </option>
                              ))}
                            </select>
                          ) : (
                            <input
                              type="text"
                              required
                              value={branch}
                              onChange={(e) => setBranch(e.target.value)}
                              placeholder="main"
                            />
                          )}
                          <button
                            type="button"
                            className="icon-btn"
                            onClick={handleFetchBranches}
                            disabled={fetchingBranches || !repoUrl}
                            title="Load branches from GitHub"
                            aria-label="Load branches from GitHub"
                          >
                            {fetchingBranches ? <Loader2 size={15} className="spin" /> : <GitBranch size={15} />}
                          </button>
                        </span>
                      </label>
                    </>
                  )}

                  {repoType === 'upload' && (
                    <div className="field grow">
                      <span className="field-label">Project archive (.zip, up to 50 MB)</span>
                      <button type="button" className="filepick" onClick={() => fileInputRef.current?.click()}>
                        <Upload size={15} />
                        {repoFile ? (
                          <span>
                            <strong>{repoFile.name}</strong>{' '}
                            <span className="muted">{(repoFile.size / (1024 * 1024)).toFixed(1)} MB, click to replace</span>
                          </span>
                        ) : (
                          <span className="muted">Choose a .zip of the project</span>
                        )}
                      </button>
                      <input
                        ref={fileInputRef}
                        className="visually-hidden"
                        type="file"
                        accept=".zip"
                        tabIndex={-1}
                        onChange={(e) => setRepoFile(e.target.files[0] || null)}
                      />
                    </div>
                  )}

                  {repoType === 'local' && (
                    <label className="field grow">
                      <span className="field-label">Absolute path on the server</span>
                      <span className="with-icon">
                        <FolderOpen size={15} />
                        <input
                          type="text"
                          required
                          placeholder="/path/to/project"
                          value={localPath}
                          onChange={(e) => setLocalPath(e.target.value)}
                        />
                      </span>
                    </label>
                  )}

                  <button
                    type="submit"
                    className="btn btn-primary scan-btn"
                    disabled={busy || (repoType === 'upload' && !repoFile)}
                  >
                    {busy ? (
                      <>
                        <Loader2 size={16} className="spin" /> Scanning
                      </>
                    ) : (
                      'Scan project'
                    )}
                  </button>
                </div>

                {branchError && (
                  <p className="field-error">
                    <AlertCircle size={14} /> {branchError}
                  </p>
                )}
                {repoType === 'local' && (
                  <p className="field-hint">
                    Server folders are off unless the API runs with <code>TRACELOCK_ALLOW_LOCAL_PATHS=1</code>.
                  </p>
                )}
              </form>
            </section>

            {scanning && <Progress scan={scan} />}

            {error && (
              <div className="notice notice-error" role="alert">
                <AlertCircle size={18} />
                <div>
                  <strong>The scan stopped.</strong>
                  <pre>{error}</pre>
                </div>
              </div>
            )}

            {result && <Results scanId={scanId} result={result} project={projectLabel(scan)} />}

            {!result && !scanning && !error && <Intro />}
          </>
        )}
      </main>
    </div>
  )
}

export default App
