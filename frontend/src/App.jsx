import { useState, useRef, useEffect } from 'react'
import {
  Shield,
  FolderArchive,
  FolderOpen,
  GitBranch,
  ArrowRight,
  Loader2,
  AlertCircle,
  UploadCloud,
  FileCode2,
  RefreshCw
} from 'lucide-react'
import { listScans, fetchBranches, getResult, getScan, submitScan } from './api'
import Results from './Results'

const POLL_MS = 1000

const STAGE_LABELS = {
  queued: 'Waiting for the worker',
  repository_fetch: 'Fetching the project',
  repository_fetched: 'Project fetched',
  analysis: 'Tracing call paths to vulnerable functions',
  analyzed: 'Done',
}

// Clean GitHub SVG icon
const GithubIcon = ({ size = 16, className = '' }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="currentColor"
    className={className}
    style={{ display: 'inline-block', verticalAlign: 'middle' }}
  >
    <path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
    />
  </svg>
)

// ?scan=<id> in the URL, so a refresh or a shared link reopens the same result.
const initialScanId = () => new URLSearchParams(window.location.search).get('scan')

function App() {
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

  const fileInputRef = useRef(null)
  const scanning = Boolean(scanId) && !result && !error
  const [history, setHistory] = useState([])

  const refreshHistory = async () => {
    try {
      const data = await listScans(12)
      setHistory(data.scans || [])
    } catch {
      /* history is a convenience; never block the page on it */
    }
  }

  useEffect(() => { refreshHistory() }, [result, error])

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
          setError(status.error || 'The scan failed')
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
      const branchNames = (await fetchBranches(repoUrl)).branches || []

      if (branchNames.length === 0) {
        throw new Error('No branches found in this repository')
      }

      setBranches(branchNames)
      if (branchNames.includes('main')) {
        setBranch('main')
      } else if (branchNames.includes('master')) {
        setBranch('master')
      } else {
        setBranch(branchNames[0])
      }
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
    <div>
      {/* Header */}
      <header className="header">
        <div className="brand-badge">
          <Shield size={14} />
          <span>TraceLock Security</span>
        </div>
        <h1 className="brand-title">
          Vulnerability Reachability Analyzer
        </h1>
        <p className="brand-subtitle">
          Submit a Python project to see whether its code can actually reach the vulnerable functions in its dependencies.
        </p>
      </header>

      {/* Main Form Card */}
      <div className="card">
        {/* Source Switcher */}
        <div className="source-tabs">
          <button
            type="button"
            className={`source-tab-btn ${repoType === 'github' ? 'active' : ''}`}
            onClick={() => setRepoType('github')}
          >
            <GithubIcon size={16} />
            GitHub
          </button>
          <button
            type="button"
            className={`source-tab-btn ${repoType === 'upload' ? 'active' : ''}`}
            onClick={() => setRepoType('upload')}
          >
            <FolderArchive size={16} />
            Upload .zip
          </button>
          <button
            type="button"
            className={`source-tab-btn ${repoType === 'local' ? 'active' : ''}`}
            onClick={() => setRepoType('local')}
          >
            <FolderOpen size={16} />
            Local folder
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {repoType === 'github' && (
            <>
              {/* GitHub URL Input */}
              <div className="form-group">
                <label className="form-label">GitHub Repository URL</label>
                <div className="input-with-action">
                  <div className="input-wrapper" style={{ flex: 1 }}>
                    <span className="input-icon">
                      <GithubIcon size={16} />
                    </span>
                    <input
                      type="text"
                      required
                      className="text-input"
                      placeholder="https://github.com/owner/repo"
                      value={repoUrl}
                      onChange={(e) => {
                        setRepoUrl(e.target.value)
                        setBranches([])
                      }}
                    />
                  </div>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={handleFetchBranches}
                    disabled={fetchingBranches || !repoUrl}
                  >
                    {fetchingBranches ? (
                      <>
                        <Loader2 size={14} className="spin" />
                        Fetching
                      </>
                    ) : (
                      <>
                        <RefreshCw size={14} />
                        Fetch Branches
                      </>
                    )}
                  </button>
                </div>
                {branchError && (
                  <div className="helper-error">
                    <AlertCircle size={13} />
                    <span>{branchError}</span>
                  </div>
                )}
              </div>

              {/* Branch / Commit Selection */}
              <div className="form-group">
                <label className="form-label">Target Branch / Commit</label>
                <div className="input-wrapper">
                  <GitBranch size={16} className="input-icon" />
                  {branches.length > 0 ? (
                    <select
                      className="select-input"
                      value={branch}
                      onChange={(e) => setBranch(e.target.value)}
                    >
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
                      className="text-input"
                      value={branch}
                      onChange={(e) => setBranch(e.target.value)}
                      placeholder="e.g. main, master, or commit hash"
                    />
                  )}
                </div>
                {branches.length > 0 && (
                  <div className="branch-counter">
                    {branches.length} branches discovered
                  </div>
                )}
              </div>
            </>
          )}

          {repoType === 'upload' && (
            /* File Upload Dropzone */
            <div className="form-group">
              <label className="form-label">Project Archive</label>
              <div
                className="dropzone"
                onClick={() => fileInputRef.current?.click()}
              >
                <UploadCloud size={32} className="dropzone-icon" />
                <div className="dropzone-text">
                  {repoFile ? 'Click to replace file' : 'Click to select project archive'}
                </div>
                <div className="dropzone-subtext">
                  .zip up to 50 MB
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  required={!repoFile}
                  accept=".zip"
                  onChange={(e) => setRepoFile(e.target.files[0])}
                />
              </div>
              {repoFile && (
                <div className="selected-file-badge">
                  <FileCode2 size={16} />
                  <span>{repoFile.name}</span>
                  <span style={{ color: '#64748b', fontSize: '11px' }}>
                    ({(repoFile.size / (1024 * 1024)).toFixed(2)} MB)
                  </span>
                </div>
              )}
            </div>
          )}

          {repoType === 'local' && (
            <div className="form-group">
              <label className="form-label">Folder on the server</label>
              <div className="input-wrapper">
                <FolderOpen size={16} className="input-icon" />
                <input
                  type="text"
                  required
                  className="text-input"
                  placeholder="/absolute/path/to/project"
                  value={localPath}
                  onChange={(e) => setLocalPath(e.target.value)}
                />
              </div>
              <div className="branch-counter">
                The API must run with TRACELOCK_ALLOW_LOCAL_PATHS=1
              </div>
            </div>
          )}

          {/* Submit Button */}
          <button type="submit" className="btn-submit" disabled={busy}>
            {busy ? (
              <>
                <Loader2 size={18} className="spin" />
                <span>Running Reachability Analysis...</span>
              </>
            ) : (
              <>
                <span>Start Full Analysis</span>
                <ArrowRight size={17} />
              </>
            )}
          </button>
        </form>
      </div>

      {/* Progress */}
      {scanning && (
        <div className="progress-card">
          <div className="progress-head">
            <span>{STAGE_LABELS[scan?.stage] || 'Starting scan'}</span>
            <span className="progress-pct">{scan?.progress ?? 0}%</span>
          </div>
          <div className="progress-track">
            <div className="progress-fill" style={{ width: `${scan?.progress ?? 0}%` }} />
          </div>
        </div>
      )}

      {/* Error Output */}
      {error && (
        <div className="result-card error">
          <div className="result-header error">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <AlertCircle size={16} />
              <span>Analysis Failed</span>
            </div>
          </div>
          <div className="result-body">
            <pre>{error}</pre>
          </div>
        </div>
      )}

      {result && <Results scanId={scanId} result={result} />}

      {/* Recent scans */}
      {history.length > 0 && (
        <div className="card history-card">
          <div className="history-head">
            <span>Recent scans</span>
            <button type="button" className="btn-secondary" onClick={refreshHistory}>
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
          <table className="history-table">
            <thead>
              <tr><th>When</th><th>Source</th><th>Ref</th><th>Status</th><th>Reachable</th><th>Not reachable</th><th>Uncertain</th></tr>
            </thead>
            <tbody>
              {history.map((h) => (
                <tr key={h.scan_id} className={h.scan_id === scanId ? 'current' : ''}>
                  <td>{h.created_at ? new Date(h.created_at).toLocaleString() : ''}</td>
                  <td className="mono" title={h.repository_url}>
                    <a href={`?scan=${h.scan_id}`}>{(h.repository_url || '').replace('https://github.com/', '').slice(0, 48) || h.source_type}</a>
                  </td>
                  <td className="mono">{h.ref || ''}</td>
                  <td><span className={`status-pill ${h.status}`}>{h.status}</span></td>
                  <td className="num reachable">{h.counts ? h.counts.reachable : '–'}</td>
                  <td className="num not-reachable">{h.counts ? h.counts.not_reachable : '–'}</td>
                  <td className="num uncertain">{h.counts ? h.counts.uncertain : '–'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default App
