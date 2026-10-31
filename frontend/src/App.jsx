import { useState, useRef } from 'react'
import {
  Shield,
  FolderArchive,
  GitBranch,
  ArrowRight,
  Loader2,
  CheckCircle2,
  AlertCircle,
  UploadCloud,
  FileCode2,
  RefreshCw
} from 'lucide-react'

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

function App() {
  const [repoType, setRepoType] = useState('github')
  const [repoUrl, setRepoUrl] = useState('')
  const [repoFile, setRepoFile] = useState(null)
  const [branch, setBranch] = useState('main')
  const [branches, setBranches] = useState([])
  const [fetchingBranches, setFetchingBranches] = useState(false)
  const [branchError, setBranchError] = useState(null)

  const [loading, setLoading] = useState(false)
  const [response, setResponse] = useState(null)
  const [error, setError] = useState(null)

  const fileInputRef = useRef(null)

  const handleFetchBranches = async () => {
    if (!repoUrl) return
    setFetchingBranches(true)
    setBranchError(null)

    try {
      const res = await fetch('http://127.0.0.1:5001/api/branches', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl }),
      })

      const data = await res.json()

      if (!res.ok) {
        throw new Error(data.error || 'Failed to fetch branches')
      }

      const branchNames = data.branches || []

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
    setLoading(true)
    setError(null)
    setResponse(null)

    const formData = new FormData()
    formData.append('repo_type', repoType)
    if (repoType === 'github') {
      formData.append('repo_url', repoUrl)
    } else if (repoFile) {
      formData.append('repo_file', repoFile)
    }
    formData.append('branch', branch)
    formData.append('scan_mode', 'full')

    try {
      const res = await fetch('http://127.0.0.1:5001/api/analyze', {
        method: 'POST',
        body: formData,
      })

      if (!res.ok) {
        throw new Error(`Server returned error status ${res.status}`)
      }

      const data = await res.json()
      setResponse(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

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
          Submit your Python repository to trace execution paths and reachability of dangerous dependencies.
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
            GitHub Repository
          </button>
          <button
            type="button"
            className={`source-tab-btn ${repoType === 'upload' ? 'active' : ''}`}
            onClick={() => setRepoType('upload')}
          >
            <FolderArchive size={16} />
            Upload Archive (.zip)
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {repoType === 'github' ? (
            /* GitHub URL Input */
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
          ) : (
            /* File Upload Dropzone */
            <div className="form-group">
              <label className="form-label">Repository Archive</label>
              <div
                className="dropzone"
                onClick={() => fileInputRef.current?.click()}
              >
                <UploadCloud size={32} className="dropzone-icon" />
                <div className="dropzone-text">
                  {repoFile ? 'Click to replace file' : 'Click to select project archive'}
                </div>
                <div className="dropzone-subtext">
                  Supports .zip, .tar.gz, .tar
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  required={!repoFile}
                  accept=".zip,.tar.gz,.tar"
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

          {/* Submit Button */}
          <button type="submit" className="btn-submit" disabled={loading}>
            {loading ? (
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

      {/* Error Output */}
      {error && (
        <div className="result-card error">
          <div className="result-header error">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <AlertCircle size={16} />
              <span>Analysis Request Failed</span>
            </div>
          </div>
          <div className="result-body">
            <pre>{error}</pre>
          </div>
        </div>
      )}

      {/* Response Output */}
      {response && (
        <div className="result-card success">
          <div className="result-header success">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <CheckCircle2 size={16} />
              <span>Backend Response Received</span>
            </div>
            <span style={{ fontSize: '11px', color: '#64748b' }}>HTTP 200 OK</span>
          </div>
          <div className="result-body">
            <pre>{JSON.stringify(response, null, 2)}</pre>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
