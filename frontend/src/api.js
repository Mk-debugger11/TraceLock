// All calls to the TraceLock API. Errors come back as {"error": "..."}.
export const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:5001'

async function request(path, options) {
  const res = await fetch(`${API_BASE}${path}`, options)
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(data.error || `Server returned error status ${res.status}`)
  }
  return data
}

export const fetchBranches = (repoUrl) =>
  request('/api/branches', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo_url: repoUrl }),
  })

export const submitScan = (formData) => request('/api/analyze', { method: 'POST', body: formData })

export const getScan = (scanId) => request(`/api/scans/${encodeURIComponent(scanId)}`)

export const getResult = (scanId) => request(`/api/scans/${encodeURIComponent(scanId)}/result`)

export const downloadUrl = (scanId, file) => `${API_BASE}/api/scans/${encodeURIComponent(scanId)}/${file}`

export const listScans = (limit = 12) => request(`/api/scans?limit=${limit}`)
