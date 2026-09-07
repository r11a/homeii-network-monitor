const API_ROOT = './api'

export async function api(path, options = {}) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), options.method && options.method !== 'GET' ? 180000 : 30000)
  try {
    const response = await fetch(`${API_ROOT}${path}`, {
      signal: options.signal || controller.signal,
      cache: 'no-store',
      credentials: 'include',
      ...options,
      headers: options.body instanceof FormData
        ? options.headers
        : { 'Content-Type': 'application/json', ...(options.headers || {}) },
    })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(payload.error || payload.detail || `HTTP ${response.status}`)
    return payload
  } finally {
    clearTimeout(timeout)
  }
}

export function query(path, values) {
  const params = new URLSearchParams()
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') params.set(key, value)
  })
  return api(`${path}?${params.toString()}`)
}
