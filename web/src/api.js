// In production the API server also serves this SPA, so default to SAME-ORIGIN (relative) requests — that is
// what makes a remote/cross-host deploy work with no rebuild: the browser talks to whatever host served the
// page. For local dev (Vite on :5173, API on :8000) VITE_API_BASE is set in web/.env.development.
const BASE = import.meta.env.VITE_API_BASE || ''

export function apiBase() { return BASE }
export function token() { return localStorage.getItem('token') || '' }
export function setToken(t) { t ? localStorage.setItem('token', t) : localStorage.removeItem('token') }
export function getUser() { try { return JSON.parse(localStorage.getItem('user') || 'null') } catch { return null } }
export function setUser(u) { u ? localStorage.setItem('user', JSON.stringify(u)) : localStorage.removeItem('user') }
export function isAdmin() { return (getUser() || {}).role === 'admin' }
export function getActivitySeen() { return parseInt(localStorage.getItem('activity_seen') || '0') }
export function setActivitySeen(id) { if (id) localStorage.setItem('activity_seen', String(id)) }

async function req(method, path, body) {
  const headers = { 'Content-Type': 'application/json' }
  const t = token()
  if (t) headers.Authorization = 'Bearer ' + t
  const r = await fetch(BASE + path, {
    method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (r.status === 401) {
    setToken(''); setUser('')
    if (location.hash !== '#/login') location.hash = '#/login'
  }
  const txt = await r.text()
  const data = txt ? JSON.parse(txt) : null
  if (!r.ok) throw new Error((data && (data.detail || data.error)) || r.statusText)
  return data
}

export const api = {
  get: (p) => req('GET', p),
  post: (p, b) => req('POST', p, b),
  patch: (p, b) => req('PATCH', p, b),
  del: (p) => req('DELETE', p),
  login: (username, password, code) => req('POST', '/auth/login', { username, password, code }),
  me: () => req('GET', '/auth/me'),
  changePassword: (current_password, new_password) =>
    req('POST', '/auth/change-password', { current_password, new_password }),
}
