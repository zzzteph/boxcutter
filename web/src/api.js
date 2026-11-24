// The UI talks to the same server that served it, under /api. Authentication is HTTP basic auth handled by the
// browser itself (it asks once and then sends the credentials with every request, EventSource and download
// link included), so there is no token or login page here. In dev, Vite proxies /api to the server.
const BASE = '/api'

export function apiUrl(path) { return BASE + path }
export function getActivitySeen() { return parseInt(localStorage.getItem('activity_seen') || '0') }
export function setActivitySeen(id) { if (id) localStorage.setItem('activity_seen', String(id)) }

async function handle(r) {
  if (r.status === 401) { location.reload(); throw new Error('authentication required') }
  const txt = await r.text()
  let data = null
  try { data = txt ? JSON.parse(txt) : null } catch { data = txt }
  if (!r.ok) {
    const d = data && (data.detail || data.error)
    throw new Error(typeof d === 'string' ? d : (Array.isArray(d) ? d.map(x => x.msg).join('; ') : r.statusText))
  }
  return data
}

async function req(method, path, body) {
  const r = await fetch(BASE + path, {
    method, headers: body !== undefined ? { 'Content-Type': 'application/json' } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  return handle(r)
}

// multipart/form-data POST (file uploads) - the browser sets the boundary itself
async function postForm(path, formData) {
  return handle(await fetch(BASE + path, { method: 'POST', body: formData }))
}

export const api = {
  get: (p) => req('GET', p),
  post: (p, b) => req('POST', p, b === undefined ? {} : b),
  put: (p, b) => req('PUT', p, b),
  patch: (p, b) => req('PATCH', p, b),
  del: (p) => req('DELETE', p),
  postForm,
}
