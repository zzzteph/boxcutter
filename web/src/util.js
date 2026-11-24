// Timestamps come back as ISO strings with an offset; older/naive ones are treated as UTC.
export function toDate(iso) {
  if (!iso) return null
  const s = /[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z'
  return new Date(s)
}

export function fmtDuration(sec) {
  if (sec > 0 && sec < 1) return '<1s'
  sec = Math.max(0, Math.round(sec))
  if (sec < 60) return sec + 's'
  const m = Math.floor(sec / 60), s = sec % 60
  if (m < 60) return m + 'm' + (s ? ' ' + s + 's' : '')
  const h = Math.floor(m / 60)
  if (h < 48) return h + 'h ' + (m % 60) + 'm'
  return Math.floor(h / 24) + 'd ' + (h % 24) + 'h'
}

export function scanDuration(scan) {
  if (!scan || !scan.last_run_at) return ''
  const start = toDate(scan.last_run_at).getTime()
  const end = scan.finished_at ? toDate(scan.finished_at).getTime() : Date.now()
  return fmtDuration((end - start) / 1000)
}

export function durationLabel(scan) {
  const d = scanDuration(scan)
  if (!d) return ''
  if (scan.status === 'running') return 'running ' + d
  if (scan.finished_at) return 'took ' + d
  return d
}

export function timeAgo(iso) {
  if (!iso) return 'never'
  const s = (Date.now() - toDate(iso).getTime()) / 1000
  if (s < 0) return timeUntil(iso)
  if (s < 60) return Math.round(s) + 's ago'
  if (s < 3600) return Math.round(s / 60) + 'm ago'
  if (s < 86400) return Math.round(s / 3600) + 'h ago'
  return Math.round(s / 86400) + 'd ago'
}

export function timeUntil(iso) {
  if (!iso) return '—'
  const s = (toDate(iso).getTime() - Date.now()) / 1000
  if (s <= 30) return 'now'
  if (s < 3600) return 'in ' + Math.round(s / 60) + 'm'
  if (s < 86400) return 'in ' + Math.round(s / 3600) + 'h'
  return 'in ' + Math.round(s / 86400) + 'd'
}

// ---- schedules ---------------------------------------------------------------------------------------------
export const INTERVALS = [
  { value: 3600, label: 'Every hour' },
  { value: 6 * 3600, label: 'Every 6 hours' },
  { value: 12 * 3600, label: 'Every 12 hours' },
  { value: 86400, label: 'Every day' },
  { value: 7 * 86400, label: 'Every week' },
  { value: 30 * 86400, label: 'Every 30 days' },
]
export function intervalLabel(sec) {
  const hit = INTERVALS.find(i => i.value === sec)
  if (hit) return hit.label
  if (sec % 86400 === 0) return `Every ${sec / 86400} days`
  if (sec % 3600 === 0) return `Every ${sec / 3600} hours`
  return `Every ${Math.round(sec / 60)} min`
}

// ---- targets -------------------------------------------------------------------------------------------------
const HOST_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/
const NET_RE = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2}|-\d{1,3}(\.\d{1,3}){0,3})$/

export function targetLines(text) {
  return (text || '').split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'))
}

// what one target looks like: url | endpoint (url with ?params) | domain | ip | network | unknown
export function targetKind(v) {
  if (/^https?:\/\//i.test(v)) {
    try { return new URL(v).search.length > 1 ? 'endpoint' : 'url' } catch { return 'unknown' }
  }
  if (NET_RE.test(v)) return 'network'
  if (IP_RE.test(v)) return 'ip'
  if (HOST_RE.test(v.replace(/\.$/, ''))) return 'domain'
  return 'unknown'
}

// the dominant kind of a target list + a per-kind count; endpoints count as URLs for picking a scan type
export function detectTargets(lines) {
  const counts = {}
  for (const l of lines.slice(0, 5000)) { const k = targetKind(l); counts[k] = (counts[k] || 0) + 1 }
  const merged = { ...counts }
  if (merged.endpoint) { merged.url = (merged.url || 0) + merged.endpoint }
  let kind = ''
  if (lines.length) {
    const order = ['domain', 'url', 'ip', 'network']
    kind = order.reduce((best, k) => ((merged[k] || 0) > (merged[best] || 0) ? k : best), 'domain')
    if (!merged[kind]) kind = ''
    if (kind === 'url' && counts.endpoint && !counts.url) kind = 'endpoint'
  }
  return { kind, counts, total: lines.length }
}

export const KIND_ONE = {
  domain: 'domain', url: 'URL', endpoint: 'URL with parameters', ip: 'IP address', network: 'network',
  unknown: 'unrecognised',
}
export const KIND_LABEL = {
  domain: 'domains', url: 'URLs', endpoint: 'URLs with parameters', ip: 'IP addresses', network: 'networks',
  unknown: 'unrecognised',
}

// which template `accepts` values fit a kind of input (a target kind, or what a previous pipeline step produces)
const FITS = {
  domain: ['domain', 'host', 'spec', 'any'],
  url: ['url', 'host', 'endpoint', 'spec', 'graphql', 'js', 'any'],
  endpoint: ['endpoint', 'url', 'host', 'any'],
  ip: ['host', 'network', 'any'],
  network: ['network', 'any'],
  hosts: ['domain', 'host', 'network', 'spec', 'any'],
  urls: ['url', 'host', 'endpoint', 'spec', 'graphql', 'js', 'any'],
  items: ['url', 'host', 'endpoint', 'spec', 'graphql', 'js', 'any'],
}
export function fits(template, kind) {
  if (!kind) return true
  return (FITS[kind] || []).includes(template.accepts)
}

export const ACCEPTS_LABEL = {
  domain: 'a domain', host: 'a host, IP or URL', url: 'a URL', endpoint: 'a URL with parameters',
  js: 'a JavaScript file URL', spec: 'an OpenAPI spec or host', graphql: 'a GraphQL endpoint',
  network: 'an IP, CIDR or range', any: 'anything',
}
export const PRODUCES_LABEL = { findings: 'findings', hosts: 'hostnames', urls: 'URLs', items: 'URLs & requests' }
export const DEPTH_LABEL = { quick: 'Quick', standard: 'Standard', deep: 'Deep' }

// the template that actually runs: the chosen one, or its built-in distributed variant when that is switched on
export function resolveTemplate(templates, id, distributed) {
  const t = templates.find(x => x.id === id)
  if (!t) return null
  if (distributed) {
    const v = templates.find(x => x.kind === 'pipeline' && x.builtin && x.variant_of === t.name)
    if (v) return v
  }
  return t
}
