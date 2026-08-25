// The API returns naive UTC timestamps (SQLite drops tz info), i.e. no trailing 'Z'. Parse them as UTC so the
// browser doesn't shift them by its local offset.
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
  if (m < 60) return m + 'm ' + (s ? s + 's' : '')
  const h = Math.floor(m / 60)
  return h + 'h ' + (m % 60) + 'm'
}

// Elapsed for a running scan (start -> now) or total for a finished one (start -> finish).
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
  if (s < 60) return Math.round(s) + 's ago'
  if (s < 3600) return Math.round(s / 60) + 'm ago'
  if (s < 86400) return Math.round(s / 3600) + 'h ago'
  return Math.round(s / 86400) + 'd ago'
}
