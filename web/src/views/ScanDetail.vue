<script setup>
import { ref, computed, nextTick, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, apiUrl } from '../api'
import { durationLabel, fmtDuration, intervalLabel, timeAgo, timeUntil } from '../util'
import Select from '../components/Select.vue'

const route = useRoute()
const router = useRouter()
const id = route.params.id

const scan = ref(null)
const tab = ref('findings')
const SEVS = ['Critical', 'High', 'Medium', 'Low', 'Info']
const sevOpts = [{ value: '', label: 'All severities' }, ...SEVS.map(s => ({ value: s, label: s }))]
const stateOpts = [{ value: '', label: 'All states' }, { value: 'active', label: 'Active (new + open)' },
  { value: 'new', label: 'New' }, { value: 'open', label: 'Open' }, { value: 'resolved', label: 'Resolved' }]
const jobStatusOpts = [{ value: '', label: 'All statuses' },
  ...['running', 'pending', 'done', 'failed', 'cancelled'].map(s => ({ value: s, label: s }))]

// ---- steps (pipeline stages) ----
const stages = computed(() => (scan.value && scan.value.stages) || [])
const levels = computed(() => {
  const lv = []
  for (const s of stages.value) {
    const parents = s.from.filter(f => f >= 0)
    lv[s.index] = parents.length ? 1 + Math.max(...parents.map(p => lv[p] || 0)) : 0
  }
  const rows = []
  for (const s of stages.value) (rows[lv[s.index]] = rows[lv[s.index]] || []).push(s)
  return rows.filter(Boolean)
})
const stageFilter = ref(null)          // filter jobs/assets to one step
function stageName(i) { const s = stages.value[i]; return s ? `${i + 1}. ${s.title}` : '' }
function srcLabel(s) {
  return s.from.map(f => f < 0 ? 'your targets' : 'step ' + (f + 1)).join(' + ')
}
function stagePct(s) { return s.jobs.total ? Math.round(100 * (s.jobs.done + s.jobs.failed + s.jobs.cancelled) / s.jobs.total) : 0 }
function focusStage(s) {
  stageFilter.value = stageFilter.value === s.index ? null : s.index
  jOffset.value = 0; iOffset.value = 0
  loadJobs(); if (scan.value.items_total) loadItems()
}

// ---- findings ----
const FLIMIT = 25
const findings = ref([]); const fTotal = ref(0); const fOffset = ref(0)
const fState = ref(''); const fSev = ref(''); const fSort = ref('severity'); const fDir = ref('asc'); const fq = ref('')
const selFinding = ref(null); const detail = ref(null)
function fQuery() {
  let u = `state=${fState.value}&sort=${fSort.value}&dir=${fDir.value}`
  if (fSev.value) u += `&severity=${fSev.value}`
  if (fq.value) u += `&q=${encodeURIComponent(fq.value)}`
  return u
}
async function loadFindings() {
  const r = await api.get(`/scans/${id}/findings?limit=${FLIMIT}&offset=${fOffset.value}&${fQuery()}`)
  findings.value = r.items; fTotal.value = r.total
}
function setSort(col) {
  if (fSort.value === col) fDir.value = fDir.value === 'asc' ? 'desc' : 'asc'
  else { fSort.value = col; fDir.value = col === 'last_seen' ? 'desc' : 'asc' }
  fOffset.value = 0; loadFindings()
}
function sortInd(col) { return fSort.value === col ? (fDir.value === 'asc' ? ' ▲' : ' ▼') : '' }
function applyF() { fOffset.value = 0; loadFindings() }
function fPage(d) { fOffset.value = Math.max(0, fOffset.value + d * FLIMIT); loadFindings() }
async function toggleFinding(f) {
  if (selFinding.value === f.id) { selFinding.value = null; detail.value = null; return }
  selFinding.value = f.id; detail.value = null
  try { detail.value = await api.get(`/scans/${id}/findings/${f.id}`) } catch (e) { /* transient */ }
}
async function focusFinding(fid) {
  try {
    const d = await api.get(`/scans/${id}/findings/${fid}`)
    findings.value = [d, ...findings.value.filter(f => f.id !== d.id)]
    selFinding.value = d.id; detail.value = d
    await nextTick()
    document.getElementById('finding-' + d.id)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  } catch (e) { /* gone */ }
}
async function clearFindings() {
  if (!confirm(`Delete all ${fTotal.value} findings of this scan? The scan itself stays.`)) return
  try { await api.post(`/scans/${id}/truncate?scope=findings`); fOffset.value = 0; await refresh() } catch (e) { alert(e.message) }
}

// ---- discovered assets ----
const ILIMIT = 100
const items = ref([]); const iTotal = ref(0); const iOffset = ref(0); const iq = ref(''); const aType = ref('')
const aCounts = ref({})
const ATABS = [{ key: '', label: 'All' }, { key: 'domain', label: 'Domains' }, { key: 'subdomain', label: 'Subdomains' },
  { key: 'url', label: 'URLs' }, { key: 'ip', label: 'IPs' }, { key: 'endpoint', label: 'Endpoints' }, { key: 'other', label: 'Other' }]
const visibleATabs = computed(() => ATABS.filter(t => t.key === '' || (aCounts.value[t.key] || 0) > 0))
function aCount(k) { return k === '' ? Object.values(aCounts.value).reduce((a, b) => a + b, 0) : (aCounts.value[k] || 0) }
function iQuery() {
  let u = `sort=value&dir=asc`
  if (iq.value) u += `&q=${encodeURIComponent(iq.value)}`
  if (aType.value) u += `&type=${aType.value}`
  if (stageFilter.value != null) u += `&stage=${stageFilter.value}`
  return u
}
async function loadItems() {
  const r = await api.get(`/scans/${id}/items?limit=${ILIMIT}&offset=${iOffset.value}&${iQuery()}`)
  items.value = r.items; iTotal.value = r.total; aCounts.value = r.counts || {}
}
function applyI() { iOffset.value = 0; loadItems() }
function iPage(d) { iOffset.value = Math.max(0, iOffset.value + d * ILIMIT); loadItems() }
function setAType(k) { aType.value = k; applyI() }

// ---- jobs ----
const JLIMIT = 25
const jobs = ref([]); const jTotal = ref(0); const jOffset = ref(0); const jStatus = ref(''); const jCounts = ref({})
const selJob = ref(null); const jobLog = ref([])
async function loadJobs() {
  let u = `/scans/${id}/jobs?limit=${JLIMIT}&offset=${jOffset.value}`
  if (jStatus.value) u += `&status=${jStatus.value}`
  if (stageFilter.value != null) u += `&stage=${stageFilter.value}`
  const r = await api.get(u); jobs.value = r.items; jTotal.value = r.total; jCounts.value = r.counts
}
function jPage(d) { jOffset.value = Math.max(0, jOffset.value + d * JLIMIT); loadJobs() }
async function toggleJob(j) {
  if (selJob.value === j.id) { selJob.value = null; return }
  selJob.value = j.id; jobLog.value = []
  try { jobLog.value = await api.get(`/scans/${id}/events?job_id=${j.id}&tail=300`) } catch (e) { /* transient */ }
}

// ---- targets ----
const TLIMIT = 100
const targets = ref([]); const tTotal = ref(0); const tOffset = ref(0); const tq = ref(''); const addText = ref('')
const adding = ref(false)
async function loadTargets() {
  let u = `/scans/${id}/targets?limit=${TLIMIT}&offset=${tOffset.value}`
  if (tq.value) u += `&q=${encodeURIComponent(tq.value)}`
  const r = await api.get(u); targets.value = r.items; tTotal.value = r.total
}
function tPage(d) { tOffset.value = Math.max(0, tOffset.value + d * TLIMIT); loadTargets() }
async function addTargets() {
  const lines = addText.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean)
  if (!lines.length) return
  adding.value = true
  try {
    let added = 0
    for (let i = 0; i < lines.length; i += 20000) added += (await api.post(`/scans/${id}/targets`, { targets: lines.slice(i, i + 20000) })).added
    addText.value = ''; alert(`Added ${added} new target(s) — they are being scanned now.`)
    await Promise.all([loadTargets(), refresh()]); ensureLive()
  } catch (e) { alert(e.message) } finally { adding.value = false }
}
async function uploadTargets(ev) {
  const f = ev.target.files && ev.target.files[0]; if (!f) return
  adding.value = true
  try {
    const fd = new FormData(); fd.append('file', f)
    const r = await api.postForm(`/scans/${id}/targets/upload`, fd)
    alert(`Added ${r.added} new target(s).`); await Promise.all([loadTargets(), refresh()]); ensureLive()
  } catch (e) { alert(e.message) } finally { adding.value = false; ev.target.value = '' }
}
async function removeTarget(t) {
  if (!confirm(`Remove target ${t.value}?`)) return
  try { await api.post(`/scans/${id}/targets/delete`, { ids: [t.id] }); await Promise.all([loadTargets(), refresh()]) }
  catch (e) { alert(e.message) }
}

// ---- live log ----
const events = ref([]); const cursor = ref(0); const MAX_EVENTS = 3000
const logText = computed(() => events.value.map(e => (e.agent ? '[' + e.agent + '] ' : '') + e.line).join('\n'))
function pushEvents(list) {
  for (const e of list) {
    if (e.cursor != null && e.cursor <= cursor.value) continue
    events.value.push(e)
    if (e.cursor > cursor.value) cursor.value = e.cursor
  }
  const over = events.value.length - MAX_EVENTS
  if (over > 0) events.value.splice(0, over)
}

// ---- lifecycle ----
let timer = null, es = null
const isLive = () => scan.value && ['running', 'paused', 'queued'].includes(scan.value.status)
function stopLive() { if (timer) { clearInterval(timer); timer = null } if (es) { es.close(); es = null } }
function ensureLive() { if (!timer) timer = setInterval(refresh, 3000); if (!es) startStream() }
function startStream() {
  try {
    es = new EventSource(apiUrl(`/scans/${id}/stream?since=${cursor.value}`))
    es.onmessage = (m) => { try { pushEvents([JSON.parse(m.data)]) } catch { /* keepalive */ } }
    es.onerror = () => { if (es) { es.close(); es = null } }
  } catch { es = null }
}
async function loadScan() { scan.value = await api.get('/scans/' + id) }
async function refresh() {
  try {
    await Promise.all([loadScan(), loadFindings(), loadJobs()])
    if (scan.value.items_total) await loadItems()
    if (!es) { const ev = await api.get(`/scans/${id}/events?since=${cursor.value}`); if (ev.length) pushEvents(ev) }
    if (!isLive()) stopLive()
  } catch (e) { /* transient */ }
}
async function act(a) {
  try { await api.post(`/scans/${id}/${a}`); await refresh(); if (isLive()) ensureLive() } catch (e) { alert(e.message) }
}
async function delScan() {
  if (!confirm(`Delete scan "${scan.value.name}" and all its results? This can't be undone.`)) return
  try { await api.del('/scans/' + id); router.push('/scans') } catch (e) { alert(e.message) }
}
async function rename() {
  const n = prompt('Scan name', scan.value.name)
  if (n && n.trim()) { await api.patch('/scans/' + id, { name: n.trim() }); await loadScan() }
}

const progress = computed(() => {
  const s = scan.value
  if (!s) return { pct: 0 }
  return { pct: s.jobs_total ? Math.round(100 * s.jobs_done / s.jobs_total) : 0 }
})
const sevCounts = computed(() => (scan.value && scan.value.findings_by_severity) || {})

onMounted(async () => {
  await Promise.all([loadScan(), loadFindings(), loadJobs()]).catch(() => {})
  if (scan.value && scan.value.items_total) await loadItems().catch(() => {})
  if (scan.value && !scan.value.findings_total && scan.value.items_total) tab.value = 'assets'
  loadTargets().catch(() => {})
  const seed = await api.get(`/scans/${id}/events?tail=200`).catch(() => [])
  if (seed.length) pushEvents(seed)
  if (isLive()) ensureLive()
  if (route.query.finding) { tab.value = 'findings'; await focusFinding(route.query.finding) }
})
onUnmounted(stopLive)
</script>

<template>
  <div v-if="scan">
    <div class="row" style="justify-content:space-between;align-items:flex-start;gap:12px">
      <div style="min-width:0">
        <div class="muted crumbs"><router-link to="/scans">Scans</router-link> ›</div>
        <h1 style="margin:0;word-break:break-word">{{ scan.name }}
          <span class="state" :class="'st-' + scan.status">{{ scan.status }}</span></h1>
        <div class="muted" style="margin-top:4px">
          {{ scan.template }}<span v-if="scan.distributed"> · distributed, {{ scan.steps }} steps</span>
          · run #{{ scan.run_no }} · {{ scan.assets }} target(s)<span v-if="durationLabel(scan)"> · {{ durationLabel(scan) }}</span>
        </div>
        <div v-if="scan.scheduler" class="muted" style="margin-top:2px">
          ⟳ <router-link to="/schedulers">{{ intervalLabel(scan.scheduler.interval_seconds) }}</router-link>
          <span v-if="scan.scheduler.enabled"> · next run {{ timeUntil(scan.scheduler.next_run_at) }}</span>
          <span v-else> · paused</span>
        </div>
      </div>
      <div class="row" style="gap:8px">
        <button v-if="scan.status === 'running'" @click="act('pause')">Pause</button>
        <button v-if="scan.status === 'paused'" class="primary" @click="act('resume')">Resume</button>
        <button v-if="['running', 'paused'].includes(scan.status)" class="danger" @click="act('stop')">Stop</button>
        <button v-if="!['running', 'paused'].includes(scan.status)" class="primary" @click="act('rerun')">Run again</button>
        <a class="btn ghost" :href="apiUrl(`/scans/${id}/report`)" download>Report</a>
        <button class="ghost" @click="rename">Rename</button>
        <button class="danger ghost" @click="delScan">Delete</button>
      </div>
    </div>

    <div class="progress" style="margin-top:14px">
      <div class="bar" :class="{ done: scan.status !== 'running' }" :style="{ width: progress.pct + '%' }"></div>
    </div>
    <div class="row sumline">
      <span>{{ scan.jobs_done }}/{{ scan.jobs_total }} jobs done<span v-if="scan.running"> · {{ scan.running }} running</span><span
        v-if="scan.jobs_failed" class="st-failed"> · {{ scan.jobs_failed }} failed</span></span>
      <span class="sep">|</span>
      <span v-for="s in SEVS" :key="s" v-show="sevCounts[s]" class="badge" :class="'sev-' + s">{{ sevCounts[s] }} {{ s }}</span>
      <span><span class="state-new">{{ scan.findings_new }} new</span> · {{ scan.findings_open_state }} open ·
        <span class="muted">{{ scan.findings_resolved }} resolved</span></span>
    </div>

    <!-- pipeline steps -->
    <div v-if="stages.length > 1" class="card" style="margin-top:16px">
      <div class="row" style="justify-content:space-between">
        <h2 style="margin:0">Steps</h2>
        <span class="muted" style="font-size:12.5px">Each step's results are handed to the next as separate jobs, spread
          over every scanner. Click a step to filter jobs and assets.</span>
      </div>
      <div class="lv" v-for="(row, li) in levels" :key="li">
        <div v-if="li" class="lv-arrow">↓</div>
        <div class="lv-row">
          <button v-for="s in row" :key="s.index" type="button" class="stg" :class="['stg-' + s.state, { on: stageFilter === s.index }]"
                  @click="focusStage(s)">
            <div class="stg-top"><span class="stg-no">{{ s.index + 1 }}</span><b>{{ s.title }}</b></div>
            <div class="stg-src">{{ s.input_label }} from {{ srcLabel(s) }}<span v-if="s.args"> · <code>{{ s.args }}</code></span></div>
            <div class="progress thin"><div class="bar" :class="{ done: s.state === 'done' }" :style="{ width: stagePct(s) + '%' }"></div></div>
            <div class="stg-meta">
              <span>{{ s.state }}</span>
              <span>{{ s.jobs.done + s.jobs.failed }}/{{ s.jobs.total }} jobs<span v-if="s.jobs.running"> · {{ s.jobs.running }} running</span><span
                v-if="s.jobs.failed" class="st-failed"> · {{ s.jobs.failed }} failed</span></span>
              <span v-if="s.items">{{ s.items }} found</span>
            </div>
          </button>
        </div>
      </div>
    </div>

    <div class="tabs">
      <button :class="{ on: tab === 'findings' }" @click="tab = 'findings'">Findings <span class="cnt">{{ scan.findings_total }}</span></button>
      <button :class="{ on: tab === 'assets' }" @click="tab = 'assets'">Discovered <span class="cnt">{{ scan.items_total }}</span></button>
      <button :class="{ on: tab === 'jobs' }" @click="tab = 'jobs'">Jobs <span class="cnt">{{ scan.jobs_total }}</span></button>
      <button :class="{ on: tab === 'targets' }" @click="tab = 'targets'">Targets <span class="cnt">{{ scan.assets }}</span></button>
      <button :class="{ on: tab === 'log' }" @click="tab = 'log'">Live log</button>
      <span v-if="stageFilter != null && (tab === 'jobs' || tab === 'assets')" class="chip">step {{ stageName(stageFilter) }}
        <a href="#" @click.prevent="focusStage(stages[stageFilter])">✕</a></span>
    </div>

    <!-- findings -->
    <template v-if="tab === 'findings'">
      <div class="row toolbar">
        <Select v-model="fState" :options="stateOpts" auto @change="applyF" />
        <Select v-model="fSev" :options="sevOpts" auto @change="applyF" />
        <input v-model="fq" placeholder="search…" style="max-width:200px" @input="applyF" />
        <span class="spacer" />
        <a class="btn ghost sm" :href="apiUrl(`/scans/${id}/findings/export?format=csv&${fQuery()}`)" download>⬇ CSV</a>
        <a class="btn ghost sm" :href="apiUrl(`/scans/${id}/findings/export?format=json&${fQuery()}`)" download>JSON</a>
        <button class="ghost danger sm" :disabled="!fTotal" @click="clearFindings">Clear</button>
      </div>
      <div class="card tablecard">
        <table class="reflow findings rows">
          <thead><tr>
            <th class="sortable" @click="setSort('severity')">Sev{{ sortInd('severity') }}</th>
            <th class="sortable" @click="setSort('title')">Title{{ sortInd('title') }}</th>
            <th class="sortable" @click="setSort('target')">Target{{ sortInd('target') }}</th>
            <th>URL</th>
            <th class="sortable" @click="setSort('state')">State{{ sortInd('state') }}</th>
            <th class="sortable" @click="setSort('last_seen')">Seen{{ sortInd('last_seen') }}</th>
          </tr></thead>
          <tbody>
            <template v-for="f in findings" :key="f.id">
              <tr :id="'finding-' + f.id" :class="['sevrow-' + f.severity, { sel: selFinding === f.id }]" style="cursor:pointer"
                  @click="toggleFinding(f)">
                <td data-label="Sev"><span class="badge" :class="'sev-' + f.severity">{{ f.severity }}</span></td>
                <td data-label="Title">{{ f.title }}</td>
                <td data-label="Target" style="word-break:break-all">{{ f.target }}</td>
                <td data-label="URL" style="word-break:break-all">{{ f.url }}</td>
                <td data-label="State"><span class="state" :class="'state-' + f.state">{{ f.state }}</span></td>
                <td data-label="Seen" class="muted" style="white-space:nowrap">{{ timeAgo(f.last_seen) }}</td>
              </tr>
              <tr v-if="selFinding === f.id" class="expand">
                <td colspan="6">
                  <div class="detail">
                    <div v-if="f.cls"><span class="k">Class</span>{{ f.cls }}</div>
                    <div v-if="f.url"><span class="k">URL</span><a :href="f.url" target="_blank" rel="noopener">{{ f.url }}</a></div>
                    <div><span class="k">First seen</span>{{ timeAgo(f.first_seen) }}</div>
                    <div><span class="k">Last seen</span>{{ timeAgo(f.last_seen) }}</div>
                  </div>
                  <template v-if="detail && detail.evidence"><b class="sub">Evidence</b><div class="log" style="max-height:200px">{{ detail.evidence }}</div></template>
                  <template v-if="detail && detail.reproduce"><b class="sub">Reproduce</b><div class="log" style="max-height:160px">{{ detail.reproduce }}</div></template>
                  <template v-if="detail && Object.keys(detail.raw || {}).length">
                    <b class="sub">Full record</b><div class="log" style="max-height:260px">{{ JSON.stringify(detail.raw, null, 2) }}</div>
                  </template>
                  <div v-if="!detail" class="muted" style="font-size:12px">Loading…</div>
                </td>
              </tr>
            </template>
            <tr v-if="!findings.length"><td colspan="6" class="muted">
              {{ scan.status === 'running' ? 'No findings yet — they appear here as soon as a job reports one.' : 'No findings match.' }}</td></tr>
          </tbody>
        </table>
      </div>
      <div v-if="fTotal > FLIMIT" class="row pager">
        <button class="ghost" :disabled="fOffset === 0" @click="fPage(-1)">← Prev</button>
        <span class="muted">{{ fOffset + 1 }}–{{ Math.min(fOffset + FLIMIT, fTotal) }} of {{ fTotal }}</span>
        <button class="ghost" :disabled="fOffset + FLIMIT >= fTotal" @click="fPage(1)">Next →</button>
      </div>
    </template>

    <!-- discovered assets -->
    <template v-if="tab === 'assets'">
      <div class="row toolbar">
        <div class="atabs">
          <button v-for="t in visibleATabs" :key="t.key" class="atab" :class="{ on: aType === t.key }" @click="setAType(t.key)">
            {{ t.label }} <span class="cnt">{{ aCount(t.key) }}</span></button>
        </div>
        <span class="spacer" />
        <input v-model="iq" placeholder="search…" style="max-width:200px" @input="applyI" />
        <a class="btn ghost sm" :href="apiUrl(`/scans/${id}/items/export?${iQuery()}`)" download title="One per line">⬇ TXT</a>
      </div>
      <div class="card tablecard">
        <table class="reflow rows">
          <thead><tr><th>Value</th><th>Type</th><th v-if="stages.length > 1">Step</th><th>Found on</th><th>Seen</th></tr></thead>
          <tbody>
            <tr v-for="it in items" :key="it.id">
              <td data-label="Value" style="word-break:break-all">
                <a v-if="/^https?:\/\//.test(it.value)" :href="it.value" target="_blank" rel="noopener">{{ it.value }}</a>
                <code v-else>{{ it.value }}</code>
              </td>
              <td data-label="Type"><span class="atype">{{ it.asset_type }}</span></td>
              <td v-if="stages.length > 1" data-label="Step" class="muted">{{ stageName(it.stage) }}</td>
              <td data-label="Found on" style="word-break:break-all">{{ it.target }}</td>
              <td data-label="Seen" class="muted" style="white-space:nowrap">{{ timeAgo(it.last_seen) }}</td>
            </tr>
            <tr v-if="!items.length"><td colspan="5" class="muted">Nothing discovered yet.</td></tr>
          </tbody>
        </table>
      </div>
      <div v-if="iTotal > ILIMIT" class="row pager">
        <button class="ghost" :disabled="iOffset === 0" @click="iPage(-1)">← Prev</button>
        <span class="muted">{{ iOffset + 1 }}–{{ Math.min(iOffset + ILIMIT, iTotal) }} of {{ iTotal }}</span>
        <button class="ghost" :disabled="iOffset + ILIMIT >= iTotal" @click="iPage(1)">Next →</button>
      </div>
    </template>

    <!-- jobs -->
    <template v-if="tab === 'jobs'">
      <div class="row toolbar">
        <Select v-model="jStatus" :options="jobStatusOpts" auto @change="jOffset = 0; loadJobs()" />
        <span class="muted" style="font-size:12.5px">One job = one target through one step. Click a job for its command and output.</span>
      </div>
      <div class="card tablecard">
        <table class="reflow rows">
          <thead><tr><th>Target</th><th v-if="stages.length > 1">Step</th><th>Status</th><th>Duration</th></tr></thead>
          <tbody>
            <template v-for="j in jobs" :key="j.id">
              <tr style="cursor:pointer" :class="{ sel: selJob === j.id }" @click="toggleJob(j)">
                <td data-label="Target" style="word-break:break-all">{{ j.target }}</td>
                <td v-if="stages.length > 1" data-label="Step" class="muted">{{ j.stage + 1 }}. {{ j.step }}</td>
                <td data-label="Status"><span class="state" :class="'st-' + j.status">{{ j.status }}</span>
                  <span v-if="j.attempts > 1" class="muted" style="font-size:12px"> · try {{ j.attempts }}</span></td>
                <td data-label="Duration">{{ j.duration_sec != null ? fmtDuration(j.duration_sec) : '—' }}</td>
              </tr>
              <tr v-if="selJob === j.id" class="expand">
                <td colspan="4">
                  <div class="cmd sm">{{ j.command || '(not started yet)' }}</div>
                  <div v-if="j.error" class="err">error: {{ j.error }}</div>
                  <b class="sub">Live steps</b>
                  <div class="log" style="max-height:180px">{{ jobLog.map(e => e.line).join('\n') || 'no output yet' }}</div>
                  <b class="sub">Raw output</b>
                  <div class="log" style="max-height:220px">{{ j.output || '(the engine prints its result when the job finishes)' }}</div>
                </td>
              </tr>
            </template>
            <tr v-if="!jobs.length"><td colspan="4" class="muted">No jobs.</td></tr>
          </tbody>
        </table>
      </div>
      <div v-if="jTotal > JLIMIT" class="row pager">
        <button class="ghost" :disabled="jOffset === 0" @click="jPage(-1)">← Prev</button>
        <span class="muted">{{ jOffset + 1 }}–{{ Math.min(jOffset + JLIMIT, jTotal) }} of {{ jTotal }}</span>
        <button class="ghost" :disabled="jOffset + JLIMIT >= jTotal" @click="jPage(1)">Next →</button>
      </div>
    </template>

    <!-- targets -->
    <template v-if="tab === 'targets'">
      <div class="row toolbar" style="align-items:flex-start">
        <textarea v-model="addText" rows="2" placeholder="Add targets, one per line — they start scanning right away" style="flex:1;min-width:240px"></textarea>
        <div style="display:flex;flex-direction:column;gap:6px">
          <button class="sm" :disabled="adding || !addText.trim()" @click="addTargets">+ Add</button>
          <label class="btn ghost sm" style="margin:0">⬆ File<input type="file" accept=".txt,text/plain" style="display:none" @change="uploadTargets" /></label>
        </div>
      </div>
      <input v-model="tq" placeholder="search targets…" style="max-width:260px;margin-bottom:8px" @input="tOffset = 0; loadTargets()" />
      <div class="card tablecard">
        <table class="reflow rows">
          <tbody>
            <tr v-for="t in targets" :key="t.id">
              <td style="word-break:break-all">{{ t.value }}</td>
              <td style="width:1%"><button class="ghost danger sm" title="Remove" @click="removeTarget(t)">✕</button></td>
            </tr>
            <tr v-if="!targets.length"><td class="muted">No targets match.</td></tr>
          </tbody>
        </table>
      </div>
      <div v-if="tTotal > TLIMIT" class="row pager">
        <button class="ghost" :disabled="tOffset === 0" @click="tPage(-1)">← Prev</button>
        <span class="muted">{{ tOffset + 1 }}–{{ Math.min(tOffset + TLIMIT, tTotal) }} of {{ tTotal }}</span>
        <button class="ghost" :disabled="tOffset + TLIMIT >= tTotal" @click="tPage(1)">Next →</button>
      </div>
    </template>

    <template v-if="tab === 'log'">
      <div class="log" style="max-height:560px;margin-top:4px">{{ logText || 'waiting for output…' }}</div>
    </template>
  </div>
  <div v-else class="muted">Loading…</div>
</template>

<style scoped>
.crumbs { font-size: 12.5px; margin-bottom: 2px; }
.sumline { margin-top: 6px; font-size: 12.5px; color: var(--on-surface-variant); gap: 8px; }
.sumline .badge { height: 20px; font-size: 11px; }
.sep { color: var(--outline-variant); }
.lv-arrow { color: var(--outline); padding: 2px 0 2px 14px; }
.lv:first-of-type { margin-top: 12px; }
.lv-row { display: grid; gap: 8px; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); }
.stg { all: unset; box-sizing: border-box; cursor: pointer; padding: 10px 12px; border-radius: var(--radius-s);
  background: var(--sc); border: 1px solid var(--outline-variant); display: flex; flex-direction: column; gap: 5px; }
.stg:hover { border-color: var(--outline); }
.stg.on { border-color: var(--accent); box-shadow: var(--glow); }
.stg-running { border-left: 3px solid var(--accent); }
.stg-done { border-left: 3px solid var(--ok); }
.stg-skipped, .stg-waiting { opacity: .7; }
.stg-top { display: flex; gap: 8px; align-items: center; }
.stg-top b { font-weight: 600; font-size: 13px; }
.stg-no { flex: none; width: 20px; height: 20px; border-radius: 50%; display: grid; place-items: center; font-size: 11px;
  font-weight: 700; background: var(--sc-highest); color: var(--on-surface); }
.stg-src { font-size: 11.5px; color: var(--on-surface-variant); }
.stg-src code { font-size: 11px; }
.stg-meta { display: flex; gap: 8px; flex-wrap: wrap; font-size: 11.5px; color: var(--on-surface-variant); }
.progress.thin { height: 4px; }
.tabs { display: flex; gap: 4px; flex-wrap: wrap; align-items: center; margin: 20px 0 10px; border-bottom: 1px solid var(--outline-variant); }
.tabs > button { border: 0; border-bottom: 2px solid transparent; border-radius: 0; background: transparent; height: 40px;
  color: var(--on-surface-variant); text-transform: none; letter-spacing: 0; font-weight: 500; font-size: 14px; }
.tabs > button:hover { background: transparent; color: var(--on-surface); box-shadow: none; }
.tabs > button.on { color: var(--accent-ink); border-bottom-color: var(--accent); }
.cnt { font-size: 11px; color: var(--outline); margin-left: 4px; }
.toolbar { margin-bottom: 10px; gap: 8px; }
.spacer { flex: 1; }
.sub { font-size: 13px; display: block; margin-top: 10px; }
.atabs { display: flex; flex-wrap: wrap; gap: 6px; }
.atab { height: 30px; padding: 0 12px; font-size: 12.5px; text-transform: none; letter-spacing: 0; font-weight: 500;
  border-color: var(--outline-variant); color: var(--on-surface-variant); }
.atab.on { background: var(--primary-container); color: var(--accent-ink); border-color: var(--accent); }
.atype { font-size: 11px; padding: 1px 8px; border-radius: 999px; background: var(--sc-high); color: var(--on-surface-variant); }
</style>
