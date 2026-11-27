<script setup>
// A scan: what it is, how far it got, and - the centre of the page - its workflow running live: every step with its
// state, jobs, what it found and its findings, wires animated while data flows. Click a step for its own log and to
// filter the tabs below (findings / discovered / jobs / log) to just that step.
import { ref, computed, nextTick, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, apiUrl } from '../api'
import { durationLabel, fmtDuration, timeAgo, timeUntil } from '../util'
import Select from '../components/Select.vue'
import WorkflowGraph from '../components/WorkflowGraph.vue'
import WindowInput from '../components/WindowInput.vue'
import { graphFromPlan } from '../workflow'

const route = useRoute()
const router = useRouter()
const id = route.params.id

const scan = ref(null)
const inputs = ref([])
const tab = ref('findings')
const SEVS = ['Critical', 'High', 'Medium', 'Low', 'Info']
const sevOpts = [{ value: '', label: 'All severities' }, ...SEVS.map(s => ({ value: s, label: s }))]
const stateOpts = [{ value: '', label: 'All findings' }, { value: 'new', label: 'New this run' },
  { value: 'open', label: 'Still open' }, { value: 'unconfirmed', label: 'Not re-checked' }]
const UNCONFIRMED = 'Its step could not re-check this target in the last run (the job failed or the target was not reached), so it is kept until a run checks it again.'
const jobStatusOpts = [{ value: '', label: 'All statuses' },
  ...['running', 'pending', 'done', 'failed', 'cancelled'].map(s => ({ value: s, label: s }))]
const inputLabels = computed(() => Object.fromEntries(inputs.value.map(i => [i.value, i.label])))

// ---- the live workflow graph ----
const stages = computed(() => (scan.value && scan.value.stages) || [])
const graph = computed(() => graphFromPlan(stages.value))
const states = computed(() => {
  const out = { '@targets': { count: scan.value ? scan.value.assets : 0 } }
  for (const s of stages.value) out['n' + s.index] = s
  return out
})
const graphKey = computed(() => stages.value.map(s => s.index + ':' + s.from.join(',')).join('|'))
const selKey = ref('')
const step = computed(() => selKey.value && selKey.value !== '@targets' ? stages.value.find(s => 'n' + s.index === selKey.value) : null)
const stepFilter = computed(() => (step.value ? step.value.index : null))
const stepLog = ref([])
function srcLabel(s) { return s.from.map(f => (f < 0 ? 'your targets' : stages.value[f]?.title || 'step ' + (f + 1))).join(' + ') }
async function onSelect(k) {
  selKey.value = selKey.value === k ? '' : k
  applyStep()
}
function applyStep() {
  fOffset.value = 0; iOffset.value = 0; jOffset.value = 0
  loadFindings(); loadJobs(); if (scan.value.items_total) loadItems()
  loadStepLog()
  if (tab.value === 'log') loadStageLog()
}
async function loadStepLog() {
  if (!step.value) { stepLog.value = []; return }
  try { stepLog.value = await api.get(`/scans/${id}/events?stage=${step.value.index}&tail=40`) } catch (e) { /* transient */ }
}
function showTab(t) { tab.value = t; if (t === 'log') loadStageLog(); nextTick(() => document.getElementById('tabs')?.scrollIntoView({ behavior: 'smooth' })) }

// ---- findings ----
const FLIMIT = 25
const findings = ref([]); const fTotal = ref(0); const fOffset = ref(0)
const fState = ref(''); const fSev = ref(''); const fSort = ref('severity'); const fDir = ref('asc'); const fq = ref('')
const selFinding = ref(null); const detail = ref(null)
function fQuery() {
  let u = `state=${fState.value}&sort=${fSort.value}&dir=${fDir.value}`
  if (fSev.value) u += `&severity=${fSev.value}`
  if (fq.value) u += `&q=${encodeURIComponent(fq.value)}`
  if (stepFilter.value != null) u += `&stage=${stepFilter.value}`
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
  if (!confirm(`Delete all findings of this scan? The scan itself stays.`)) return
  try { await api.post(`/scans/${id}/truncate?scope=findings`); fOffset.value = 0; await refresh() } catch (e) { alert(e.message) }
}

// ---- discovered ----
const ILIMIT = 100
const items = ref([]); const iTotal = ref(0); const iOffset = ref(0); const iq = ref(''); const aType = ref('')
const aCounts = ref({})
const ATABS = [{ key: '', label: 'All' }, { key: 'domain', label: 'Domains' }, { key: 'subdomain', label: 'Subdomains' },
  { key: 'url', label: 'URLs' }, { key: 'ip', label: 'IPs' }, { key: 'endpoint', label: 'Endpoints' }, { key: 'other', label: 'Other' }]
const visibleATabs = computed(() => ATABS.filter(t => t.key === '' || (aCounts.value[t.key] || 0) > 0))
function aCount(k) { return k === '' ? Object.values(aCounts.value).reduce((a, b) => a + b, 0) : (aCounts.value[k] || 0) }
function iQuery() {
  let u = 'sort=value&dir=asc'
  if (iq.value) u += `&q=${encodeURIComponent(iq.value)}`
  if (aType.value) u += `&type=${aType.value}`
  if (stepFilter.value != null) u += `&stage=${stepFilter.value}`
  return u
}
async function loadItems() {
  const r = await api.get(`/scans/${id}/items?limit=${ILIMIT}&offset=${iOffset.value}&${iQuery()}`)
  items.value = r.items; iTotal.value = r.total; aCounts.value = r.counts || {}
}
function applyI() { iOffset.value = 0; loadItems() }
function iPage(d) { iOffset.value = Math.max(0, iOffset.value + d * ILIMIT); loadItems() }

// ---- jobs ----
const JLIMIT = 25
const jobs = ref([]); const jTotal = ref(0); const jOffset = ref(0); const jStatus = ref('')
const selJob = ref(null); const jobLog = ref([])
async function loadJobs() {
  let u = `/scans/${id}/jobs?limit=${JLIMIT}&offset=${jOffset.value}`
  if (jStatus.value) u += `&status=${jStatus.value}`
  if (stepFilter.value != null) u += `&stage=${stepFilter.value}`
  const r = await api.get(u); jobs.value = r.items; jTotal.value = r.total
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

// ---- log ----
const events = ref([]); const cursor = ref(0); const MAX_EVENTS = 3000
const stageLog = ref([])
const logText = computed(() => (stepFilter.value != null ? stageLog.value : events.value)
  .map(e => (e.agent ? '[' + e.agent + '] ' : '') + e.line).join('\n'))
async function loadStageLog() {
  if (stepFilter.value == null) return
  try { stageLog.value = await api.get(`/scans/${id}/events?stage=${stepFilter.value}&tail=500`) } catch (e) { /* transient */ }
}
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
    if (step.value) loadStepLog()
    if (tab.value === 'log' && stepFilter.value != null) loadStageLog()
    if (!es) { const ev = await api.get(`/scans/${id}/events?since=${cursor.value}`); if (ev.length) pushEvents(ev) }
    if (!isLive()) stopLive()
  } catch (e) { /* transient */ }
}
async function act(a) {
  try { await api.post(`/scans/${id}/${a}`); await refresh(); if (isLive()) ensureLive() } catch (e) { alert(e.message) }
}
const menu = ref(false)
async function delScan() {
  menu.value = false
  if (!confirm(`Delete scan "${scan.value.name}" and all its results? This can't be undone.`)) return
  try { await api.del('/scans/' + id); router.push('/scans') } catch (e) { alert(e.message) }
}
// ---- scan window ----
const winEdit = ref(null)               // {window} while the dialog is open
const winErr = ref('')
const waiting = computed(() => scan.value && scan.value.status === 'running' && scan.value.window && !scan.value.window_open)
function editWindow() { menu.value = false; winErr.value = ''; winEdit.value = { window: scan.value.window } }
async function saveWindow() {
  try {
    await api.patch('/scans/' + id, { window: winEdit.value.window, set_window: true })
    winEdit.value = null
    await loadScan()
  } catch (e) { winErr.value = e.message }
}
// shown in the window's own time zone, like its "Mon–Fri 09:00–18:00 (zone)" text
function whenLocal(iso) {
  const tz = scan.value && scan.value.window ? scan.value.window.tz : undefined
  try { return new Intl.DateTimeFormat(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit', timeZone: tz }).format(new Date(iso)) }
  catch { return iso }
}
async function rename() {
  menu.value = false
  const n = prompt('Scan name', scan.value.name)
  if (n && n.trim()) { await api.patch('/scans/' + id, { name: n.trim() }); await loadScan() }
}

const pct = computed(() => (scan.value && scan.value.jobs_total ? Math.round(100 * scan.value.jobs_done / scan.value.jobs_total) : 0))
const sevCounts = computed(() => (scan.value && scan.value.findings_by_severity) || {})
const runningSteps = computed(() => stages.value.filter(s => s.state === 'running').length)
const graphHeight = computed(() => (stages.value.length <= 2 ? 200 : (stages.value.length <= 6 ? 340 : (stages.value.length <= 12 ? 520 : 640))))

onMounted(async () => {
  api.get('/templates/inputs').then(r => { inputs.value = r }).catch(() => {})
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
    <div class="crumbs muted"><router-link to="/scans">Scans</router-link> ›</div>
    <div class="head">
      <div style="min-width:0">
        <h1 class="title">{{ scan.name }} <span class="state" :class="'st-' + scan.status">{{ scan.status }}</span></h1>
        <div class="muted sub">
          <template v-if="scan.template_info">
            <router-link v-if="scan.template_info.kind === 'pipeline'" :to="'/workflows/' + scan.template_info.id">{{ scan.template }}</router-link>
            <span v-else>{{ scan.template }}</span>
          </template><span v-else>{{ scan.template }}</span>
          <span v-if="scan.steps > 1"> · workflow, {{ scan.steps }} steps</span>
          · {{ scan.assets }} target{{ scan.assets === 1 ? '' : 's' }} · run #{{ scan.run_no }}<span v-if="durationLabel(scan)"> · {{ durationLabel(scan) }}</span>
        </div>
        <div v-if="scan.scheduler" class="muted sub">⟳ <router-link to="/schedulers">{{ scan.scheduler.schedule }}</router-link>
          <code class="cron">{{ scan.scheduler.cron }}</code>
          <span v-if="scan.scheduler.enabled"> · next run {{ timeUntil(scan.scheduler.next_run_at) }}</span><span v-else> · paused</span></div>
        <div class="muted sub">🕘 <template v-if="scan.window">runs only {{ scan.window_text }}
            <span v-if="scan.window_next"> · {{ scan.window_open ? 'closes' : 'opens' }} {{ whenLocal(scan.window_next) }}</span></template>
          <template v-else>runs any time</template>
          · <a href="#" @click.prevent="editWindow">change</a></div>
      </div>
      <div class="row acts">
        <button v-if="scan.status === 'running'" @click="act('pause')">Pause</button>
        <button v-if="scan.status === 'paused'" class="primary" @click="act('resume')">Resume</button>
        <button v-if="['running', 'paused'].includes(scan.status)" class="danger" @click="act('stop')">Stop</button>
        <button v-if="!['running', 'paused'].includes(scan.status)" class="primary" @click="act('rerun')">Run again</button>
        <a class="btn ghost" :href="apiUrl(`/scans/${id}/report`)" download>Report</a>
        <div class="more">
          <button class="ghost" @click="menu = !menu" aria-label="More">⋯</button>
          <div v-if="menu" class="menu-panel right">
            <button class="menu-item" @click="rename">Rename</button>
            <button class="menu-item" @click="editWindow">Scan window…</button>
            <button class="menu-item danger" @click="delScan">Delete scan</button>
          </div>
        </div>
      </div>
    </div>

    <div v-if="waiting" class="waitbar">⏸ Outside its scan window — no new jobs start until it opens
      <b v-if="scan.window_next">{{ whenLocal(scan.window_next) }}</b>. Jobs that were already running finish.</div>

    <div v-if="winEdit" class="modal" @click.self="winEdit = null">
      <div class="modal-inner card">
        <div class="row" style="justify-content:space-between"><h2 style="margin:0">Scan window</h2>
          <button class="ghost sm" @click="winEdit = null">✕</button></div>
        <p class="muted" style="margin:6px 0 12px">When this scan's jobs may run<span v-if="scan.scheduler"> — changes the scheduler too</span>.
          Applies right away, also to the run in progress.</p>
        <WindowInput v-model="winEdit.window" />
        <div v-if="winErr" class="err">{{ winErr }}</div>
        <div class="row" style="justify-content:flex-end;margin-top:14px">
          <button class="ghost" @click="winEdit = null">Cancel</button>
          <button class="primary" @click="saveWindow">Save</button>
        </div>
      </div>
    </div>

    <div class="tiles4">
      <div class="card t">
        <div class="tl">Progress</div>
        <div class="tv">{{ pct }}%</div>
        <div class="progress"><div class="bar" :class="{ done: scan.status !== 'running' }" :style="{ width: pct + '%' }"></div></div>
        <div class="ts">{{ scan.jobs_done }}/{{ scan.jobs_total }} jobs<span v-if="scan.jobs_failed" class="st-failed"> · {{ scan.jobs_failed }} failed</span></div>
      </div>
      <div class="card t" @click="showTab('findings')">
        <div class="tl">Open findings</div>
        <div class="tv">{{ scan.findings_open }}</div>
        <div class="sevs"><span v-for="s in SEVS" :key="s" v-show="sevCounts[s]" class="badge" :class="'sev-' + s">{{ sevCounts[s] }} {{ s }}</span></div>
        <div class="ts"><span class="state-new">{{ scan.findings_new }} new</span><span v-if="scan.run_no > 1"> ·
          {{ scan.removed_last_run }} no longer found in the last run</span><span v-if="scan.findings_unconfirmed" :title="UNCONFIRMED"> ·
          {{ scan.findings_unconfirmed }} not re-checked</span></div>
      </div>
      <div class="card t" @click="showTab('assets')">
        <div class="tl">Discovered</div>
        <div class="tv">{{ scan.items_total }}</div>
        <div class="ts">hosts, URLs and requests found along the way</div>
      </div>
      <div class="card t" @click="showTab('jobs')">
        <div class="tl">Working now</div>
        <div class="tv">{{ scan.running }}</div>
        <div class="ts">jobs running<span v-if="scan.steps > 1"> · {{ runningSteps }} step(s) active</span></div>
      </div>
    </div>

    <!-- the workflow, live -->
    <div class="card wfcard">
      <div class="row" style="justify-content:space-between">
        <h2 style="margin:0">Workflow <span class="muted" style="font-weight:400;font-size:13px">— live</span></h2>
        <span class="muted" style="font-size:12.5px">Each box runs once per item it receives, as separate jobs on all scanners.
          Click a box for its details.</span>
      </div>
      <div class="wfgrid" :class="{ withside: !!step }">
        <WorkflowGraph :key="graphKey" :model-value="graph" mode="live" :states="states" :selected="selKey"
                       :height="graphHeight" :input-labels="inputLabels" @select="onSelect" />
        <aside v-if="step" class="side">
          <div class="row" style="justify-content:space-between;flex-wrap:nowrap;align-items:flex-start">
            <b class="st-title">{{ step.index + 1 }}. {{ step.title }}</b>
            <button class="ghost sm" @click="onSelect(selKey)">✕</button>
          </div>
          <div class="muted dd">{{ step.description }}</div>
          <div class="kv"><span>Takes</span>{{ step.input_label }} from {{ srcLabel(step) }}</div>
          <div class="kv" v-if="step.args"><span>Arguments</span><code>{{ step.args }}</code></div>
          <div class="kv"><span>State</span><b :class="'st-' + step.state">{{ step.state }}</b></div>
          <template v-if="step.kind === 'merge'">
            <div class="kv"><span>Merged</span><b>{{ step.items }}</b> unique item(s) passed on — duplicates dropped, no job of its own</div>
          </template>
          <template v-else>
          <div class="kv"><span>Jobs</span>{{ step.jobs.done }} done · {{ step.jobs.running }} running · {{ step.jobs.pending }} waiting<span
            v-if="step.jobs.failed" class="st-failed"> · {{ step.jobs.failed }} failed</span></div>
          <div class="sidebtns">
            <button class="sm" @click="showTab('jobs')">Jobs ({{ step.jobs.total }})</button>
            <button class="sm" :disabled="!step.findings" @click="showTab('findings')">Findings ({{ step.findings }})</button>
            <button class="sm" :disabled="!step.items" @click="showTab('assets')">Found ({{ step.items }})</button>
            <button class="sm" @click="showTab('log')">Full log</button>
          </div>
          <div class="log steplog">{{ stepLog.map(e => (e.agent ? '[' + e.agent + '] ' : '') + e.line).join('\n') || 'no output yet' }}</div>
          </template>
        </aside>
      </div>
    </div>

    <div class="tabs" id="tabs">
      <button :class="{ on: tab === 'findings' }" @click="tab = 'findings'">Findings <span class="cnt">{{ scan.findings_total }}</span></button>
      <button :class="{ on: tab === 'assets' }" @click="tab = 'assets'">Discovered <span class="cnt">{{ scan.items_total }}</span></button>
      <button :class="{ on: tab === 'jobs' }" @click="tab = 'jobs'">Jobs <span class="cnt">{{ scan.jobs_total }}</span></button>
      <button :class="{ on: tab === 'targets' }" @click="tab = 'targets'">Targets <span class="cnt">{{ scan.assets }}</span></button>
      <button :class="{ on: tab === 'log' }" @click="showTab('log')">Live log</button>
      <span v-if="step && tab !== 'targets'" class="chip stepchip">only step {{ step.index + 1 }}: {{ step.title }}
        <a href="#" @click.prevent="onSelect(selKey)">✕</a></span>
    </div>

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
              <tr :id="'finding-' + f.id" :class="['sevrow-' + f.severity, { sel: selFinding === f.id }]" style="cursor:pointer" @click="toggleFinding(f)">
                <td data-label="Sev"><span class="badge" :class="'sev-' + f.severity">{{ f.severity }}</span></td>
                <td data-label="Title">{{ f.title }}</td>
                <td data-label="Target" style="word-break:break-all">{{ f.target }}</td>
                <td data-label="URL" style="word-break:break-all">{{ f.url }}</td>
                <td data-label="State"><span class="state" :class="'state-' + f.state"
                    :title="f.state === 'unconfirmed' ? UNCONFIRMED : ''">{{ f.state === 'unconfirmed' ? 'not re-checked' : f.state }}</span></td>
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
                  <template v-if="detail && detail.evidence"><b class="subh">Evidence</b><div class="log" style="max-height:200px">{{ detail.evidence }}</div></template>
                  <template v-if="detail && detail.reproduce"><b class="subh">Reproduce</b><div class="log" style="max-height:160px">{{ detail.reproduce }}</div></template>
                  <template v-if="detail && Object.keys(detail.raw || {}).length"><b class="subh">Full record</b><div class="log" style="max-height:260px">{{ JSON.stringify(detail.raw, null, 2) }}</div></template>
                  <div v-if="!detail" class="muted" style="font-size:12px">Loading…</div>
                </td>
              </tr>
            </template>
            <tr v-if="!findings.length"><td colspan="6" class="muted">
              {{ scan.status === 'running' ? 'No findings yet — they show up here as soon as a job reports one.' : 'No findings match.' }}</td></tr>
          </tbody>
        </table>
      </div>
      <div v-if="fTotal > FLIMIT" class="row pager">
        <button class="ghost" :disabled="fOffset === 0" @click="fPage(-1)">← Prev</button>
        <span class="muted">{{ fOffset + 1 }}–{{ Math.min(fOffset + FLIMIT, fTotal) }} of {{ fTotal }}</span>
        <button class="ghost" :disabled="fOffset + FLIMIT >= fTotal" @click="fPage(1)">Next →</button>
      </div>
    </template>

    <template v-if="tab === 'assets'">
      <div class="row toolbar">
        <div class="atabs">
          <button v-for="t in visibleATabs" :key="t.key" class="atab" :class="{ on: aType === t.key }" @click="aType = t.key; applyI()">
            {{ t.label }} <span class="cnt">{{ aCount(t.key) }}</span></button>
        </div>
        <span class="spacer" />
        <input v-model="iq" placeholder="search…" style="max-width:200px" @input="applyI" />
        <a class="btn ghost sm" :href="apiUrl(`/scans/${id}/items/export?${iQuery()}`)" download title="One per line">⬇ TXT</a>
      </div>
      <div class="card tablecard">
        <table class="reflow rows">
          <thead><tr><th>Value</th><th>Type</th><th v-if="stages.length > 1">Found by step</th><th>Found on</th><th>Seen</th></tr></thead>
          <tbody>
            <tr v-for="it in items" :key="it.id">
              <td data-label="Value" style="word-break:break-all">
                <a v-if="/^https?:\/\//.test(it.value)" :href="it.value" target="_blank" rel="noopener">{{ it.value }}</a><code v-else>{{ it.value }}</code></td>
              <td data-label="Type"><span class="atype">{{ it.asset_type }}</span></td>
              <td v-if="stages.length > 1" data-label="Step" class="muted">{{ it.stage + 1 }}. {{ stages[it.stage]?.title }}</td>
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

    <template v-if="tab === 'jobs'">
      <div class="row toolbar">
        <Select v-model="jStatus" :options="jobStatusOpts" auto @change="jOffset = 0; loadJobs()" />
        <span class="muted" style="font-size:12.5px">One job = one item through one step. Click a job for its command and output.</span>
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
                  <b class="subh">Live output</b>
                  <div class="log" style="max-height:180px">{{ jobLog.map(e => e.line).join('\n') || 'no output yet' }}</div>
                  <b class="subh">Raw result</b>
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
.head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.title { margin: 0; word-break: break-word; }
.sub { margin-top: 4px; }
.cron { font-size: 11.5px; margin-left: 6px; color: var(--outline); }
.acts { gap: 8px; flex-wrap: nowrap; }
.more { position: relative; }
.tiles4 { display: grid; gap: 12px; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 16px; }
.t { padding: 14px 16px; display: flex; flex-direction: column; gap: 6px; cursor: default; }
.t:nth-child(n+2) { cursor: pointer; }
.t:nth-child(n+2):hover { background: var(--sc); }
.tl { font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--on-surface-variant); }
.tv { font-size: 28px; line-height: 1.1; }
.ts { font-size: 12px; color: var(--on-surface-variant); }
.sevs { display: flex; flex-wrap: wrap; gap: 4px; min-height: 20px; }
.sevs .badge { height: 20px; font-size: 11px; }
.wfcard { margin-top: 14px; }
.wfgrid { display: grid; grid-template-columns: minmax(0, 1fr); gap: 12px; margin-top: 12px; }
.wfgrid.withside { grid-template-columns: minmax(0, 1fr) 340px; }
.side { background: var(--sc); border-radius: var(--radius-s); padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; min-width: 0; }
.st-title { font-weight: 600; }
.dd { font-size: 12.5px; }
.kv { font-size: 12.5px; color: var(--on-surface); }
.kv span { display: inline-block; min-width: 78px; color: var(--on-surface-variant); font-size: 11.5px; }
.kv code { font-size: 11.5px; }
.sidebtns { display: flex; flex-wrap: wrap; gap: 6px; }
.sidebtns button { height: 30px; padding: 0 10px; text-transform: none; letter-spacing: 0; font-weight: 500; font-size: 12.5px; }
.steplog { max-height: 200px; font-size: 11.5px; }
.tabs { display: flex; gap: 4px; flex-wrap: wrap; align-items: center; margin: 20px 0 10px; border-bottom: 1px solid var(--outline-variant); }
.tabs > button { border: 0; border-bottom: 2px solid transparent; border-radius: 0; background: transparent; height: 40px;
  color: var(--on-surface-variant); text-transform: none; letter-spacing: 0; font-weight: 500; font-size: 14px; }
.tabs > button:hover { background: transparent; color: var(--on-surface); box-shadow: none; }
.tabs > button.on { color: var(--accent-ink); border-bottom-color: var(--accent); }
.cnt { font-size: 11px; color: var(--outline); margin-left: 4px; }
.stepchip { margin-left: 8px; color: var(--accent-ink); background: var(--wash); }
.toolbar { margin-bottom: 10px; gap: 8px; }
.spacer { flex: 1; }
.subh { font-size: 13px; display: block; margin-top: 10px; }
.atabs { display: flex; flex-wrap: wrap; gap: 6px; }
.atab { height: 30px; padding: 0 12px; font-size: 12.5px; text-transform: none; letter-spacing: 0; font-weight: 500;
  border-color: var(--outline-variant); color: var(--on-surface-variant); }
.atab.on { background: var(--primary-container); color: var(--accent-ink); border-color: var(--accent); }
.atype { font-size: 11px; padding: 1px 8px; border-radius: 999px; background: var(--sc-high); color: var(--on-surface-variant); }
@media (max-width: 1000px) { .tiles4 { grid-template-columns: repeat(2, minmax(0, 1fr)); } .wfgrid.withside { grid-template-columns: 1fr; } .head { flex-direction: column; } }
.waitbar { margin-top: 12px; padding: 10px 14px; border-radius: var(--radius-s); font-size: 13px;
  background: color-mix(in srgb, var(--warn) 16%, var(--sc)); border: 1px solid color-mix(in srgb, var(--warn) 45%, var(--outline-variant)); }
.modal { position: fixed; inset: 0; background: var(--scrim); display: flex; align-items: flex-start; justify-content: center;
  z-index: 50; padding: 40px 16px; overflow: auto; }
.modal-inner { width: min(860px, 100%); }
</style>
