<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, apiBase, token } from '../api'
import { durationLabel, fmtDuration, timeAgo } from '../util'
import Select from '../components/Select.vue'

const route = useRoute()
const router = useRouter()
const id = route.params.id

async function delScan() {
  if (!confirm(`Delete scan "${scan.value ? scan.value.name : ''}" and all its findings? This can't be undone.`)) return
  try { await api.del('/scans/' + id); router.push('/scans') } catch (e) { alert(e.message) }
}
const JLIMIT = 25, FLIMIT = 25, ILIMIT = 100
const SEVS = ['Critical', 'High', 'Medium', 'Low', 'Info']
const sevOpts = [{ value: '', label: 'All severities' }, ...SEVS.map(s => ({ value: s, label: s }))]
const jobStatusOpts = [{ value: '', label: 'All statuses' },
  ...['running', 'pending', 'done', 'failed', 'cancelled'].map(s => ({ value: s, label: s }))]
function onJobStatus() { jobOffset.value = 0; loadJobs() }

const scan = ref(null)
const events = ref([])
const cursor = ref(0)
const MAX_EVENTS = 3000                   // bound the browser on a long, chatty scan (full log stays server-side)

// assets (jobs)
const jobs = ref([]); const jobsTotal = ref(0); const jobCounts = ref({}); const jobOffset = ref(0)
const jobStatus = ref('')
const selJob = ref(null)                 // the asset the user drilled into

// findings
const findings = ref([]); const fTotal = ref(0); const fOffset = ref(0)
const fState = ref(''); const fSev = ref(''); const fSort = ref('severity'); const fDir = ref('asc'); const fq = ref('')
const selFinding = ref(null)
const detail = ref(null)                 // heavy per-finding data (evidence/reproduce/raw), fetched on expand

// items — the non-finding results (a recon workflow's domains, a crawl's URLs). The panel only exists for a
// scan that actually produced some, so an ordinary vuln scan looks exactly as it did before.
const items = ref([]); const iTotal = ref(0); const iOffset = ref(0)
const iq = ref(''); const iSort = ref('value'); const iDir = ref('asc')
const hasItems = () => !!(scan.value && scan.value.items_total > 0)

let timer = null, es = null

const progress = computed(() => {
  const c = jobCounts.value
  const done = (c.done || 0) + (c.failed || 0) + (c.cancelled || 0)
  const total = Object.values(c).reduce((a, b) => a + b, 0)
  const running = (c.running || 0) + (c.claimed || 0)
  return { done, total, running, pct: total ? Math.round(100 * done / total) : 0 }
})
const logText = computed(() => lines(events.value))
const assetLog = computed(() => selJob.value ? lines(events.value.filter(e => e.job_id === selJob.value.id)) : '')
function lines(evs) {
  const out = []
  for (const e of evs) { out.push((e.agent ? '[' + e.agent + '] ' : '') + e.line); if (e.reasoning) out.push('    ↳ ' + e.reasoning) }
  return out.join('\n')
}

function jobsUrl() {
  const s = jobStatus.value ? `&status=${jobStatus.value}` : ''
  return `/scans/${id}/jobs?limit=${JLIMIT}&offset=${jobOffset.value}${s}`
}
function findingsUrl() {
  let u = `/scans/${id}/findings?limit=${FLIMIT}&offset=${fOffset.value}&state=${fState.value}&sort=${fSort.value}&dir=${fDir.value}`
  if (fSev.value) u += `&severity=${fSev.value}`
  if (fq.value) u += `&q=${encodeURIComponent(fq.value)}`
  if (selJob.value) u += `&target=${encodeURIComponent(selJob.value.target)}`
  return u
}
function itemsUrl() {
  let u = `/scans/${id}/items?limit=${ILIMIT}&offset=${iOffset.value}&sort=${iSort.value}&dir=${iDir.value}`
  if (iq.value) u += `&q=${encodeURIComponent(iq.value)}`
  if (selJob.value) u += `&target=${encodeURIComponent(selJob.value.target)}`
  return u
}
function setISort(col) {
  if (iSort.value === col) iDir.value = iDir.value === 'asc' ? 'desc' : 'asc'
  else { iSort.value = col; iDir.value = col === 'last_seen' ? 'desc' : 'asc' }
  iOffset.value = 0; loadItems()
}
function iSortInd(col) { return iSort.value === col ? (iDir.value === 'asc' ? ' ▲' : ' ▼') : '' }
function iPage(d) { iOffset.value = Math.max(0, iOffset.value + d * ILIMIT); loadItems() }
function applyItemFilters() { iOffset.value = 0; loadItems() }
async function exportItems() {
  // one entry per line, ready to pipe back into a tool — same filters/sort as the list on screen
  let u = `${apiBase()}/scans/${id}/items/export?sort=${iSort.value}&dir=${iDir.value}`
  if (iq.value) u += `&q=${encodeURIComponent(iq.value)}`
  if (selJob.value) u += `&target=${encodeURIComponent(selJob.value.target)}`
  try {
    const r = await fetch(u, { headers: { Authorization: 'Bearer ' + token() } })
    if (!r.ok) throw new Error('export failed')
    const a = document.createElement('a')
    a.href = URL.createObjectURL(await r.blob()); a.download = `scan-${id}-items.txt`; a.click(); URL.revokeObjectURL(a.href)
  } catch (e) { alert(e.message) }
}
function setSort(col) {
  if (fSort.value === col) fDir.value = fDir.value === 'asc' ? 'desc' : 'asc'
  else { fSort.value = col; fDir.value = col === 'last_seen' ? 'desc' : 'asc' }
  fOffset.value = 0; loadFindings()
}
function sortInd(col) { return fSort.value === col ? (fDir.value === 'asc' ? ' ▲' : ' ▼') : '' }
async function toggleFinding(f) {
  if (selFinding.value === f.id) { selFinding.value = null; detail.value = null; return }
  selFinding.value = f.id; detail.value = null
  try { detail.value = await api.get(`/scans/${id}/findings/${f.id}`) } catch (e) { /* transient */ }
}
async function exportFindings(fmt) {
  let u = `${apiBase()}/scans/${id}/findings/export?format=${fmt}&state=${fState.value}&sort=${fSort.value}&dir=${fDir.value}`
  if (fSev.value) u += `&severity=${fSev.value}`
  if (fq.value) u += `&q=${encodeURIComponent(fq.value)}`
  if (selJob.value) u += `&target=${encodeURIComponent(selJob.value.target)}`
  try {
    const r = await fetch(u, { headers: { Authorization: 'Bearer ' + token() } })
    if (!r.ok) throw new Error('export failed')
    const a = document.createElement('a')
    a.href = URL.createObjectURL(await r.blob()); a.download = `scan-${id}-findings.${fmt}`; a.click(); URL.revokeObjectURL(a.href)
  } catch (e) { alert(e.message) }
}
async function loadScan() { scan.value = await api.get('/scans/' + id) }
async function loadJobs() { const r = await api.get(jobsUrl()); jobs.value = r.items; jobsTotal.value = r.total; jobCounts.value = r.counts }
async function loadFindings() { const r = await api.get(findingsUrl()); findings.value = r.items; fTotal.value = r.total }
async function loadItems() { const r = await api.get(itemsUrl()); items.value = r.items; iTotal.value = r.total }
const isLive = () => scan.value && !['done', 'stopped'].includes(scan.value.status)
function stopLive() { if (timer) { clearInterval(timer); timer = null } if (es) { es.close(); es = null } }
function ensureLive() { if (!timer) timer = setInterval(refresh, 2500); if (!es) startStream() }
async function refresh() {
  try {
    await Promise.all([loadScan(), loadJobs(), loadFindings()])
    if (hasItems()) await loadItems()          // only once the scan has actually produced some
    if (!es) { const ev = await api.get('/scans/' + id + '/events?since=' + cursor.value); if (ev.length) pushEvents(ev) }
    if (!isLive()) stopLive()      // a finished scan is static — stop polling + close the stream
  } catch (e) { /* transient */ }
}
function pushEvents(list) {
  for (const e of list) {
    if (e.cursor != null && e.cursor <= cursor.value) continue   // already seen — events arrive in id order
    events.value.push(e)
    if (e.cursor != null && e.cursor > cursor.value) cursor.value = e.cursor
  }
  const over = events.value.length - MAX_EVENTS
  if (over > 0) events.value.splice(0, over)          // drop oldest; the full history stays in the DB
}
function startStream() {
  try {
    es = new EventSource(`${apiBase()}/scans/${id}/stream?since=${cursor.value}&access_token=${encodeURIComponent(token())}`)
    es.onmessage = (m) => { try { pushEvents([JSON.parse(m.data)]) } catch { /* keepalive */ } }
    es.onerror = () => { if (es) { es.close(); es = null } }
  } catch { es = null }
}
async function act(a) {
  try { await api.post('/scans/' + id + '/' + a); await refresh(); if (isLive()) ensureLive() }  // rerun/resume -> live again
  catch (e) { alert(e.message) }
}
async function downloadReport() {
  try {
    const r = await fetch(`${apiBase()}/scans/${id}/report`, { headers: { Authorization: 'Bearer ' + token() } })
    if (!r.ok) throw new Error('could not generate report')
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([await r.text()], { type: 'text/markdown' }))
    a.download = `scan-${id}-report.md`; a.click(); URL.revokeObjectURL(a.href)
  } catch (e) { alert(e.message) }
}
function selectAsset(j) {
  selJob.value = (selJob.value && selJob.value.id === j.id) ? null : j
  fOffset.value = 0; loadFindings()
  iOffset.value = 0; if (hasItems()) loadItems()
}
function jobPage(d) { jobOffset.value = Math.max(0, jobOffset.value + d * JLIMIT); loadJobs() }
function fPage(d) { fOffset.value = Math.max(0, fOffset.value + d * FLIMIT); loadFindings() }
function applyFindingFilters() { fOffset.value = 0; loadFindings() }

onMounted(async () => {
  // load the tables WITHOUT events (refresh() would also poll events and race the seed below → duplicates)
  await Promise.all([loadScan(), loadJobs(), loadFindings()]).catch(() => {})
  if (hasItems()) await loadItems().catch(() => {})
  // seed only the MOST RECENT events (not the whole history) so opening a big scan doesn't replay thousands
  const seed = await api.get('/scans/' + id + '/events?tail=200').catch(() => [])
  if (seed.length) pushEvents(seed)
  if (isLive()) ensureLive()       // only a running/paused scan needs the live stream + polling
})
onUnmounted(() => { clearInterval(timer); if (es) es.close() })
</script>

<template>
  <div v-if="scan">
    <div class="row" style="justify-content:space-between;align-items:flex-start;gap:12px">
      <div>
        <h1 style="margin:0">{{ scan.name }} <span class="state" :class="'st-' + scan.status">{{ scan.status }}</span></h1>
        <div class="muted" style="margin-top:4px">
          run #{{ scan.run_no }} · {{ scan.assets }} assets<span v-if="durationLabel(scan)"> · {{ durationLabel(scan) }}</span>
        </div>
      </div>
      <div class="row" style="gap:8px">
        <button v-if="scan.status === 'running'" @click="act('pause')">Pause</button>
        <button v-if="scan.status === 'paused'" class="primary" @click="act('resume')">Resume</button>
        <button v-if="['running', 'paused'].includes(scan.status)" class="danger" @click="act('stop')">Stop</button>
        <button class="primary" @click="act('rerun')">Rerun</button>
        <button class="ghost" @click="downloadReport">Report</button>
        <button class="danger ghost" @click="delScan">Delete</button>
      </div>
    </div>

    <div class="progress" style="margin-top:12px" :title="progress.done + '/' + progress.total + ' assets done'">
      <div class="bar" :class="{ done: scan.status !== 'running' }" :style="{ width: progress.pct + '%' }"></div>
    </div>
    <div class="muted" style="font-size:12px;margin-top:4px">
      {{ progress.done }}/{{ progress.total }} assets done<span v-if="progress.running"> · {{ progress.running }} in progress</span> ·
      <span class="state-new">{{ scan.findings_new }} new</span> · {{ scan.findings_open_state }} open ·
      <span class="muted">{{ scan.findings_resolved }} resolved</span>
    </div>

    <!-- assets -->
    <div class="row" style="justify-content:space-between;align-items:flex-end;margin-top:18px">
      <h2 style="margin:0">Assets <span class="muted" style="font-weight:400">({{ jobsTotal }})</span></h2>
      <Select v-model="jobStatus" :options="jobStatusOpts" auto right @change="onJobStatus" />
    </div>
    <div class="muted" style="font-size:12px;margin:4px 0">Click an asset to see its findings, command, and live steps.</div>
    <div class="card tablecard">
    <table class="reflow rows">
      <thead><tr><th>Asset</th><th>Status</th><th>Command</th><th>Duration</th></tr></thead>
      <tbody>
        <template v-for="j in jobs" :key="j.id">
          <tr @click="selectAsset(j)" :class="{ sel: selJob && selJob.id === j.id }" style="cursor:pointer">
            <td data-label="Asset">{{ j.target }}</td>
            <td data-label="Status"><span class="state" :class="'st-' + j.status">{{ j.status }}</span></td>
            <td data-label="Command"><code style="font-size:12px;word-break:break-all">{{ j.command || '—' }}</code></td>
            <td data-label="Duration">{{ j.duration_sec != null ? fmtDuration(j.duration_sec) : '—' }}</td>
          </tr>
          <tr v-if="selJob && selJob.id === j.id" class="expand">
            <td colspan="4">
              <div class="muted" style="font-size:12px">runner #{{ j.runner_id || '—' }} · attempt {{ j.attempts }} · run #{{ j.run_no }}</div>
              <div v-if="j.error" class="err" style="margin:6px 0">error: {{ j.error }}</div>
              <b style="font-size:13px">Live steps</b>
              <div class="log" style="max-height:180px">{{ assetLog || 'no steps yet' }}</div>
              <b style="font-size:13px">Raw output</b>
              <div class="log" style="max-height:220px">{{ j.output || (['pending','claimed','running'].includes(j.status) ? '(still running — the engine prints its output when the step finishes)' : '(no engine stdout captured)') }}</div>
            </td>
          </tr>
        </template>
        <tr v-if="!jobs.length"><td colspan="4" class="muted">No assets.</td></tr>
      </tbody>
    </table>
    </div>
    <div v-if="jobsTotal > JLIMIT" class="row pager">
      <button class="ghost" :disabled="jobOffset === 0" @click="jobPage(-1)">← Prev</button>
      <span class="muted">{{ jobOffset + 1 }}–{{ Math.min(jobOffset + JLIMIT, jobsTotal) }} of {{ jobsTotal }}</span>
      <button class="ghost" :disabled="jobOffset + JLIMIT >= jobsTotal" @click="jobPage(1)">Next →</button>
    </div>

    <!-- findings -->
    <div class="row" style="justify-content:space-between;align-items:flex-end;margin-top:20px;gap:8px">
      <h2 style="margin:0">Findings <span class="muted" style="font-weight:400">({{ fTotal }})</span>
        <span v-if="selJob" class="chip">{{ selJob.target }} <a @click.prevent="selectAsset(selJob)" href="#">✕</a></span>
      </h2>
      <div class="row" style="gap:8px">
        <Select v-model="fSev" :options="sevOpts" auto right @change="applyFindingFilters" />
        <input v-model="fq" placeholder="search…" style="width:auto;max-width:150px" @keyup.enter="applyFindingFilters" @input="applyFindingFilters" />
        <button class="ghost" title="Export filtered findings as CSV" @click="exportFindings('csv')">⬇ CSV</button>
        <button class="ghost" title="Export filtered findings as JSON" @click="exportFindings('json')">JSON</button>
      </div>
    </div>
    <div class="muted" style="font-size:12px;margin-bottom:4px">Click a column to sort · click a finding for full detail.</div>
    <div class="card tablecard">
    <table class="reflow findings rows">
      <thead><tr>
        <th class="sortable" @click="setSort('severity')">Sev{{ sortInd('severity') }}</th>
        <th class="sortable" @click="setSort('title')">Title{{ sortInd('title') }}</th>
        <th class="sortable" @click="setSort('target')">Asset{{ sortInd('target') }}</th>
        <th>URL</th>
        <th class="sortable" @click="setSort('state')">State{{ sortInd('state') }}</th>
        <th class="sortable" @click="setSort('last_seen')">Seen{{ sortInd('last_seen') }}</th>
      </tr></thead>
      <tbody>
        <template v-for="f in findings" :key="f.id">
          <tr :class="'sevrow-' + f.severity" style="cursor:pointer" @click="toggleFinding(f)">
            <td data-label="Sev"><span class="badge" :class="'sev-' + f.severity">{{ f.severity }}</span></td>
            <td data-label="Title">{{ f.title }}</td>
            <td data-label="Asset">{{ f.target }}</td>
            <td data-label="URL" style="word-break:break-all">{{ f.url }}</td>
            <td data-label="State"><span class="state" :class="'state-' + f.state">{{ f.state }}</span></td>
            <td data-label="Seen" class="muted" style="white-space:nowrap" :title="f.last_seen">{{ timeAgo(f.last_seen) }}</td>
          </tr>
          <tr v-if="selFinding === f.id" class="expand">
            <td colspan="6">
              <div class="detail">
                <div><span class="k">Severity</span><span class="badge" :class="'sev-' + f.severity">{{ f.severity }}</span></div>
                <div><span class="k">State</span>{{ f.state }}</div>
                <div><span class="k">Asset</span>{{ f.target }}</div>
                <div v-if="f.cls"><span class="k">Class</span>{{ f.cls }}</div>
                <div v-if="f.url"><span class="k">URL</span><a :href="f.url" target="_blank" rel="noopener">{{ f.url }}</a></div>
                <div><span class="k">Kind</span>{{ f.template_kind }}</div>
                <div><span class="k">First seen</span>{{ f.first_seen }}</div>
                <div><span class="k">Last seen</span>{{ f.last_seen }}</div>
              </div>
              <template v-if="detail && detail.evidence"><b style="font-size:13px">Evidence</b><div class="log" style="max-height:200px">{{ detail.evidence }}</div></template>
              <template v-if="detail && detail.reproduce"><b style="font-size:13px">Reproduce</b><div class="log" style="max-height:160px">{{ detail.reproduce }}</div></template>
              <template v-if="detail && Object.keys(detail.raw || {}).length">
                <b style="font-size:13px">Full report (from boxcutter)</b>
                <div class="log" style="max-height:260px">{{ JSON.stringify(detail.raw, null, 2) }}</div>
              </template>
              <div v-if="!detail" class="muted" style="font-size:12px">Loading detail…</div>
            </td>
          </tr>
        </template>
        <tr v-if="!findings.length"><td colspan="6" class="muted">No findings match.</td></tr>
      </tbody>
    </table>
    </div>
    <div v-if="fTotal > FLIMIT" class="row pager">
      <button class="ghost" :disabled="fOffset === 0" @click="fPage(-1)">← Prev</button>
      <span class="muted">{{ fOffset + 1 }}–{{ Math.min(fOffset + FLIMIT, fTotal) }} of {{ fTotal }}</span>
      <button class="ghost" :disabled="fOffset + FLIMIT >= fTotal" @click="fPage(1)">Next →</button>
    </div>

    <!-- items: results that aren't findings (recon domains, crawled URLs) — only for scans that made some -->
    <template v-if="hasItems()">
      <div class="row" style="justify-content:space-between;align-items:flex-end;margin-top:20px;gap:8px">
        <h2 style="margin:0">Items <span class="muted" style="font-weight:400">({{ iTotal }})</span>
          <span v-if="selJob" class="chip">{{ selJob.target }} <a @click.prevent="selectAsset(selJob)" href="#">✕</a></span>
        </h2>
        <div class="row" style="gap:8px">
          <input v-model="iq" placeholder="search…" style="width:auto;max-width:150px" @keyup.enter="applyItemFilters" @input="applyItemFilters" />
          <button class="ghost" title="Download as a .txt file, one entry per line" @click="exportItems">⬇ TXT</button>
        </div>
      </div>
      <div class="muted" style="font-size:12px;margin-bottom:4px">
        Results this scan produced that aren't findings — domains, hosts, URLs. TXT gives you one per line.
      </div>
      <div class="card tablecard">
        <table class="reflow rows">
          <thead><tr>
            <th class="sortable" @click="setISort('value')">Value{{ iSortInd('value') }}</th>
            <th class="sortable" @click="setISort('target')">Asset{{ iSortInd('target') }}</th>
            <th class="sortable" @click="setISort('last_seen')">Seen{{ iSortInd('last_seen') }}</th>
          </tr></thead>
          <tbody>
            <tr v-for="it in items" :key="it.id">
              <td data-label="Value" style="word-break:break-all">
                <a v-if="/^https?:\/\//.test(it.value)" :href="it.value" target="_blank" rel="noopener">{{ it.value }}</a>
                <code v-else>{{ it.value }}</code>
                <span v-if="it.label && it.label !== it.value" class="muted" style="font-size:12px"> · {{ it.label }}</span>
              </td>
              <td data-label="Asset">{{ it.target }}</td>
              <td data-label="Seen" class="muted" style="white-space:nowrap" :title="it.last_seen">{{ timeAgo(it.last_seen) }}</td>
            </tr>
            <tr v-if="!items.length"><td colspan="3" class="muted">No items match.</td></tr>
          </tbody>
        </table>
      </div>
      <div v-if="iTotal > ILIMIT" class="row pager">
        <button class="ghost" :disabled="iOffset === 0" @click="iPage(-1)">← Prev</button>
        <span class="muted">{{ iOffset + 1 }}–{{ Math.min(iOffset + ILIMIT, iTotal) }} of {{ iTotal }}</span>
        <button class="ghost" :disabled="iOffset + ILIMIT >= iTotal" @click="iPage(1)">Next →</button>
      </div>
    </template>

    <h2 style="margin-top:20px">Live log</h2>
    <div class="log">{{ logText || 'waiting for output…' }}</div>
  </div>
</template>
