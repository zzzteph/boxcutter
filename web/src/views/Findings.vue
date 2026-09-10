<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api'
import { timeAgo } from '../util'
import Select from '../components/Select.vue'

const route = useRoute()
const router = useRouter()
const LIMIT = 50
const SEVS = ['Critical', 'High', 'Medium', 'Low', 'Info']
const sevOpts = [{ value: '', label: 'All severities' }, ...SEVS.map(s => ({ value: s, label: s }))]

const items = ref([])
const total = ref(0)
const offset = ref(0)
const sort = ref('last_seen')       // severity|title|target|scan|state|last_seen
const dir = ref('desc')
const loading = ref(false)
const q = ref(route.query.q || '')
const severity = ref(route.query.severity || '')
let timer = null, qTimer = null

function findingsUrl() {
  let u = `/findings?limit=${LIMIT}&offset=${offset.value}&sort=${sort.value}&dir=${dir.value}`
  if (severity.value) u += `&severity=${severity.value}`
  if (q.value) u += `&q=${encodeURIComponent(q.value)}`
  return u
}
async function load() {
  loading.value = true
  try { const r = await api.get(findingsUrl()); items.value = r.items; total.value = r.total } catch (e) { /* transient */ }
  finally { loading.value = false }
}
function apply() { offset.value = 0; load() }
function onSearch() { clearTimeout(qTimer); qTimer = setTimeout(apply, 250) }
function setSort(col) {
  if (sort.value === col) dir.value = dir.value === 'asc' ? 'desc' : 'asc'
  else { sort.value = col; dir.value = (col === 'last_seen' || col === 'severity') ? 'desc' : 'asc' }
  offset.value = 0; load()
}
function sortInd(col) { return sort.value === col ? (dir.value === 'asc' ? ' ▲' : ' ▼') : '' }
function page(d) { offset.value = Math.max(0, offset.value + d * LIMIT); load() }
function openFinding(f) { router.push({ path: '/scans/' + f.scan_id, query: { finding: f.id } }) }
// keep the first page fresh (new findings surface); pause once the user has paged or re-sorted away from the top
async function refreshTop() {
  if (offset.value !== 0 || loading.value) return
  try { const r = await api.get(findingsUrl()); items.value = r.items; total.value = r.total } catch (e) { /* */ }
}
onMounted(async () => { await load(); timer = setInterval(refreshTop, 5000) })
onUnmounted(() => { clearInterval(timer); clearTimeout(qTimer) })
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center;gap:10px">
    <h1 style="margin:0">Findings</h1>
    <div class="row" style="gap:8px">
      <Select v-model="severity" :options="sevOpts" auto @change="apply" />
      <input v-model="q" placeholder="search all findings…" style="width:auto;max-width:240px"
        @keyup.enter="apply" @input="onSearch" />
    </div>
  </div>
  <div class="muted" style="font-size:12px;margin:6px 0">Across all scans. Click a column to sort · click a
    finding to open it in its scan.</div>

  <div class="card tablecard">
  <table class="reflow findings rows">
    <thead><tr>
      <th class="sortable" @click="setSort('severity')">Sev{{ sortInd('severity') }}</th>
      <th class="sortable" @click="setSort('title')">Title{{ sortInd('title') }}</th>
      <th class="sortable" @click="setSort('target')">Asset{{ sortInd('target') }}</th>
      <th class="sortable" @click="setSort('scan')">Scan{{ sortInd('scan') }}</th>
      <th class="sortable" @click="setSort('state')">State{{ sortInd('state') }}</th>
      <th class="sortable" @click="setSort('last_seen')">Seen{{ sortInd('last_seen') }}</th>
    </tr></thead>
    <tbody>
      <tr v-for="f in items" :key="f.id" :class="'sevrow-' + f.severity" style="cursor:pointer"
        @click="openFinding(f)">
        <td data-label="Sev"><span class="badge" :class="'sev-' + f.severity">{{ f.severity }}</span></td>
        <td data-label="Title">{{ f.title }}</td>
        <td data-label="Asset">{{ f.target }}</td>
        <td data-label="Scan">{{ f.scan }}</td>
        <td data-label="State"><span class="state" :class="'state-' + f.state">{{ f.state }}</span></td>
        <td data-label="Seen" style="white-space:nowrap">{{ timeAgo(f.last_seen) }}</td>
      </tr>
      <tr v-if="!items.length && !loading"><td colspan="6" class="muted">No findings match.</td></tr>
    </tbody>
  </table>
  </div>

  <div class="row" style="justify-content:center;margin:16px 0;gap:12px;align-items:center">
    <button class="ghost" :disabled="offset === 0 || loading" @click="page(-1)">← Prev</button>
    <span class="muted" style="font-size:12px">
      {{ total ? offset + 1 : 0 }}–{{ Math.min(offset + LIMIT, total) }} of {{ total }}</span>
    <button class="ghost" :disabled="offset + LIMIT >= total || loading" @click="page(1)">Next →</button>
  </div>
</template>
