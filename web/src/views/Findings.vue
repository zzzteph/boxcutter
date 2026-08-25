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
const next = ref(null)          // keyset cursor for the next page (null = no more)
const loading = ref(false)
const q = ref(route.query.q || '')
const severity = ref(route.query.severity || '')
let timer = null, qTimer = null

function url(before) {
  let u = `/findings?limit=${LIMIT}`
  if (before != null) u += `&before=${before}`
  if (severity.value) u += `&severity=${severity.value}`
  if (q.value) u += `&q=${encodeURIComponent(q.value)}`
  return u
}
async function loadFirst() {
  loading.value = true
  try { const r = await api.get(url(null)); items.value = r.items; next.value = r.next } catch (e) { /* transient */ }
  finally { loading.value = false }
}
async function loadMore() {
  if (next.value == null || loading.value) return
  loading.value = true
  try { const r = await api.get(url(next.value)); items.value = items.value.concat(r.items); next.value = r.next }
  catch (e) { /* */ } finally { loading.value = false }
}
function apply() { loadFirst() }
function onSearch() { clearTimeout(qTimer); qTimer = setTimeout(loadFirst, 250) }
// keep the first page fresh (new findings surface on top); pause once the user has paged further down
async function refreshTop() {
  if (items.value.length > LIMIT || loading.value) return
  try { const r = await api.get(url(null)); items.value = r.items; next.value = r.next } catch (e) { /* */ }
}
onMounted(async () => { await loadFirst(); timer = setInterval(refreshTop, 5000) })
onUnmounted(() => { clearInterval(timer); clearTimeout(qTimer) })
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center;gap:10px">
    <h1 style="margin:0">Findings</h1>
    <div class="row" style="gap:8px">
      <Select v-model="severity" :options="sevOpts" auto @change="apply" />
      <input v-model="q" placeholder="search all findings…" style="width:auto;max-width:240px"
        @keyup.enter="loadFirst" @input="onSearch" />
    </div>
  </div>
  <div class="muted" style="font-size:12px;margin:6px 0">Most recent across all scans — pick a severity for
    "most severe first". Click a finding to open its scan.</div>

  <div class="card tablecard">
  <table class="reflow findings rows">
    <thead><tr><th>Sev</th><th>Title</th><th>Asset</th><th>Scan</th><th>State</th><th>Seen</th></tr></thead>
    <tbody>
      <tr v-for="f in items" :key="f.id" :class="'sevrow-' + f.severity" style="cursor:pointer"
        @click="router.push('/scans/' + f.scan_id)">
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

  <div class="row" style="justify-content:center;margin:16px 0;gap:12px">
    <button v-if="next != null" class="tonal" :disabled="loading" @click="loadMore">
      {{ loading ? 'Loading…' : 'Load more' }}</button>
    <span class="muted" style="font-size:12px">{{ items.length }} shown<span v-if="next == null && items.length"> · end</span></span>
  </div>
</template>
