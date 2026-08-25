<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, setActivitySeen } from '../api'
import { timeAgo } from '../util'
import Select from '../components/Select.vue'

const router = useRouter()
const LIMIT = 50
const items = ref([])
const total = ref(0)
const offset = ref(0)
const kind = ref('')
let timer = null

const KINDS = ['', 'scan_created', 'job_claimed', 'scan_done', 'new_critical', 'job_failed', 'job_retry',
  'scan_paused', 'scan_stopped', 'scan_rerun', 'scanner_enrolled', 'agent_lost']
const kindOpts = KINDS.map(k => ({ value: k, label: k ? k.replace(/_/g, ' ') : 'All events' }))

function url() {
  const k = kind.value ? `&kind=${kind.value}` : ''
  return `/activity?limit=${LIMIT}&offset=${offset.value}${k}`
}
async function load() {
  try {
    const r = await api.get(url())
    items.value = r.items; total.value = r.total
    if (offset.value === 0 && r.items[0]) setActivitySeen(r.items[0].id)   // mark newest as seen
  } catch (e) { /* transient */ }
}
function go(a) {
  if (a.scan_id) router.push('/scans/' + a.scan_id)
  else if (a.runner_id) router.push('/scanners/' + a.runner_id)
}
function page(d) { offset.value = Math.max(0, offset.value + d * LIMIT); load() }
function applyFilter() { offset.value = 0; load() }
onMounted(async () => { await load(); timer = setInterval(load, 3000) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center">
    <h1 style="margin:0">Activity <span class="muted" style="font-weight:400;font-size:16px">({{ total }})</span></h1>
    <Select v-model="kind" :options="kindOpts" auto right @change="applyFilter" />
  </div>

  <div class="card tablecard" style="margin-top:12px">
  <table class="reflow rows">
    <thead><tr><th>When</th><th>Event</th><th>Details</th></tr></thead>
    <tbody>
      <tr v-for="a in items" :key="a.id" @click="go(a)" :style="{ cursor: (a.scan_id || a.runner_id) ? 'pointer' : 'default' }">
        <td data-label="When" style="white-space:nowrap"><span class="dot" :class="a.severity === 'critical' ? 'bad' : (a.severity === 'warn' ? 'busy' : 'ok')"></span> {{ timeAgo(a.at) }}</td>
        <td data-label="Event"><span class="chip">{{ a.kind.replace(/_/g, ' ') }}</span></td>
        <td data-label="Details" :class="{ crit: a.severity === 'critical' }">{{ a.message }}</td>
      </tr>
      <tr v-if="!items.length"><td colspan="3" class="muted">No activity yet.</td></tr>
    </tbody>
  </table>
  </div>

  <div v-if="total > LIMIT" class="row pager">
    <button class="ghost" :disabled="offset === 0" @click="page(-1)">← Prev</button>
    <span class="muted">{{ offset + 1 }}–{{ Math.min(offset + LIMIT, total) }} of {{ total }}</span>
    <button class="ghost" :disabled="offset + LIMIT >= total" @click="page(1)">Next →</button>
  </div>
</template>
