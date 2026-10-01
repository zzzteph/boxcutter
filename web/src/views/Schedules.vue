<script setup>
// Continuous perimeter monitoring: attach a recurring schedule to a scan. The server re-runs it every interval,
// so its findings diff over time (new / resolved). One schedule per scan. See server/app/routers/schedules.py.
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'
import Select from '../components/Select.vue'
import { timeAgo } from '../util'

const router = useRouter()
const rows = ref([])
const scans = ref([])
const err = ref('')
const newScan = ref(null)
const newInterval = ref(3600)
let timer = null

const INTERVALS = [
  { value: 900, label: 'every 15 minutes' }, { value: 3600, label: 'hourly' },
  { value: 21600, label: 'every 6 hours' }, { value: 43200, label: 'every 12 hours' },
  { value: 86400, label: 'daily' }, { value: 604800, label: 'weekly' },
]
function intervalLabel(s) { return (INTERVALS.find(i => i.value === s) || {}).label || `every ${Math.round(s / 60)} min` }

// scans that don't already have a schedule — the pickable set for a new one
const scheduledIds = computed(() => new Set(rows.value.map(r => r.scan_id)))
const scanOpts = computed(() => scans.value.filter(s => !scheduledIds.value.has(s.id))
  .map(s => ({ value: s.id, label: `${s.name} (#${s.id})` })))

async function load() {
  try {
    rows.value = await api.get('/schedules')
    scans.value = await api.get('/scans')
  } catch (e) { /* transient */ }
}
async function create() {
  err.value = ''
  if (!newScan.value) { err.value = 'pick a scan to monitor'; return }
  try {
    await api.put('/schedules/' + newScan.value, { interval_seconds: newInterval.value, enabled: true })
    newScan.value = null; await load()
  } catch (e) { err.value = e.message }
}
async function setInterval_(r, v) {
  try { await api.put('/schedules/' + r.scan_id, { interval_seconds: v, enabled: r.enabled }); await load() }
  catch (e) { alert(e.message) }
}
async function toggle(r) {
  try { await api.put('/schedules/' + r.scan_id, { interval_seconds: r.interval_seconds, enabled: !r.enabled }); await load() }
  catch (e) { alert(e.message) }
}
async function del(r) {
  if (!confirm(`Stop monitoring "${r.scan_name}"?`)) return
  try { await api.del('/schedules/' + r.scan_id); await load() } catch (e) { alert(e.message) }
}
function fmtNext(r) {
  if (!r.enabled) return 'paused'
  if (!r.next_run_at) return '—'
  const d = new Date(r.next_run_at), now = Date.now()
  const mins = Math.round((d - now) / 60000)
  if (mins <= 0) return 'due now'
  if (mins < 60) return `in ${mins} min`
  return `in ${Math.round(mins / 60)} h`
}
onMounted(() => { load(); timer = setInterval(load, 15000) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <h1>Monitoring</h1>
  <p class="muted">Keep a scan running continuously to watch your perimeter: the server re-runs it on a
    schedule, and its findings diff over time — new issues show as <b>new</b>, fixed ones flip to
    <b>resolved</b>. Build a recon/scan, then schedule it here.</p>

  <div class="card" style="margin:14px 0">
    <h2>Monitor a scan</h2>
    <div class="row" style="gap:12px;align-items:flex-end;flex-wrap:wrap">
      <div style="flex:1;min-width:220px">
        <label>Scan</label>
        <Select v-model="newScan" :options="scanOpts" placeholder="pick a scan to monitor…" />
      </div>
      <div style="min-width:180px">
        <label>How often</label>
        <Select v-model="newInterval" :options="INTERVALS" />
      </div>
      <button class="primary" @click="create">Start monitoring</button>
    </div>
    <p v-if="err" class="err">{{ err }}</p>
    <p v-if="!scanOpts.length && !rows.length" class="muted" style="font-size:13px">No scans yet —
      <router-link to="/scans/new">create one</router-link> first.</p>
  </div>

  <div class="card tablecard">
    <table class="reflow rows">
      <thead><tr><th>Scan</th><th>Status</th><th>Every</th><th>Last run</th><th>Next</th><th></th></tr></thead>
      <tbody>
        <tr v-for="r in rows" :key="r.id">
          <td data-label="Scan"><a href="#" @click.prevent="router.push('/scans/' + r.scan_id)"><b>{{ r.scan_name }}</b></a></td>
          <td data-label="Status"><span v-if="r.scan_status" class="state" :class="'st-' + r.scan_status">{{ r.scan_status }}</span></td>
          <td data-label="Every">
            <Select :modelValue="r.interval_seconds" :options="INTERVALS" auto @update:modelValue="v => setInterval_(r, v)" />
          </td>
          <td data-label="Last run" class="muted">{{ r.last_run_at ? timeAgo(r.last_run_at) : 'not yet' }}</td>
          <td data-label="Next" :class="r.enabled ? '' : 'muted'">{{ fmtNext(r) }}</td>
          <td data-label="">
            <div class="row" style="gap:6px;justify-content:flex-end">
              <button class="sm ghost" @click="toggle(r)">{{ r.enabled ? 'Pause' : 'Resume' }}</button>
              <button class="sm danger ghost" @click="del(r)">Remove</button>
            </div>
          </td>
        </tr>
        <tr v-if="!rows.length"><td colspan="6" class="muted">Nothing monitored yet. Add a scan above.</td></tr>
      </tbody>
    </table>
  </div>
</template>
