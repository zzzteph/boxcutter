<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, isAdmin } from '../api'
import { timeAgo } from '../util'

const router = useRouter()
const runners = ref([])
const newToken = ref('')
const admin = isAdmin()
let timer = null

async function load() { try { runners.value = await api.get('/runners') } catch (e) { /* transient */ } }
async function bump(r, d) {
  const cur = (r.desired_slots != null ? r.desired_slots : r.slots)
  try { await api.patch('/runners/' + r.id, { concurrency: Math.max(0, Math.min(32, cur + d)) }); await load() }
  catch (e) { alert(e.message) }
}
async function delRunner(r) {
  if (!confirm(`Remove scanner "${r.name || ('runner #' + r.id)}" from the fleet?`)) return
  try { await api.del('/runners/' + r.id); await load() } catch (e) { alert(e.message) }
}
async function mkToken() {
  try { const r = await api.post('/enroll-tokens', { label: 'ui' }); newToken.value = r.token }
  catch (e) { alert(e.message) }
}
function open(r) { router.push('/scanners/' + r.id) }
function meterClass(v) { return v >= 85 ? 'hi' : (v >= 60 ? 'mid' : '') }

// The server has no idea what the newest boxcutter release is — but the fleet does: the highest engine version
// any scanner reports is the newest one we have actually seen, so anything below it is running an old engine.
function verKey(v) { return (String(v || '').match(/\d+/g) || []).map(Number) }
function cmpVer(a, b) {
  const x = verKey(a), y = verKey(b)
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] || 0) - (y[i] || 0)
    if (d) return d > 0 ? 1 : -1
  }
  return 0
}
const newestEngine = computed(() => runners.value.map(r => r.engine_version).filter(Boolean)
  .reduce((best, v) => (!best || cmpVer(v, best) > 0 ? v : best), ''))
function outdated(r) {
  return !!(r.engine_version && newestEngine.value && cmpVer(r.engine_version, newestEngine.value) < 0)
}
onMounted(async () => { await load(); timer = setInterval(load, 3000) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="row" style="justify-content:space-between">
    <h1>Scanners</h1>
    <button class="primary" @click="mkToken">New enroll token</button>
  </div>
  <div v-if="newToken" class="card" style="margin:10px 0">
    <b>Enroll token (shown once):</b> <code style="word-break:break-all">{{ newToken }}</code>
    <div class="muted" style="font-size:12px">Paste this into a scanner's local UI (or set <code>ENROLL_TOKEN</code>) to connect it.</div>
  </div>

  <div class="card tablecard">
  <table class="reflow rows">
    <thead><tr><th></th><th>Scanner</th><th>IP</th><th>Status</th><th>Slots</th><th>CPU</th><th>Memory</th><th>Boxcutter</th><th>Agent</th><th>Last beat</th></tr></thead>
    <tbody>
      <tr v-for="r in runners" :key="r.id" @click="open(r)" style="cursor:pointer">
        <td data-label=""><span class="dot" :class="r.status === 'disconnected' ? 'bad' : (r.status === 'busy' ? 'busy' : 'ok')"></span></td>
        <td data-label="Scanner"><b>{{ r.name || ('runner #' + r.id) }}</b>
          <span v-if="r.internal" class="tag sm" title="Built-in agent — can't be removed">built-in</span></td>
        <td data-label="IP"><code>{{ r.ip || '—' }}</code></td>
        <td data-label="Status">{{ r.status }}</td>
        <td data-label="Slots">
          <div class="row" style="gap:6px;align-items:center;flex-wrap:nowrap">
            <span>{{ r.busy_slots }}/{{ r.slots }}</span>
            <span v-if="r.desired_slots != null" class="muted" title="requested">→ {{ r.desired_slots }}</span>
            <template v-if="admin">
              <button class="sm ghost" style="padding:0 10px" title="run fewer" @click.stop="bump(r, -1)">−</button>
              <button class="sm ghost" style="padding:0 10px" title="run more" @click.stop="bump(r, 1)">+</button>
            </template>
          </div>
        </td>
        <td data-label="CPU">
          <template v-if="r.metrics && r.metrics.cpu != null">
            <div class="meter" style="min-width:70px"><div :class="meterClass(r.metrics.cpu)" :style="{ width: r.metrics.cpu + '%' }"></div></div>
            <span class="muted" style="font-size:12px">{{ r.metrics.cpu }}%</span>
          </template>
          <span v-else class="muted">—</span>
        </td>
        <td data-label="Memory">
          <template v-if="r.metrics && r.metrics.mem != null">
            <div class="meter" style="min-width:70px"><div :class="meterClass(r.metrics.mem)" :style="{ width: r.metrics.mem + '%' }"></div></div>
            <span class="muted" style="font-size:12px">{{ r.metrics.mem }}%</span>
          </template>
          <span v-else class="muted">—</span>
        </td>
        <td data-label="Boxcutter">
          <code>{{ r.engine_version || '—' }}</code>
          <span v-if="outdated(r)" class="tag sm" :title="'Newest engine in the fleet: ' + newestEngine"
                style="color:var(--warn);background:rgba(253,176,34,.16);margin-left:6px">old</span>
        </td>
        <td data-label="Agent" class="muted">v{{ r.version || '?' }}</td>
        <td data-label="Last beat">
          <div class="row" style="gap:8px;align-items:center;flex-wrap:nowrap;justify-content:space-between">
            <span>{{ timeAgo(r.last_heartbeat) }}</span>
            <button v-if="admin && !r.internal" class="danger ghost sm" title="Remove scanner" @click.stop="delRunner(r)">Remove</button>
          </div>
        </td>
      </tr>
      <tr v-if="!runners.length"><td colspan="10" class="muted">No scanners connected. Start one and enroll it with a token.</td></tr>
    </tbody>
  </table>
  </div>
</template>
