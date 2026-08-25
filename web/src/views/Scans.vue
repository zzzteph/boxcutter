<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { api } from '../api'
import { durationLabel } from '../util'

const LIMIT = 20
const scans = ref([])
const total = ref(0)
const offset = ref(0)
const q = ref('')
const loading = ref(true)

function scansUrl() {
  const qs = q.value ? `&q=${encodeURIComponent(q.value)}` : ''
  return `/scans?limit=${LIMIT}&offset=${offset.value}${qs}`
}
async function refresh() {
  try { const r = await api.get(scansUrl()); scans.value = r.items; total.value = r.total } catch (e) { /* transient */ }
  finally { loading.value = false }
}
function search() { offset.value = 0; refresh() }
function page(delta) { offset.value = Math.max(0, offset.value + delta * LIMIT); refresh() }
function pct(s) { return s.jobs_total ? Math.round(100 * s.jobs_done / s.jobs_total) : 0 }
function scanning(s) {
  const t = s.running_targets || []
  if (!t.length) return ''
  const extra = (s.running || 0) - t.length
  return t.join(', ') + (extra > 0 ? ` +${extra} more` : '')
}

let timer = null
onMounted(async () => { await refresh(); timer = setInterval(refresh, 3000) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center">
    <h1 style="margin:0">Scans <span class="muted" style="font-weight:400;font-size:16px">({{ total }})</span></h1>
    <router-link to="/scans/new" class="btn primary">+ New scan</router-link>
  </div>

  <div class="row" style="margin:14px 0 10px">
    <input v-model="q" placeholder="search scans…" style="max-width:280px" @keyup.enter="search" @input="search" />
  </div>

  <div class="grid">
    <router-link v-for="s in scans" :key="s.id" :to="'/scans/' + s.id" class="card scancard">
      <div class="row" style="justify-content:space-between">
        <b>{{ s.name }}</b><span class="state" :class="'st-' + s.status">{{ s.status }}</span>
      </div>
      <div class="muted" style="font-size:12px">run #{{ s.run_no }} · {{ s.assets }} assets<span v-if="durationLabel(s)"> · {{ durationLabel(s) }}</span></div>
      <div v-if="s.jobs_total" class="progress" :title="s.jobs_done + '/' + s.jobs_total + ' assets'">
        <div class="bar" :class="{ done: s.status !== 'running' }" :style="{ width: pct(s) + '%' }"></div>
      </div>
      <div v-if="s.jobs_total" class="muted" style="font-size:12px">{{ s.jobs_done }}/{{ s.jobs_total }} assets done<span v-if="s.running"> · {{ s.running }} in progress</span></div>
      <div v-if="scanning(s)" class="scanning" title="assets scanning now">▸ {{ scanning(s) }}</div>
      <div>
        <span v-if="s.findings_new" class="state-new">{{ s.findings_new }} new</span>
        <span v-if="s.findings_new"> · </span>{{ s.findings_open_state }} open ·
        <span class="muted">{{ s.findings_resolved }} resolved</span>
      </div>
    </router-link>
    <div v-if="loading" class="muted">Loading…</div>
    <div v-else-if="!scans.length" class="muted">No scans{{ q ? ' match your search' : ' yet' }} — <router-link to="/scans/new">start one</router-link>.</div>
  </div>

  <div v-if="total > LIMIT" class="row pager">
    <button class="ghost" :disabled="offset === 0" @click="page(-1)">← Prev</button>
    <span class="muted">{{ offset + 1 }}–{{ Math.min(offset + LIMIT, total) }} of {{ total }}</span>
    <button class="ghost" :disabled="offset + LIMIT >= total" @click="page(1)">Next →</button>
  </div>
</template>
