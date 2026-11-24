<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { api } from '../api'
import { durationLabel, timeAgo } from '../util'

const LIMIT = 24
const scans = ref([])
const total = ref(0)
const offset = ref(0)
const q = ref('')
const status = ref('')
const loading = ref(true)
const SEVS = ['Critical', 'High', 'Medium', 'Low']
const FILTERS = [['', 'All'], ['running', 'Running'], ['done', 'Done'], ['paused', 'Paused'], ['stopped', 'Stopped']]

async function refresh() {
  let u = `/scans?limit=${LIMIT}&offset=${offset.value}`
  if (q.value) u += `&q=${encodeURIComponent(q.value)}`
  if (status.value) u += `&status=${status.value}`
  try { const r = await api.get(u); scans.value = r.items; total.value = r.total } catch (e) { /* transient */ }
  finally { loading.value = false }
}
function search() { offset.value = 0; refresh() }
function setStatus(s) { status.value = s; search() }
function page(d) { offset.value = Math.max(0, offset.value + d * LIMIT); refresh() }
function pct(s) { return s.jobs_total ? Math.round(100 * s.jobs_done / s.jobs_total) : 0 }

let timer = null
onMounted(async () => { await refresh(); timer = setInterval(refresh, 4000) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center">
    <h1 style="margin:0">Scans <span class="muted" style="font-weight:400;font-size:16px">({{ total }})</span></h1>
    <router-link to="/scans/new" class="btn primary">+ New scan</router-link>
  </div>

  <div class="row" style="margin:14px 0 12px;gap:10px">
    <input v-model="q" placeholder="search by name or scan type…" style="max-width:300px" @input="search" />
    <div class="fbar">
      <button v-for="[k, l] in FILTERS" :key="k" type="button" :class="{ on: status === k }" @click="setStatus(k)">{{ l }}</button>
    </div>
  </div>

  <div class="grid">
    <router-link v-for="s in scans" :key="s.id" :to="'/scans/' + s.id" class="card scancard">
      <div class="row" style="justify-content:space-between;flex-wrap:nowrap;gap:8px">
        <b class="nm">{{ s.name }}</b><span class="state" :class="'st-' + s.status">{{ s.status }}</span>
      </div>
      <div class="muted" style="font-size:12px">
        {{ s.template }}<span v-if="s.distributed"> · workflow, {{ s.steps }} steps</span><span v-if="s.scheduler_id"> · ⟳ scheduled</span>
      </div>
      <div class="muted" style="font-size:12px">run #{{ s.run_no }} · {{ s.assets }} target(s) ·
        {{ durationLabel(s) || timeAgo(s.created_at) }}</div>
      <div class="row" style="gap:6px;min-height:22px">
        <span v-for="sv in SEVS" :key="sv" v-show="s.findings_by_severity[sv]" class="badge" :class="'sev-' + sv">
          {{ s.findings_by_severity[sv] }} {{ sv }}</span>
        <span v-if="!s.findings_open" class="muted" style="font-size:12.5px">no open findings</span>
        <span v-if="s.findings_new" class="state-new" style="font-size:12.5px">{{ s.findings_new }} new</span>
      </div>
      <div v-if="s.jobs_total && ['running', 'paused'].includes(s.status)" class="edgebar" :title="pct(s) + '% done'">
        <div :style="{ width: pct(s) + '%' }"></div>
      </div>
    </router-link>
  </div>
  <div v-if="loading" class="muted">Loading…</div>
  <div v-else-if="!scans.length" class="card empty">
    <template v-if="q || status">No scans match.</template>
    <template v-else>
      <b>No scans yet.</b>
      <div class="muted">Paste a domain, URL or IP range and pick what to check — that's it.</div>
      <router-link to="/scans/new" class="btn primary" style="margin-top:10px">Start your first scan</router-link>
    </template>
  </div>

  <div v-if="total > LIMIT" class="row pager">
    <button class="ghost" :disabled="offset === 0" @click="page(-1)">← Prev</button>
    <span class="muted">{{ offset + 1 }}–{{ Math.min(offset + LIMIT, total) }} of {{ total }}</span>
    <button class="ghost" :disabled="offset + LIMIT >= total" @click="page(1)">Next →</button>
  </div>
</template>

<style scoped>
.nm { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.empty { text-align: center; padding: 34px; }
.fbar { display: inline-flex; border: 1px solid var(--outline-variant); border-radius: var(--radius-xl); overflow: hidden; }
.fbar button { border: 0; border-radius: 0; height: 36px; text-transform: none; letter-spacing: 0; font-weight: 500;
  color: var(--on-surface-variant); background: transparent; padding: 0 14px; }
.fbar button + button { border-left: 1px solid var(--outline-variant); }
.fbar button.on { background: var(--primary-container); color: var(--accent-ink); }
.fbar button:hover { box-shadow: none; color: var(--on-surface); background: var(--sc); }
.badge { height: 20px; font-size: 11px; }
.scancard { position: relative; overflow: hidden; padding-bottom: 22px; }
.edgebar { position: absolute; left: 0; right: 0; bottom: 0; height: 4px; background: var(--sc-high); }
.edgebar > div { height: 100%; background: var(--accent); transition: width .4s; }
</style>
