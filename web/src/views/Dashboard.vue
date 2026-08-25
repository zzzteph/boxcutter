<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { api } from '../api'
import { timeAgo } from '../util'

const s = ref(null)
let timer = null
const SEVS = ['Critical', 'High', 'Medium', 'Low', 'Info']
const SEV_VAR = { Critical: 'var(--crit)', High: 'var(--high)', Medium: 'var(--med)', Low: 'var(--low)', Info: 'var(--info)' }

async function load() { try { s.value = await api.get('/stats') } catch (e) { /* transient */ } }
const trendMax = computed(() => Math.max(1, ...((s.value?.trend || []).map(t => t.count))))
function pct(a) { return a.jobs_total ? Math.round(100 * a.jobs_done / a.jobs_total) : 0 }
onMounted(async () => { await load(); timer = setInterval(load, 5000) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <h1>Overview</h1>
  <div v-if="s">
    <div class="tiles">
      <router-link to="/scans" class="card tile">
        <div class="tnum">{{ s.active_scans_count }}</div><div class="muted">active scans</div>
        <div class="muted" style="font-size:12px">{{ s.scans_total }} total</div>
      </router-link>
      <router-link to="/findings" class="card tile">
        <div class="tnum">{{ s.findings_open }}</div><div class="muted">open findings</div>
        <div class="muted" style="font-size:12px"><span class="state-new">{{ s.findings_new }} new</span> · {{ s.findings_resolved }} resolved</div>
      </router-link>
      <router-link to="/findings?severity=Critical" class="card tile">
        <div class="tnum" :style="{ color: (s.findings_by_severity.Critical || 0) ? 'var(--crit)' : '' }">{{ s.findings_by_severity.Critical || 0 }}</div>
        <div class="muted">open criticals</div>
      </router-link>
      <router-link to="/scanners" class="card tile">
        <div class="tnum">{{ s.scanners_connected }}<span class="muted" style="font-size:18px">/{{ s.scanners_total }}</span></div>
        <div class="muted">scanners online</div>
      </router-link>
    </div>

    <div class="card" style="margin-top:16px">
      <h2>Open findings by severity</h2>
      <div class="sevbars">
        <div v-for="sv in SEVS" :key="sv" class="sevbar">
          <span class="badge" :class="'sev-' + sv">{{ sv }}</span>
          <div class="meter" style="flex:1"><div :style="{ width: Math.min(100, (s.findings_by_severity[sv] || 0) / Math.max(1, s.findings_open) * 100) + '%', background: SEV_VAR[sv] }"></div></div>
          <b style="min-width:34px;text-align:right">{{ s.findings_by_severity[sv] || 0 }}</b>
        </div>
      </div>
    </div>

    <div class="grid" style="margin-top:16px;grid-template-columns:repeat(auto-fill,minmax(340px,1fr))">
      <div class="card">
        <h2>Active scans</h2>
        <router-link v-for="a in s.active_scans" :key="a.id" :to="'/scans/' + a.id" class="actrow">
          <div class="row" style="justify-content:space-between"><b>{{ a.name }}</b><span class="state" :class="'st-' + a.status">{{ a.status }}</span></div>
          <div class="progress"><div class="bar" :style="{ width: pct(a) + '%' }"></div></div>
          <div class="muted" style="font-size:12px">{{ a.jobs_done }}/{{ a.jobs_total }} assets</div>
        </router-link>
        <div v-if="!s.active_scans.length" class="muted">No active scans.</div>
      </div>

      <div class="card">
        <h2>Recent criticals</h2>
        <router-link v-for="c in s.recent_criticals" :key="c.id" :to="'/scans/' + c.scan_id" class="actrow">
          <div><span class="badge sev-Critical">Critical</span> {{ c.title }}</div>
          <div class="muted" style="font-size:12px">{{ c.target }} · {{ c.scan }}</div>
        </router-link>
        <div v-if="!s.recent_criticals.length" class="muted">No open critical findings 🎉</div>
      </div>

      <div class="card">
        <h2>New findings (14 days)</h2>
        <div class="trend">
          <div v-for="t in s.trend" :key="t.date" class="tbar" :title="t.date + ': ' + t.count">
            <div :style="{ height: Math.round(t.count / trendMax * 100) + '%' }"></div>
          </div>
          <div v-if="!s.trend.length" class="muted">No findings yet.</div>
        </div>
      </div>

      <div class="card">
        <h2>Recent activity</h2>
        <router-link v-for="(a, i) in s.recent_activity" :key="i" :to="a.scan_id ? '/scans/' + a.scan_id : '/activity'" class="actrow">
          <div><span class="dot" :class="a.severity === 'critical' ? 'bad' : (a.severity === 'warn' ? 'busy' : 'ok')"></span> {{ a.message }}</div>
          <div class="muted" style="font-size:12px">{{ timeAgo(a.at) }}</div>
        </router-link>
        <div class="muted" style="margin-top:8px"><router-link to="/activity">See all activity →</router-link></div>
      </div>
    </div>
  </div>
  <div v-else class="muted">Loading…</div>
</template>
