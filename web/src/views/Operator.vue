<script setup>
import { ref, reactive, computed, nextTick, onMounted, onUnmounted } from 'vue'
import { api } from '../api'
import Select from '../components/Select.vue'
import { timeAgo } from '../util'

// A DIRECT operator run: joseph runs on the server itself (not fanned across the fleet). Pick an LLM profile,
// give a target + brief, watch the reasoning stream live, then read the report. See server/app/operator.py.
const runs = ref([])
const profiles = ref([])
const cc = ref(null)                 // claude-code login status for this server
const err = ref('')
const busy = ref(false)

const form = reactive({
  target: '', context: '', creds: '', profile_id: null,
  dry_run: false, analysts: 0, max_steps: 40, authorized: false,
})

const profileOpts = computed(() => profiles.value.map(p => ({ value: p.id, label: `${p.name} (${p.provider})` })))
const selProfile = computed(() => profiles.value.find(p => p.id === form.profile_id) || null)
const isClaudeCode = computed(() => (selProfile.value?.provider || '').toLowerCase() === 'claude-code')
// warn only when a claude-code profile is picked but this server has no Claude Code login to ride
const ccWarn = computed(() => isClaudeCode.value && cc.value && !cc.value.logged_in)
const noKey = computed(() => selProfile.value &&
  !['claude-code', 'ollama'].includes((selProfile.value.provider || '').toLowerCase()) && !selProfile.value.has_key)
const canRun = computed(() => !busy.value && form.authorized && form.profile_id &&
  (form.target.trim() || form.context.trim()) && !noKey.value)

// -- the selected run + its live output ----------------------------------------------------------------------
const selId = ref(null)
const detail = ref(null)
const logText = ref('')
let logOffset = 0
let settledId = null            // a finished run whose detail we've already loaded — stop re-polling it
const logEl = ref(null)
let timer = null

async function loadRuns() { try { runs.value = await api.get('/operator/runs') } catch (e) { /* transient */ } }

async function open(id) {
  selId.value = id; detail.value = null; logText.value = ''; logOffset = 0; settledId = null
  await tick(true)
}

// one polling cycle: pull new log bytes, and (when the status changes) the run detail with its report/findings.
async function tick(force) {
  if (!selId.value) return
  if (!force && settledId === selId.value) return          // finished + loaded: nothing more to fetch
  try {
    const r = await api.get(`/operator/runs/${selId.value}/log?since=${logOffset}`)
    if (r.text) { logText.value += r.text; logOffset = r.offset; scrollLog() }
    const wasRunning = detail.value?.status === 'running'
    if (force || !detail.value || r.status !== detail.value?.status || (wasRunning && r.done)) {
      detail.value = await api.get(`/operator/runs/${selId.value}`)
      if (detail.value.status !== 'running') { settledId = selId.value; await loadRuns() }
    }
  } catch (e) { /* transient */ }
}

function scrollLog() {
  nextTick(() => { const el = logEl.value; if (el) el.scrollTop = el.scrollHeight })
}

async function run() {
  err.value = ''; busy.value = true
  try {
    const body = {
      agent: 'joseph', target: form.target.trim(), context: form.context.trim(), creds: form.creds.trim(),
      profile_id: form.profile_id, dry_run: form.dry_run,
      analysts: Number(form.analysts) || 0, max_steps: Number(form.max_steps) || 40,
      authorized: form.authorized,
    }
    const r = await api.post('/operator/runs', body)
    await loadRuns()
    await open(r.id)
  } catch (e) { err.value = e.message } finally { busy.value = false }
}

async function stop(id) {
  try { await api.post(`/operator/runs/${id}/stop`); await tick(true) } catch (e) { alert(e.message) }
}
async function del(id) {
  if (!confirm('Delete this run and its workspace?')) return
  try {
    await api.del(`/operator/runs/${id}`)
    if (selId.value === id) { selId.value = null; detail.value = null }
    await loadRuns()
  } catch (e) { alert(e.message) }
}

const findings = computed(() => detail.value?.findings || [])
const meta = computed(() => detail.value?.meta || {})
function sevClass(s) { return 'sev-' + String(s || 'info').toLowerCase() }

async function load() {
  await loadRuns()
  profiles.value = await api.get('/llm-profiles')
  try { cc.value = await api.get('/operator/claude-code') } catch { cc.value = null }
  // default to a Claude Code profile if one exists (no key needed), else the first profile with a key
  const ccp = profiles.value.find(p => (p.provider || '').toLowerCase() === 'claude-code')
  form.profile_id = ccp?.id ?? profiles.value.find(p => p.has_key)?.id ?? profiles.value[0]?.id ?? null
}
onMounted(() => { load(); timer = setInterval(tick, 1500) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center">
    <h1>Operator</h1>
    <span class="muted" style="font-size:12.5px">joseph runs here on the server — not on the scanner fleet</span>
  </div>

  <div class="split">
    <!-- the run form -->
    <div class="card">
      <h2>New run</h2>
      <p class="muted" style="margin-top:0">A live browser + the full tool set + in-container scripting, driven
        by one LLM brain that thinks out loud and acts. You watch it work and get a written report.</p>

      <label>Target <span class="muted">— app root URL (or leave blank and name it in the brief)</span></label>
      <input v-model="form.target" placeholder="https://app.example.com" />

      <label style="margin-top:12px">Brief <span class="muted">— the goal, the endpoints in play, and how to
        authenticate. joseph reads this, not just the URL.</span></label>
      <textarea v-model="form.context" rows="4"
        placeholder="Goal: find broken access control on the orders API.&#10;In-scope: app.example.com, api.example.com.&#10;Login at /login; a test account is user:pass below."></textarea>

      <label style="margin-top:12px">Credentials <span class="muted">— optional; for an authenticated live-browser login</span></label>
      <input v-model="form.creds" placeholder="user:pass" />

      <label style="margin-top:12px">LLM profile</label>
      <Select v-model="form.profile_id" :options="profileOpts" placeholder="Pick a profile" />
      <p v-if="noKey" class="err" style="font-size:12.5px">This profile has no API key — set one on LLM Profiles,
        or pick a Claude Code / Ollama profile.</p>
      <div v-if="isClaudeCode && cc" class="cc" :class="{ warn: ccWarn }">
        <template v-if="cc.logged_in">✓ Claude Code login found on this server — no API key needed.</template>
        <template v-else>
          <b>No Claude Code login on this server.</b> {{ cc.hint }}
        </template>
      </div>

      <div class="opts">
        <label class="opt"><input type="checkbox" v-model="form.dry_run" /> Dry run
          <span class="muted">— map &amp; predict only, no POST/PUT/DELETE</span></label>
        <div class="opt num">
          <label>Analyst lanes <span class="muted">— parallel read-only reviewers (0–9; more coverage, more cost)</span></label>
          <input type="number" min="0" max="9" v-model.number="form.analysts" />
        </div>
        <div class="opt num">
          <label>Max steps <span class="muted">— hard cap; it usually stops earlier</span></label>
          <input type="number" min="1" max="200" v-model.number="form.max_steps" />
        </div>
      </div>

      <label class="ack"><input type="checkbox" v-model="form.authorized" />
        I am authorized to test this target.</label>

      <p v-if="err" class="err">{{ err }}</p>
      <button class="primary" style="margin-top:6px" :disabled="!canRun" @click="run">
        {{ busy ? 'Starting…' : 'Run joseph' }}</button>
    </div>

    <!-- recent runs -->
    <div class="card">
      <h2>Runs</h2>
      <p v-if="!runs.length" class="muted">No runs yet. Start one on the left.</p>
      <table v-else class="reflow rows">
        <tbody>
          <tr v-for="r in runs" :key="r.id" :class="{ openrow: r.id === selId }" style="cursor:pointer"
              @click="open(r.id)">
            <td><span class="state" :class="'st-' + r.status">{{ r.status }}</span></td>
            <td style="word-break:break-all">{{ r.target || '(brief)' }}
              <div class="muted" style="font-size:12px">{{ r.provider }}<span v-if="r.model"> · {{ r.model }}</span></div>
            </td>
            <td style="white-space:nowrap" class="muted">{{ timeAgo(r.created_at) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- the selected run: live output + report -->
  <div v-if="selId" class="card">
    <div class="row" style="justify-content:space-between;align-items:center">
      <h2 style="margin:0">Run #{{ selId }}
        <span v-if="detail" class="state" :class="'st-' + detail.status">{{ detail.status }}</span></h2>
      <div class="row" style="gap:8px">
        <button v-if="detail?.status === 'running'" class="danger ghost sm" @click="stop(selId)">Stop</button>
        <button v-if="detail && detail.status !== 'running'" class="danger ghost sm" @click="del(selId)">Delete</button>
      </div>
    </div>

    <div v-if="detail && (detail.meta?.tokens || detail.meta?.cost_usd != null)" class="muted" style="font-size:12px;margin:4px 0 0">
      {{ (detail.meta.tokens?.total_tokens || 0).toLocaleString() }} tokens
      <span v-if="detail.meta.cost_usd != null"> · ~${{ Number(detail.meta.cost_usd).toFixed(4) }}</span>
      <span v-if="detail.meta.steps"> · {{ detail.meta.steps }} steps</span>
      <span v-if="detail.meta.scripts"> · {{ detail.meta.scripts }} script(s)</span>
      <span v-if="detail.meta.mutations"> · {{ detail.meta.mutations }} mutation(s)</span>
    </div>

    <label style="margin-top:10px">Live output <span class="muted">— the reasoning stream (observe → interpret →
      trace → hypothesize → plan → act)</span></label>
    <pre ref="logEl" class="log">{{ logText || (detail?.status === 'running' ? 'starting…' : '(no output)') }}</pre>

    <p v-if="detail?.error" class="err" style="white-space:pre-wrap">{{ detail.error }}</p>

    <template v-if="findings.length">
      <h3>Findings ({{ findings.length }})</h3>
      <div v-for="(f, i) in findings" :key="i" class="finding">
        <div><span class="sev" :class="sevClass(f.severity)">{{ f.severity }}</span> <b>{{ f.title }}</b></div>
        <div v-if="f.url" class="muted" style="font-size:12.5px;word-break:break-all">{{ f.url }}</div>
        <div v-if="f.summary" style="font-size:13px;margin-top:4px">{{ f.summary }}</div>
        <div v-if="f.impact" style="font-size:12.5px;margin-top:4px"><b>Impact:</b> {{ f.impact }}</div>
        <pre v-if="f.poc" class="cmd" style="margin-top:6px">{{ f.poc }}</pre>
      </div>
    </template>

    <template v-if="detail?.report">
      <h3>Report</h3>
      <pre class="report">{{ detail.report }}</pre>
    </template>
  </div>
</template>

<style scoped>
.cc { margin: 8px 0 0; padding: 8px 10px; border-radius: 8px; font-size: 12.5px;
  background: rgba(46, 160, 67, .12); border: 1px solid rgba(46, 160, 67, .35); }
.cc.warn { background: rgba(253, 176, 34, .14); border-color: rgba(253, 176, 34, .4); }
.opts { display: flex; flex-direction: column; gap: 10px; margin: 14px 0; }
.opt.num { display: flex; flex-direction: column; gap: 4px; }
.opt.num input { width: 120px; }
.opt input[type=checkbox] { width: auto; margin-right: 6px; }
.ack { display: flex; align-items: center; gap: 8px; font-weight: 600; margin: 6px 0 12px; }
.ack input { width: auto; }
tr.openrow { background: var(--panel-2, rgba(0, 0, 0, .04)); }
.log { max-height: 460px; overflow: auto; white-space: pre-wrap; word-break: break-word;
  font-size: 12px; line-height: 1.45; background: #0b0e14; color: #d7dde8; padding: 12px; border-radius: 8px; }
.report { white-space: pre-wrap; word-break: break-word; font-size: 12.5px; line-height: 1.5;
  max-height: 560px; overflow: auto; }
.finding { border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; margin: 8px 0; }
.sev { font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 1px 6px; border-radius: 4px;
  color: #fff; background: #6b7280; }
.sev.sev-critical, .sev.sev-high { background: #d64550; }
.sev.sev-medium { background: #e08c00; }
.sev.sev-low { background: #3b7dd8; }
</style>
