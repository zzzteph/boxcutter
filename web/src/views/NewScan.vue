<script setup>
// New scan in three plain steps on one page:
//   1. What to scan   - paste targets (or upload a file); the kind is detected as you type
//   2. What to do     - a workflow (its graph is shown) or a single template, as cards that fit those targets
//   3. When           - once now, or on a cron schedule (that creates a scheduler)
// A sticky summary bar says exactly what will happen and starts it.
// Query params pre-fill it: ?template=<id>&targets=a,b&repeat=1
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api'
import ScanTypePicker from '../components/ScanTypePicker.vue'
import WorkflowGraph from '../components/WorkflowGraph.vue'
import CronInput from '../components/CronInput.vue'
import { KIND_LABEL, KIND_ONE, detectTargets, targetLines } from '../util'
import { graphFromPlan } from '../workflow'

const route = useRoute()
const router = useRouter()

const templates = ref([])
const inputs = ref([])
const stats = ref(null)
const targetsText = ref('')
const file = ref(null)
const templateId = ref(null)
const when = ref('now')                 // now | schedule
const cron = ref('0 3 * * *')
const tz = ref('')
const cronOk = ref(false)
const cronDesc = ref('')
const firstNow = ref(true)
const name = ref('')
const showAdvanced = ref(false)
const params = ref([])
const err = ref('')
const busy = ref(false)
const preview = ref(null)               // the chosen workflow's expanded plan, drawn as a graph

const lines = computed(() => targetLines(targetsText.value))
const detected = computed(() => detectTargets(lines.value))
const kind = computed(() => (file.value && !lines.value.length) ? '' : detected.value.kind)
const chosen = computed(() => templates.value.find(t => t.id === templateId.value) || null)
const inputLabels = computed(() => Object.fromEntries(inputs.value.map(i => [i.value, i.label])))
const slots = computed(() => stats.value ? stats.value.slots_total : null)
const detectLabel = computed(() => {
  const d = detected.value
  if (!d.total) return ''
  return Object.entries(d.counts).filter(([, n]) => n).map(([k, n]) => `${n} ${(n === 1 ? KIND_ONE[k] : KIND_LABEL[k]) || k}`).join(' · ')
})
const unknownCount = computed(() => detected.value.counts.unknown || 0)
const ready = computed(() => !!chosen.value && (lines.value.length > 0 || !!file.value) && (when.value === 'now' || cronOk.value))
const summary = computed(() => {
  if (!chosen.value) return 'Pick what to run'
  const on = file.value ? `targets from ${file.value.name}` : `${lines.value.length} target${lines.value.length === 1 ? '' : 's'}`
  const what = chosen.value.title + (chosen.value.kind === 'pipeline' ? ` (workflow, ${chosen.value.steps} steps)` : '')
  const sched = (cronDesc.value || 'cron ' + cron.value).replace(/^At /, 'at ')
  return `${what} on ${on} · ` + (when.value === 'schedule' ? `${sched} (${tz.value})${firstNow.value ? ', first run now' : ''}` : 'now')
})

watch(templateId, async (id) => {
  preview.value = null
  const t = templates.value.find(x => x.id === id)
  if (!t || t.kind !== 'pipeline') return
  try { const full = await api.get('/templates/' + id); if (templateId.value === id) preview.value = graphFromPlan(full.plan) }
  catch (e) { /* preview is optional */ }
})

function onFile(ev) { file.value = (ev.target.files && ev.target.files[0]) || null }
function addParam() { params.value.push({ flag: '', value: '' }) }

async function start() {
  if (!ready.value || busy.value) return
  err.value = ''
  busy.value = true
  const vars = { custom: params.value.filter(p => p.flag.trim()) }
  const sched = when.value === 'schedule'
  try {
    let r
    if (file.value) {
      const fd = new FormData()
      fd.append('template_id', chosen.value.id)
      fd.append('name', name.value)
      fd.append('vars', JSON.stringify(vars))
      if (sched) { fd.append('cron', cron.value); fd.append('timezone', tz.value); fd.append('start_now', firstNow.value) }
      fd.append('file', file.value)
      r = await api.postForm('/scans/upload', fd)
    } else {
      r = await api.post('/scans', { template_id: chosen.value.id, name: name.value, targets: lines.value, vars,
        cron: sched ? cron.value : null, timezone: tz.value || 'UTC', start_now: firstNow.value })
    }
    router.push(r.id ? '/scans/' + r.id : '/schedulers')
  } catch (e) { err.value = e.message } finally { busy.value = false }
}

onMounted(async () => {
  const [t, inp, s] = await Promise.all([api.get('/templates'), api.get('/templates/inputs'), api.get('/stats').catch(() => null)])
  templates.value = t; inputs.value = inp; stats.value = s
  const q = route.query
  if (q.targets) targetsText.value = String(q.targets).split(',').join('\n')
  if (q.repeat) when.value = 'schedule'
  if (q.template && t.some(x => String(x.id) === String(q.template))) templateId.value = Number(q.template)
})
</script>

<template>
  <h1>New scan</h1>
  <p class="muted" style="margin-top:0">Three steps: what to scan, what to do, and when.</p>

  <section class="step card">
    <div class="step-h"><span class="num">1</span><h2>What do you want to scan?</h2></div>
    <textarea v-model="targetsText" rows="5" :disabled="!!file"
              placeholder="One target per line, for example:&#10;example.com&#10;https://app.example.com/login&#10;10.0.0.0/24"></textarea>
    <div class="row" style="justify-content:space-between;margin-top:8px">
      <div class="row" style="gap:6px">
        <span v-if="detectLabel" class="chip detect">Detected: {{ detectLabel }}</span>
        <span v-if="unknownCount" class="chip warnchip">{{ unknownCount }} line(s) don't look like a domain, URL or IP</span>
        <span v-if="file" class="chip">📄 {{ file.name }} ({{ Math.ceil(file.size / 1024) }} KB) <a href="#" @click.prevent="file = null">✕</a></span>
      </div>
      <label class="btn ghost sm" style="margin:0">⬆ Upload a list
        <input type="file" accept=".txt,.csv,text/plain" style="display:none" @change="onFile" />
      </label>
    </div>
  </section>

  <section class="step card">
    <div class="step-h"><span class="num">2</span><h2>What should it do?</h2></div>
    <div v-if="!templates.length" class="muted">Loading…</div>
    <ScanTypePicker v-else :templates="templates" :kind="kind" v-model="templateId" />
    <div v-if="chosen && chosen.kind === 'pipeline'" class="wfprev">
      <div class="row" style="justify-content:space-between">
        <b>How “{{ chosen.title }}” runs</b>
        <router-link :to="'/workflows/' + chosen.id" class="muted" style="font-size:12.5px">open in the workflow builder →</router-link>
      </div>
      <div class="muted" style="font-size:12.5px;margin:2px 0 8px">Every box runs once per item it receives, as separate jobs on all
        scanners; the wires show what each step hands to the next.</div>
      <WorkflowGraph v-if="preview" :model-value="preview" mode="view" :height="380" :input-labels="inputLabels" />
      <div v-else class="muted">loading the graph…</div>
    </div>
  </section>

  <section class="step card">
    <div class="step-h"><span class="num">3</span><h2>When?</h2></div>
    <div class="seg">
      <button type="button" :class="{ on: when === 'now' }" @click="when = 'now'">Run once, now</button>
      <button type="button" :class="{ on: when === 'schedule' }" @click="when = 'schedule'">On a schedule (cron)</button>
    </div>
    <template v-if="when === 'schedule'">
      <div style="margin-top:12px"><CronInput v-model:cron="cron" v-model:timezone="tz" @valid="(v, d) => { cronOk = v; cronDesc = d }" /></div>
      <label class="chk"><input type="checkbox" v-model="firstNow" /> also run it right now</label>
      <div class="muted" style="font-size:12.5px;margin-top:6px">
        Creates a <router-link to="/schedulers">scheduler</router-link>. Each run is compared with the previous one, so you see
        what is new, still open and fixed. If a run is still going at the next tick, that tick is skipped.
      </div>
    </template>

    <div class="formgrid" style="margin-top:6px">
      <div>
        <label>Name <span class="muted">(optional)</span></label>
        <input v-model="name" :placeholder="chosen ? chosen.title + (lines[0] ? ' — ' + lines[0] : '') : 'e.g. Weekly perimeter'" />
      </div>
    </div>

    <button type="button" class="ghost sm" style="margin-top:10px" @click="showAdvanced = !showAdvanced">
      {{ showAdvanced ? '▾' : '▸' }} Advanced: extra engine parameters</button>
    <div v-if="showAdvanced" style="margin-top:6px">
      <div class="muted" style="font-size:12.5px">Added to every job of this scan, e.g. <code>--header</code> =
        <code>Cookie: session=…</code> for an authenticated scan. A tool that doesn't know a flag will fail that job.</div>
      <div v-for="(p, i) in params" :key="i" class="kvrow" style="margin-top:6px">
        <input v-model="p.flag" placeholder="--flag" />
        <input v-model="p.value" placeholder="value (empty = on/off flag)" />
        <button type="button" class="ghost danger sm" @click="params.splice(i, 1)">✕</button>
      </div>
      <button type="button" class="ghost sm" @click="addParam">+ Add parameter</button>
    </div>
  </section>

  <div class="sumbar">
    <div class="sumtext">
      <b>{{ summary }}</b>
      <div v-if="slots === 0" class="warn">No scanner is online — the scan will wait until one connects
        (<router-link to="/scanners">Scanners</router-link>).</div>
      <div v-if="err" class="err">{{ err }}</div>
    </div>
    <button class="primary" :disabled="!ready || busy" @click="start">
      {{ busy ? 'Starting…' : (when === 'schedule' ? 'Create scheduler' : 'Start scan') }}</button>
  </div>
</template>

<style scoped>
.step { margin-top: 14px; }
.step-h { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.step-h h2 { margin: 0; }
.num { width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center; font-weight: 700; font-size: 13px;
  background: var(--accent); color: var(--on-primary); flex: none; }
.detect { color: var(--accent-ink); background: var(--wash); }
.warnchip { color: var(--warn); }
.wfprev { margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--outline-variant); }
.seg { display: inline-flex; border: 1px solid var(--outline-variant); border-radius: var(--radius-xl); overflow: hidden; }
.seg button { border: 0; border-radius: 0; height: 38px; text-transform: none; letter-spacing: 0; font-weight: 500;
  color: var(--on-surface-variant); background: transparent; }
.seg button + button { border-left: 1px solid var(--outline-variant); }
.seg button.on { background: var(--primary-container); color: var(--accent-ink); }
.seg button:hover { box-shadow: none; color: var(--on-surface); background: var(--sc); }
.chk { display: inline-flex; gap: 8px; align-items: center; cursor: pointer; margin-top: 12px; }
.chk input { width: auto; }
.sumbar { position: sticky; bottom: 0; margin: 18px -28px -24px; padding: 14px 28px; display: flex; gap: 16px;
  align-items: center; justify-content: space-between; background: color-mix(in srgb, var(--sc) 94%, transparent);
  border-top: 1px solid var(--outline-variant); backdrop-filter: blur(8px); z-index: 5; }
.sumtext { min-width: 0; }
.sumtext b { font-weight: 600; }
.warn { color: var(--warn); font-size: 12.5px; margin-top: 2px; }
.sumbar .err { margin: 2px 0 0; font-size: 13px; }
@media (max-width: 640px) { .sumbar { margin: 18px -16px -16px; padding: 12px 16px; flex-direction: column; align-items: stretch; } }
</style>
