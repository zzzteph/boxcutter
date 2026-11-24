<script setup>
// New scan in three plain steps on one page:
//   1. What to scan   - paste targets (or upload a file); the kind is detected as you type
//   2. What to do     - scan-type cards that fit those targets (see ScanTypePicker)
//   3. When           - once now, or repeat on a schedule (that creates a scheduler)
// A sticky summary bar says exactly what will happen and starts it.
// Query params pre-fill it: ?template=<id>&targets=a,b&repeat=1&distributed=1
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api'
import ScanTypePicker from '../components/ScanTypePicker.vue'
import Select from '../components/Select.vue'
import { INTERVALS, KIND_LABEL, KIND_ONE, detectTargets, intervalLabel, resolveTemplate, targetLines } from '../util'

const route = useRoute()
const router = useRouter()

const templates = ref([])
const stats = ref(null)
const targetsText = ref('')
const file = ref(null)
const templateId = ref(null)
const distributed = ref(false)
const when = ref('now')                 // now | repeat
const interval = ref(86400)
const customHours = ref(24)
const firstNow = ref(true)
const name = ref('')
const showAdvanced = ref(false)
const params = ref([])                  // [{flag, value}] extra engine flags for every job
const err = ref('')
const busy = ref(false)

const lines = computed(() => targetLines(targetsText.value))
const detected = computed(() => detectTargets(lines.value))
const kind = computed(() => (file.value && !lines.value.length) ? '' : detected.value.kind)
const chosen = computed(() => resolveTemplate(templates.value, templateId.value, distributed.value))
const base = computed(() => templates.value.find(t => t.id === templateId.value) || null)
const nTargets = computed(() => file.value ? null : lines.value.length)
const intervalOpts = [...INTERVALS, { value: -1, label: 'Custom…' }]
const intervalSeconds = computed(() => interval.value === -1 ? Math.max(1, Number(customHours.value) || 1) * 3600 : interval.value)
const slots = computed(() => stats.value ? stats.value.slots_total : null)

const detectLabel = computed(() => {
  const d = detected.value
  if (!d.total) return ''
  const parts = Object.entries(d.counts).filter(([, n]) => n).map(([k, n]) => `${n} ${(n === 1 ? KIND_ONE[k] : KIND_LABEL[k]) || k}`)
  return parts.join(' · ')
})
const unknownCount = computed(() => detected.value.counts.unknown || 0)
const ready = computed(() => !!chosen.value && (lines.value.length > 0 || !!file.value))
const summary = computed(() => {
  if (!chosen.value) return 'Pick what to run'
  const what = (base.value ? base.value.title : chosen.value.title) + (chosen.value.kind === 'pipeline' && chosen.value.builtin ? ' (distributed)' : '')
  const on = file.value ? `targets from ${file.value.name}` : `${lines.value.length} target${lines.value.length === 1 ? '' : 's'}`
  const t = when.value === 'repeat' ? intervalLabel(intervalSeconds.value).toLowerCase() + (firstNow.value ? ', starting now' : '') : 'now'
  return `${what} on ${on} · ${t}`
})

function onFile(ev) { file.value = (ev.target.files && ev.target.files[0]) || null }
function clearFile() { file.value = null }
function addParam() { params.value.push({ flag: '', value: '' }) }

async function start() {
  if (!ready.value || busy.value) return
  err.value = ''
  busy.value = true
  const vars = { custom: params.value.filter(p => p.flag.trim()) }
  const repeat = when.value === 'repeat' ? intervalSeconds.value : null
  try {
    let r
    if (file.value) {
      const fd = new FormData()
      fd.append('template_id', chosen.value.id)
      fd.append('name', name.value)
      fd.append('vars', JSON.stringify(vars))
      if (repeat) { fd.append('repeat_seconds', repeat); fd.append('start_now', firstNow.value) }
      fd.append('file', file.value)
      r = await api.postForm('/scans/upload', fd)
    } else {
      r = await api.post('/scans', { template_id: chosen.value.id, name: name.value, targets: lines.value, vars,
        repeat_seconds: repeat, start_now: firstNow.value })
    }
    if (r.id) router.push('/scans/' + r.id)
    else router.push('/schedulers')
  } catch (e) { err.value = e.message } finally { busy.value = false }
}

onMounted(async () => {
  const [t, s] = await Promise.all([api.get('/templates'), api.get('/stats').catch(() => null)])
  templates.value = t
  stats.value = s
  const q = route.query
  if (q.targets) targetsText.value = String(q.targets).split(',').join('\n')
  if (q.repeat) when.value = 'repeat'
  if (q.template) {
    const pre = t.find(x => String(x.id) === String(q.template))
    if (pre && pre.kind === 'pipeline' && pre.builtin && pre.variant_of) {
      const b = t.find(x => x.name === pre.variant_of)
      if (b) { templateId.value = b.id; distributed.value = true }
    } else if (pre) templateId.value = pre.id
  }
  if (q.distributed) distributed.value = true
  else if (!q.template && s && s.slots_total >= 2) distributed.value = true   // several scanners -> spread work
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
        <span v-if="file" class="chip">📄 {{ file.name }} ({{ Math.ceil(file.size / 1024) }} KB) <a href="#" @click.prevent="clearFile">✕</a></span>
      </div>
      <label class="btn ghost sm" style="margin:0">⬆ Upload a list
        <input type="file" accept=".txt,.csv,text/plain" style="display:none" @change="onFile" />
      </label>
    </div>
  </section>

  <section class="step card">
    <div class="step-h"><span class="num">2</span><h2>What should it do?</h2></div>
    <div v-if="!templates.length" class="muted">Loading…</div>
    <ScanTypePicker v-else :templates="templates" :kind="kind" v-model="templateId" v-model:distributed="distributed" />
    <div v-if="chosen && chosen.kind === 'pipeline'" class="muted planline">
      ⇉ {{ chosen.steps }} steps · every result is fanned out to the next step as separate jobs ·
      <router-link :to="'/pipelines/' + chosen.id">see the steps</router-link>
    </div>
  </section>

  <section class="step card">
    <div class="step-h"><span class="num">3</span><h2>When?</h2></div>
    <div class="seg">
      <button type="button" :class="{ on: when === 'now' }" @click="when = 'now'">Run once, now</button>
      <button type="button" :class="{ on: when === 'repeat' }" @click="when = 'repeat'">Repeat on a schedule</button>
    </div>
    <div v-if="when === 'repeat'" class="formgrid" style="margin-top:8px">
      <div>
        <label>How often</label>
        <Select v-model="interval" :options="intervalOpts" />
      </div>
      <div v-if="interval === -1">
        <label>Every N hours</label>
        <input v-model.number="customHours" type="number" min="1" max="2160" />
      </div>
      <div>
        <label>First run</label>
        <div class="seg sm">
          <button type="button" :class="{ on: firstNow }" @click="firstNow = true">Now</button>
          <button type="button" :class="{ on: !firstNow }" @click="firstNow = false">After the first interval</button>
        </div>
      </div>
    </div>
    <div v-if="when === 'repeat'" class="muted" style="font-size:12.5px;margin-top:8px">
      Creates a <router-link to="/schedulers">scheduler</router-link>. Each run is compared with the previous one, so you
      see what is new, still open and fixed. A run never starts while the previous one is still going.
    </div>

    <div class="formgrid" style="margin-top:6px">
      <div>
        <label>Name <span class="muted">(optional)</span></label>
        <input v-model="name" :placeholder="base ? base.title + (lines[0] ? ' — ' + lines[0] : '') : 'e.g. Weekly perimeter'" />
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
      {{ busy ? 'Starting…' : (when === 'repeat' ? 'Create scheduler' : 'Start scan') }}</button>
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
.planline { font-size: 12.5px; margin-top: 10px; }
.seg { display: inline-flex; border: 1px solid var(--outline-variant); border-radius: var(--radius-xl); overflow: hidden; }
.seg button { border: 0; border-radius: 0; height: 38px; text-transform: none; letter-spacing: 0; font-weight: 500;
  color: var(--on-surface-variant); background: transparent; }
.seg button + button { border-left: 1px solid var(--outline-variant); }
.seg button.on { background: var(--primary-container); color: var(--accent-ink); }
.seg button:hover { box-shadow: none; color: var(--on-surface); background: var(--sc); }
.seg.sm button { height: 40px; }
.sumbar { position: sticky; bottom: 0; margin: 18px -28px -24px; padding: 14px 28px; display: flex; gap: 16px;
  align-items: center; justify-content: space-between; background: color-mix(in srgb, var(--sc) 94%, transparent);
  border-top: 1px solid var(--outline-variant); backdrop-filter: blur(8px); z-index: 5; }
.sumtext { min-width: 0; }
.sumtext b { font-weight: 600; }
.warn { color: var(--warn); font-size: 12.5px; margin-top: 2px; }
.sumbar .err { margin: 2px 0 0; font-size: 13px; }
@media (max-width: 640px) { .sumbar { margin: 18px -16px -16px; padding: 12px 16px; flex-direction: column; align-items: stretch; } }
</style>
