<script setup>
// Build a pipeline step by step: step 1 runs on the scan's targets; every next step says WHICH earlier results
// it takes (scan targets / step N, several = their union), WHAT KIND of results (hostnames, URLs, URLs with
// parameters, JS files, POST requests) and what to run on each. Checked live against the server.
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api'
import Select from '../components/Select.vue'
import ScanTypePicker from '../components/ScanTypePicker.vue'
import { ACCEPTS_LABEL, PRODUCES_LABEL, resolveTemplate } from '../util'

const route = useRoute()
const router = useRouter()
const isNew = computed(() => !route.params.id)

const templates = ref([])
const inputs = ref([])
const tmpl = ref(null)                   // the pipeline being edited (null when new)
const title = ref('')
const description = ref('')
const steps = ref([])                    // [{templateId, distributed, from:[...], input, args, picking}]
const check = ref({ ok: false, error: '', plan: [] })
const err = ref('')
const saving = ref(false)
const readonly = computed(() => !!(tmpl.value && tmpl.value.builtin))

const DEFAULT_INPUT = { domain: 'hosts', host: 'all', network: 'hosts', url: 'urls', spec: 'urls', graphql: 'urls',
  endpoint: 'param-urls', js: 'js-urls', any: 'all' }
const byId = (id) => templates.value.find(t => t.id === id)
function runT(s) { return resolveTemplate(templates.value, s.templateId, s.distributed) }

function newStep(i) {
  return { templateId: null, distributed: false, from: i === 0 ? [-1] : [i - 1], input: '', args: '', picking: true, adv: false }
}
function addStep() { steps.value.forEach(s => { s.picking = false }); steps.value.push(newStep(steps.value.length)) }
function removeStep(i) {
  steps.value.splice(i, 1)
  for (const s of steps.value) {                              // re-point sources after the removed one
    s.from = s.from.filter(f => f !== i).map(f => (f > i ? f - 1 : f))
  }
  steps.value.forEach((s, j) => { if (!s.from.length) s.from = [j === 0 ? -1 : j - 1] })
}
function toggleSource(s, f) {
  const has = s.from.includes(f)
  if (has && s.from.length === 1) return
  s.from = has ? s.from.filter(x => x !== f) : [...s.from, f].sort((a, b) => a - b)
}
function sources(i) { return [-1, ...Array.from({ length: i }, (_, k) => k)] }
function srcLabel(f) {
  if (f < 0) return 'Scan targets'
  const t = runT(steps.value[f])
  return `Step ${f + 1}` + (t ? ' · ' + t.title : '')
}
function srcDisabled(f) {
  if (f < 0) return false
  const t = runT(steps.value[f])
  return !!(t && t.produces === 'findings')
}
// what kind of thing feeds step i (for filtering the picker): '' = anything (scan targets)
function feedKind(s) {
  if (s.from.includes(-1)) return ''
  const t = runT(steps.value[s.from[0]])
  return t ? t.produces : ''
}
function onPicked(s) {
  const t = byId(s.templateId)
  if (t) { s.input = DEFAULT_INPUT[t.accepts] || 'all'; s.picking = false }
}
const inputOpts = computed(() => inputs.value.map(x => ({ value: x.value, label: x.label })))
function inputHelp(v) { const x = inputs.value.find(i => i.value === v); return x ? x.help : '' }

function payload() {
  return { title: title.value || 'Untitled pipeline', description: description.value, kind: 'pipeline',
    stages: steps.value.map(s => ({ template_id: runT(s)?.id ?? null, from: s.from, input: s.input || null, args: s.args })) }
}
let tmr = null
watch([steps, title], () => {
  clearTimeout(tmr)
  tmr = setTimeout(async () => {
    if (!steps.value.length || steps.value.some(s => !s.templateId)) {
      check.value = { ok: false, error: steps.value.length ? 'pick what each step runs' : 'add a step', plan: [] }
      return
    }
    try { check.value = await api.post('/templates/preview', payload()) } catch (e) { check.value = { ok: false, error: e.message, plan: [] } }
  }, 300)
}, { deep: true })

async function save(thenScan = false) {
  err.value = ''
  if (!title.value.trim()) { err.value = 'Give the pipeline a name'; return }
  saving.value = true
  try {
    const t = isNew.value ? await api.post('/templates', payload()) : await api.put('/templates/' + tmpl.value.id, payload())
    router.push(thenScan ? '/scans/new?template=' + t.id : '/pipelines')
  } catch (e) { err.value = e.message } finally { saving.value = false }
}
async function duplicate() {
  const copy = await api.post('/templates', { title: tmpl.value.title + ' (copy)', description: tmpl.value.description,
    kind: 'pipeline', stages: tmpl.value.spec.stages })
  router.push('/pipelines/' + copy.id)
}

onMounted(async () => {
  const [t, inp] = await Promise.all([api.get('/templates'), api.get('/templates/inputs')])
  templates.value = t; inputs.value = inp
  if (!isNew.value) {
    tmpl.value = await api.get('/templates/' + route.params.id)
    title.value = tmpl.value.title; description.value = tmpl.value.description || ''
    steps.value = (tmpl.value.spec.stages || []).map(s => {
      const st = byId(s.template_id)
      const isDist = st && st.kind === 'pipeline' && st.builtin && st.variant_of
      const baseT = isDist ? templates.value.find(x => x.name === st.variant_of) : st
      return { templateId: baseT ? baseT.id : s.template_id, distributed: !!isDist, from: s.from || [-1],
        input: s.input || '', args: s.args || '', picking: false, adv: !!s.args }
    })
  } else {
    steps.value = [newStep(0)]
  }
})
</script>

<template>
  <div class="muted crumbs"><router-link to="/pipelines">Pipelines</router-link> ›</div>
  <div class="row" style="justify-content:space-between;align-items:flex-start">
    <h1 style="margin:0">{{ isNew ? 'New pipeline' : (readonly ? tmpl?.title : 'Edit pipeline') }}</h1>
    <div v-if="readonly" class="row" style="gap:8px">
      <router-link :to="'/scans/new?template=' + tmpl.id" class="btn primary">Scan with it</router-link>
      <button @click="duplicate">Duplicate &amp; edit</button>
    </div>
  </div>
  <p v-if="readonly" class="muted">{{ tmpl?.description }} Built-in pipelines are read-only — duplicate one to change it.</p>

  <div v-if="!readonly" class="card" style="margin-top:12px">
    <div class="formgrid">
      <div><label>Name</label><input v-model="title" placeholder="e.g. Subdomains → nuclei" /></div>
      <div><label>Description <span class="muted">(optional)</span></label><input v-model="description" /></div>
    </div>
  </div>

  <div v-for="(s, i) in steps" :key="i">
    <div v-if="i" class="arrow">↓</div>
    <div class="card stepc" :class="{ ro: readonly }">
      <div class="row" style="justify-content:space-between">
        <div class="row" style="gap:10px"><span class="num">{{ i + 1 }}</span>
          <h2 style="margin:0">{{ runT(s) ? runT(s).title : 'Step ' + (i + 1) }}
            <span v-if="s.distributed" class="muted" style="font-weight:400;font-size:13px">(distributed)</span></h2></div>
        <button v-if="!readonly && steps.length > 1" class="ghost danger sm" @click="removeStep(i)">Remove step</button>
      </div>

      <div class="io">
        <div>
          <div class="k">Takes</div>
          <div class="row" style="gap:6px">
            <template v-if="readonly">
              <span class="chip">{{ (inputs.find(x => x.value === s.input) || {}).label || s.input }}</span> from
              <span v-for="f in s.from" :key="f" class="chip">{{ srcLabel(f) }}</span>
            </template>
            <template v-else>
              <div style="min-width:220px"><Select v-model="s.input" :options="inputOpts" auto /></div>
              <span class="muted">from</span>
              <button v-for="f in sources(i)" :key="f" type="button" class="srcchip" :class="{ on: s.from.includes(f) }"
                      :disabled="srcDisabled(f)" :title="srcDisabled(f) ? 'only produces findings' : ''"
                      @click="toggleSource(s, f)">{{ srcLabel(f) }}</button>
            </template>
          </div>
          <div class="muted hint">{{ inputHelp(s.input) }}<span v-if="s.from.length > 1"> · the union of the selected sources, de-duplicated</span></div>
        </div>
        <div v-if="runT(s)">
          <div class="k">Gives</div>
          <div>{{ PRODUCES_LABEL[runT(s).produces] || runT(s).produces }}
            <span class="muted" v-if="runT(s).produces === 'findings'">— the end of this branch</span></div>
        </div>
      </div>

      <template v-if="!readonly">
        <div v-if="!s.picking && runT(s)" class="row" style="gap:8px;margin-top:10px">
          <span class="muted" style="font-size:12.5px">{{ runT(s).description }}</span>
          <button class="ghost sm" @click="s.picking = true">Change</button>
        </div>
        <div v-if="s.picking" style="margin-top:10px">
          <ScanTypePicker :templates="templates" :kind="feedKind(s)" v-model="s.templateId" v-model:distributed="s.distributed"
                          :exclude="tmpl ? [tmpl.id] : []" @update:modelValue="onPicked(s)" />
          <button v-if="s.templateId" class="ghost sm" style="margin-top:8px" @click="s.picking = false">Done</button>
        </div>
        <button class="ghost sm" style="margin-top:8px" @click="s.adv = !s.adv">{{ s.adv ? '▾' : '▸' }} Extra arguments</button>
        <div v-if="s.adv">
          <input v-model="s.args" placeholder='e.g. --timeout 60   or   --opt-args="-tags cve"' />
          <div class="muted hint">Appended to this step's command only.</div>
        </div>
      </template>
      <div v-else-if="s.args" class="muted hint">extra arguments: <code>{{ s.args }}</code></div>
    </div>
  </div>

  <div v-if="!readonly" class="row" style="margin-top:12px">
    <button @click="addStep">+ Add step</button>
  </div>

  <div v-if="!readonly" class="sumbar">
    <div>
      <b v-if="check.ok" class="okc">✓ Ready — {{ check.plan.length }} step(s) once expanded</b>
      <span v-else class="muted">{{ check.error || '…' }}</span>
      <div v-if="err" class="err">{{ err }}</div>
    </div>
    <div class="row" style="gap:8px">
      <button :disabled="!check.ok || saving" @click="save(false)">Save</button>
      <button class="primary" :disabled="!check.ok || saving" @click="save(true)">Save &amp; scan</button>
    </div>
  </div>
</template>

<style scoped>
.crumbs { font-size: 12.5px; margin-bottom: 2px; }
.arrow { color: var(--outline); padding: 4px 0 4px 18px; font-size: 18px; }
.stepc { margin-top: 0; }
.stepc:first-of-type { margin-top: 12px; }
.num { width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center; font-weight: 700; font-size: 13px;
  background: var(--accent); color: var(--on-primary); flex: none; }
.io { display: grid; gap: 10px 28px; grid-template-columns: 1fr auto; margin-top: 12px; }
.io .k { font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--on-surface-variant); margin-bottom: 4px; }
.hint { font-size: 12px; margin-top: 4px; }
.srcchip { height: 32px; padding: 0 12px; text-transform: none; letter-spacing: 0; font-weight: 500; font-size: 12.5px;
  border-color: var(--outline-variant); color: var(--on-surface-variant); }
.srcchip.on { background: var(--primary-container); color: var(--accent-ink); border-color: var(--accent); }
.okc { color: var(--ok); }
.sumbar { position: sticky; bottom: 0; margin: 18px -28px -24px; padding: 14px 28px; display: flex; gap: 16px;
  align-items: center; justify-content: space-between; background: color-mix(in srgb, var(--sc) 94%, transparent);
  border-top: 1px solid var(--outline-variant); backdrop-filter: blur(8px); z-index: 5; }
@media (max-width: 640px) { .io { grid-template-columns: 1fr; } .sumbar { margin: 18px -16px -16px; padding: 12px 16px; flex-direction: column; align-items: stretch; } }
</style>
