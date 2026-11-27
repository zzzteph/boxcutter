<script setup>
// The Workflow builder: a workflow is a graph of steps. Every step runs one template (a tool or a scan template)
// once per item it receives - each run a separate job that any scanner can pick up - and passes what it finds to
// the steps wired after it. Built-in workflows open read-only (duplicate one to change it).
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api'
import Select from '../components/Select.vue'
import WorkflowGraph from '../components/WorkflowGraph.vue'
import { ACCEPTS_LABEL, PRODUCES_LABEL } from '../util'
import { KIND_WORD, TARGETS, flowInfo, graphFromStages, inlineWorkflow, newNode, nodeErrors, pickInput,
  stagesFromGraph } from '../workflow'

const route = useRoute()
const router = useRouter()
const isNew = computed(() => !route.params.id)

const templates = ref([])
const inputs = ref([])
const tmpl = ref(null)
const title = ref('')
const description = ref('')
const graph = ref({ nodes: [], edges: [] })
const selected = ref('')
const q = ref('')
const notice = ref('')
const check = ref({ ok: false, error: '', plan: [] })
const saving = ref(false)
const err = ref('')
const canvas = ref(null)
const readonly = computed(() => !!(tmpl.value && tmpl.value.builtin))
const inputLabels = computed(() => Object.fromEntries(inputs.value.map(i => [i.value, i.label])))
const inputOpts = computed(() => inputs.value.map(i => ({ value: i.value, label: i.label })))

// ---- palette ----
// Steps are single tools (plus Merge). A workflow from the list is added as ALL its steps, so every box that
// runs is on the canvas - nothing hidden inside a nested box.
const palette = computed(() => {
  const s = q.value.trim().toLowerCase()
  const match = t => !s || [t.title, t.name, t.description, t.category].join(' ').toLowerCase().includes(s)
  const groups = [
    { name: 'Flow', items: templates.value.filter(t => t.kind === 'merge' && match(t)) },
    { name: 'Tools', items: templates.value.filter(t => t.kind === 'tool' && t.builtin && match(t)) },
    { name: 'My presets', items: templates.value.filter(t => t.kind === 'tool' && !t.builtin && match(t)) },
    { name: 'Workflows — adds all their steps', wf: true, items: templates.value.filter(t => t.kind === 'pipeline' && match(t)
      && !String(t.variant_of || '').endsWith('-distributed') && (!tmpl.value || t.id !== tmpl.value.id)) },
  ]
  return groups.filter(g => g.items.length)
})
const open = ref({ Flow: true, Tools: true })
let seq = 0
function nextKey() { while (graph.value.nodes.some(n => n.key === 'n' + seq)) seq++; return 'n' + seq++ }
const inputValues = computed(() => inputs.value.map(i => i.value))
function add(t) {
  if (t.kind === 'pipeline') { addWorkflow(t); return }
  const node = newNode(t, nextKey())
  const sel = graph.value.nodes.find(n => n.key === selected.value)
  let nodes = [...graph.value.nodes, node], edges = graph.value.edges
  const from = sel ? sel.key : TARGETS
  const r = pickInput({ nodes, edges }, from, node.key, inputValues.value)
  if (r.error) onInvalid(`Added “${t.title}” unwired: ${r.error}`)
  else {
    edges = [...edges, { from, to: node.key }]
    if (r.input !== node.input) nodes = nodes.map(n => (n.key === node.key ? { ...n, input: r.input } : n))
  }
  graph.value = { nodes, edges }
  selected.value = node.key
}
async function addWorkflow(t) {
  try {
    const full = await api.get('/templates/' + t.id)
    const sel = graph.value.nodes.find(n => n.key === selected.value)
    const attach = sel ? sel.key : TARGETS
    const xs = graph.value.nodes.map(n => n.x ?? 0), ys = graph.value.nodes.map(n => n.y ?? 0)
    const origin = sel && Number.isFinite(sel.x) ? { x: sel.x + 300, y: sel.y }
      : { x: (xs.length ? Math.max(...xs) + 300 : 190), y: ys.length ? Math.min(...ys) : 0 }
    const sub = inlineWorkflow(full.spec.stages || [], full.spec.layout || [], templates.value, attach, origin, nextKey)
    graph.value = { nodes: [...graph.value.nodes, ...sub.nodes], edges: [...graph.value.edges, ...sub.edges] }
    selected.value = ''
    onInvalid(`Added the ${sub.nodes.length} steps of “${t.title}”`)
  } catch (e) { onInvalid(e.message) }
}

// ---- inspector ----
const sel = computed(() => graph.value.nodes.find(n => n.key === selected.value) || null)
const selTemplate = computed(() => sel.value ? templates.value.find(t => t.id === sel.value.templateId) : null)
const incoming = computed(() => sel.value ? graph.value.edges.filter(e => e.to === sel.value.key) : [])
function label(key) { const n = graph.value.nodes.find(x => x.key === key); return key === TARGETS ? 'Scan targets' : (n ? n.label || n.title : '') }
function patchSel(fields) {
  graph.value = { nodes: graph.value.nodes.map(n => (n.key === selected.value ? { ...n, ...fields } : n)), edges: graph.value.edges }
}
function reaches(from, to) {
  const seen = new Set([from]), st = [from]
  while (st.length) { const k = st.pop(); if (k === to) return true
    for (const e of graph.value.edges) if (e.from === k && !seen.has(e.to)) { seen.add(e.to); st.push(e.to) } }
  return false
}
const sourceOpts = computed(() => {
  if (!sel.value) return []
  const have = new Set(incoming.value.map(e => e.from))
  const opts = [{ value: TARGETS, label: 'Scan targets' }]
  for (const n of graph.value.nodes) {
    if (n.key === sel.value.key || reaches(sel.value.key, n.key) || have.has(n.key)) continue
    if (pickInput(graph.value, n.key, sel.value.key, inputValues.value).error) continue
    opts.push({ value: n.key, label: n.label || n.title })
  }
  return opts.filter(o => !have.has(o.value))
})
const addSource = ref(null)
function onAddSource(v) {
  if (!v) return
  const r = pickInput(graph.value, v, selected.value, inputValues.value)
  if (r.error) { onInvalid(r.error); addSource.value = null; return }
  graph.value = { nodes: graph.value.nodes.map(n => (n.key === selected.value ? { ...n, input: r.input } : n)),
    edges: [...graph.value.edges, { from: v, to: selected.value }] }
  addSource.value = null
}
// "Takes" only offers what works with every wire into the step
const takeOpts = computed(() => {
  if (!sel.value) return []
  return inputOpts.value.filter(o => o.value === sel.value.input || !nodeErrors(graph.value, sel.value.key, o.value).length)
})
const selErrors = computed(() => sel.value ? nodeErrors(graph.value, sel.value.key, sel.value.input || 'all') : [])
const flow = computed(() => flowInfo(graph.value))
const selGives = computed(() => sel.value ? (flow.value[sel.value.key] || {}).gives : '')
// one-click next steps for the selected step (only ones that can take what it gives)
const SUGGEST = { unverified: ['dnsx'], host: ['httpx', 'nuclei', 'wayback', 'merge'],
  url: ['katana-crawl', 'harvest', 'liveless', 'nuclei', 'fuzz', 'scan-secrets', 'merge'], leads: ['sqlmap'] }
const suggestions = computed(() => {
  if (!sel.value) return []
  const f = flow.value[sel.value.key] || {}
  const names = f.unverified ? SUGGEST.unverified : (sel.value.leads ? SUGGEST.leads : (SUGGEST[f.gives] || []))
  return names.map(n => templates.value.find(t => (t.kind === 'merge' ? 'merge' : t.name) === n && t.builtin)).filter(Boolean)
})
function dropSource(from) {
  graph.value = { nodes: graph.value.nodes, edges: graph.value.edges.filter(e => !(e.from === from && e.to === selected.value)) }
}
function removeSel() {
  const k = selected.value
  graph.value = { nodes: graph.value.nodes.filter(n => n.key !== k), edges: graph.value.edges.filter(e => e.from !== k && e.to !== k) }
  selected.value = ''
}
// a nested workflow box (from before workflows were added as their steps) -> all its steps, wired in place
const nested = computed(() => graph.value.nodes.filter(n => n.kind === 'pipeline'))
async function expandNode(key) {
  const node = graph.value.nodes.find(n => n.key === key)
  if (!node) return
  const full = await api.get('/templates/' + node.templateId)
  const ATT = '__attach__'
  const sub = inlineWorkflow(full.spec.stages || [], [], templates.value, ATT,
    { x: Number.isFinite(node.x) ? node.x : 200, y: Number.isFinite(node.y) ? node.y : 0 }, nextKey)
  const parents = graph.value.edges.filter(e => e.to === key).map(e => e.from)
  const children = graph.value.edges.filter(e => e.from === key).map(e => e.to)
  const subFrom = new Set(sub.edges.map(e => e.from))
  const leaves = sub.nodes.filter(n => !subFrom.has(n.key) && (n.gives || n.produces !== 'findings')).map(n => n.key)
  const edges = graph.value.edges.filter(e => e.from !== key && e.to !== key)
  for (const e of sub.edges) {
    if (e.from === ATT) for (const p of parents) edges.push({ from: p, to: e.to })
    else edges.push(e)
  }
  for (const l of leaves) for (const c of children) edges.push({ from: l, to: c })
  graph.value = { nodes: [...graph.value.nodes.filter(n => n.key !== key), ...sub.nodes], edges }
  selected.value = ''
}
async function expandAll() {
  try { for (const n of [...nested.value]) await expandNode(n.key); canvas.value && canvas.value.tidy() }
  catch (e) { onInvalid(e.message) }
}
function onInvalid(msg) { notice.value = msg; setTimeout(() => { if (notice.value === msg) notice.value = '' }, 4000) }

// ---- validation + save ----
const built = computed(() => stagesFromGraph(graph.value))
let tmr = null
watch([graph, title], () => {
  if (readonly.value) return
  clearTimeout(tmr)
  tmr = setTimeout(async () => {
    if (built.value.error) { check.value = { ok: false, error: built.value.error, plan: [] }; return }
    try { check.value = await api.post('/templates/preview', { title: title.value || 'x', kind: 'pipeline', stages: built.value.stages }) }
    catch (e) { check.value = { ok: false, error: e.message, plan: [] } }
  }, 300)
}, { deep: true })

async function save(thenScan) {
  err.value = ''
  if (!title.value.trim()) { err.value = 'Give the workflow a name'; return }
  if (built.value.error) { err.value = built.value.error; return }
  saving.value = true
  const body = { title: title.value.trim(), description: description.value, kind: 'pipeline',
    stages: built.value.stages, layout: built.value.layout }
  try {
    const t = isNew.value ? await api.post('/templates', body) : await api.put('/templates/' + tmpl.value.id, body)
    router.push(thenScan ? '/scans/new?template=' + t.id : '/workflows')
  } catch (e) { err.value = e.message } finally { saving.value = false }
}
async function duplicate() {
  try {
    const copy = await api.post('/templates', { title: tmpl.value.title + ' (copy)', description: tmpl.value.description,
      kind: 'pipeline', stages: tmpl.value.spec.stages, layout: tmpl.value.spec.layout || [] })
    router.push('/workflows/' + copy.id)
  } catch (e) { alert(e.message) }
}

onMounted(async () => {
  const [t, inp] = await Promise.all([api.get('/templates'), api.get('/templates/inputs')])
  templates.value = t; inputs.value = inp
  if (!isNew.value) {
    tmpl.value = await api.get('/templates/' + route.params.id)
    title.value = tmpl.value.title; description.value = tmpl.value.description || ''
    graph.value = graphFromStages(tmpl.value.spec.stages || [], t, tmpl.value.spec.layout || [])
  }
})
</script>

<template>
  <div class="crumbs muted"><router-link to="/workflows">Workflows</router-link> ›</div>
  <div class="top">
    <div class="names">
      <input v-if="!readonly" v-model="title" class="title-in" placeholder="Name this workflow…" />
      <h1 v-else style="margin:0">{{ tmpl?.title }} <span class="tag plain">built-in</span></h1>
      <input v-if="!readonly" v-model="description" class="desc-in" placeholder="What it's for (optional)" />
      <div v-else class="muted">{{ tmpl?.description }}</div>
    </div>
    <div class="row" style="gap:8px">
      <template v-if="readonly">
        <router-link :to="'/scans/new?template=' + tmpl.id" class="btn primary">Scan with it</router-link>
        <button @click="duplicate">Duplicate &amp; edit</button>
      </template>
      <template v-else>
        <button :disabled="saving" @click="save(false)">Save</button>
        <button class="primary" :disabled="saving" @click="save(true)">Save &amp; scan</button>
      </template>
    </div>
  </div>

  <div class="builder" :class="{ ro: readonly }">
    <!-- palette -->
    <aside v-if="!readonly" class="pal card">
      <input v-model="q" placeholder="Search templates…" />
      <div class="muted hint">Click to add a step. It is wired after the selected step (or to the scan targets).</div>
      <div v-for="g in palette" :key="g.name" class="pg">
        <button type="button" class="pg-h" @click="open[g.name] = !open[g.name]">
          {{ open[g.name] || q ? '▾' : '▸' }} {{ g.name }} <span class="muted">{{ g.items.length }}</span></button>
        <div v-if="open[g.name] || q">
          <button v-for="t in g.items" :key="t.id" type="button" class="pi" :title="t.description" @click="add(t)">
            <b>{{ t.kind === 'merge' ? '⇉ ' : '' }}{{ t.title }}</b>
            <span v-if="t.kind === 'merge'">several steps → one stream, no duplicates</span>
            <span v-else-if="g.wf">{{ t.steps }} steps</span>
            <span v-else>{{ ACCEPTS_LABEL[t.accepts] || t.accepts }} → {{ PRODUCES_LABEL[t.produces] || t.produces }}</span>
          </button>
        </div>
      </div>
    </aside>

    <!-- canvas -->
    <section class="cv">
      <WorkflowGraph ref="canvas" v-model="graph" :mode="readonly ? 'view' : 'edit'" :selected="selected"
                     :input-labels="inputLabels" :inputs="inputValues" :height="620" @select="k => selected = k" @invalid="onInvalid" />
      <div v-if="notice" class="notice">{{ notice }}</div>
      <div v-if="!readonly && nested.length" class="nestbar">{{ nested.length }} nested workflow box(es) hide their steps.
        <button type="button" class="sm" @click="expandAll">Expand all</button></div>
    </section>

    <!-- inspector -->
    <aside class="insp card">
      <template v-if="sel">
        <div class="row" style="justify-content:space-between;align-items:flex-start;flex-wrap:nowrap">
          <h2 style="margin:0">{{ sel.label || sel.title }}</h2>
          <span class="tag plain">{{ sel.kind === 'merge' ? 'flow' : sel.kind === 'pipeline' ? 'workflow' : (sel.kind === 'workflow' ? 'template' : 'tool') }}</span>
        </div>
        <p class="muted d">{{ selTemplate?.description }}</p>
        <div v-if="sel.kind === 'pipeline' && !readonly" class="nestnote">This box hides {{ sel.steps || 'several' }} steps.
          <button type="button" class="sm" @click="expandNode(sel.key)">Expand into its steps</button></div>

        <div class="k">Step name <span class="muted" style="text-transform:none;letter-spacing:0;font-weight:400">(optional)</span></div>
        <input v-if="!readonly" :value="sel.label" :placeholder="sel.title" @input="e => patchSel({ label: e.target.value })" />
        <div v-else>{{ sel.label || sel.title }}</div>

        <div class="k">Takes</div>
        <Select v-if="!readonly" :model-value="sel.input" :options="takeOpts" @update:model-value="v => patchSel({ input: v })" />
        <div v-else>{{ inputLabels[sel.input] || sel.input }}</div>
        <div class="muted hint">{{ (inputs.find(i => i.value === sel.input) || {}).help }}</div>
        <div v-for="e in selErrors" :key="e" class="err" style="font-size:12.5px;margin:6px 0 0">⚠ {{ e }}</div>

        <div class="k">From</div>
        <div class="srcs">
          <span v-for="e in incoming" :key="e.from" class="chip">{{ label(e.from) }}
            <a v-if="!readonly" href="#" @click.prevent="dropSource(e.from)">✕</a></span>
          <span v-if="!incoming.length" class="err" style="margin:0">not connected</span>
        </div>
        <Select v-if="!readonly && sourceOpts.length" v-model="addSource" :options="sourceOpts" placeholder="+ add an input…"
                @change="onAddSource" />
        <div class="muted hint">Several inputs = their results merged, duplicates removed — each item runs once.</div>

        <div class="k">Gives</div>
        <div v-if="sel.kind === 'merge'">unique {{ KIND_WORD[selGives] || 'results' }} from its inputs, passed on at once</div>
        <div v-else>{{ PRODUCES_LABEL[sel.produces] || sel.produces }}<span v-if="sel.leads" class="muted"> — its SQL-injection hits can go to sqlmap to be confirmed</span>
          <span v-else-if="sel.produces === 'findings'" class="muted"> — the end of this branch</span></div>
        <div v-if="flow[sel.key] && flow[sel.key].unverified" class="hint warnl">These hostnames are not verified yet — the next step must be dnsx (or a merge into dnsx).</div>

        <template v-if="!readonly && suggestions.length">
          <div class="k">Add next</div>
          <div class="srcs">
            <button v-for="t in suggestions" :key="t.id" type="button" class="ghost sm sug" @click="add(t)">+ {{ t.kind === 'merge' ? '⇉ Merge' : t.title.split(' — ')[0] }}</button>
          </div>
        </template>

        <template v-if="sel.kind !== 'merge'">
          <div class="k">Extra arguments</div>
          <input v-if="!readonly" :value="sel.args" placeholder='e.g. --timeout 60   or   --opt-args="-tags cve"'
                 @input="e => patchSel({ args: e.target.value })" />
          <code v-else>{{ sel.args || '—' }}</code>
        </template>

        <button v-if="!readonly" class="ghost danger sm" style="margin-top:14px" @click="removeSel">Remove this step</button>
      </template>
      <template v-else>
        <h2 style="margin-top:0">How a workflow runs</h2>
        <ol class="how">
          <li>It starts from your <b>scan targets</b>.</li>
          <li>Each step runs <b>once per item</b> it receives — every run is a separate job that <b>any scanner</b> picks up, so the work spreads over the whole fleet.</li>
          <li>A step passes what it finds (hostnames, URLs, …) to the steps wired after it — as soon as each job finishes.</li>
          <li>Parallel steps come together in a <b>⇉ Merge</b>: one stream, duplicates dropped, no job of its own.</li>
          <li>Wires are typed: <b>hostnames</b> go through <b>httpx</b> to become URLs, and hostnames from passive discovery are verified by <b>dnsx</b> first.</li>
          <li>Findings are the end of a branch — except fuzz's SQL-injection hits, which <b>sqlmap</b> can confirm.</li>
        </ol>
        <div class="muted hint" v-if="!readonly">Drag from a step's <b>gold dot</b> onto another step to wire them — the steps that can take the data light up. Click a wire to follow it (✕ removes it).</div>
        <div class="muted hint" v-else>Click a step or a wire to follow its data.</div>
      </template>
    </aside>
  </div>

  <div v-if="!readonly" class="sumbar">
    <div>
      <b v-if="check.ok" class="okc">✓ Ready — {{ graph.nodes.length }} step(s)<template v-if="check.plan.length !== graph.nodes.length">,
        {{ check.plan.length }} once nested workflows are expanded</template></b>
      <span v-else class="muted">{{ check.error || '…' }}</span>
      <div v-if="err" class="err">{{ err }}</div>
    </div>
    <div class="row" style="gap:8px">
      <button :disabled="saving" @click="save(false)">Save</button>
      <button class="primary" :disabled="saving" @click="save(true)">Save &amp; scan</button>
    </div>
  </div>
</template>

<style scoped>
.crumbs { font-size: 12.5px; margin-bottom: 4px; }
.top { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
.names { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 6px; }
.title-in { font-size: 22px; padding: 6px 10px; border-color: transparent; background: transparent; max-width: 640px; }
.title-in:hover, .title-in:focus { border-color: var(--outline-variant); }
.desc-in { font-size: 13px; padding: 6px 10px; border-color: transparent; max-width: 640px; color: var(--on-surface-variant); }
.desc-in:hover, .desc-in:focus { border-color: var(--outline-variant); }
.builder { display: grid; grid-template-columns: 270px minmax(0, 1fr) 310px; gap: 12px; margin-top: 12px; align-items: start; }
.builder.ro { grid-template-columns: minmax(0, 1fr) 310px; }
.pal { padding: 12px; max-height: 620px; overflow: auto; }
.pal input { padding: 9px 12px; }
.hint { font-size: 12px; margin-top: 6px; line-height: 1.45; }
.pg { margin-top: 8px; }
.pg-h { all: unset; cursor: pointer; display: block; width: 100%; font-size: 11px; font-weight: 700; letter-spacing: .07em;
  text-transform: uppercase; color: var(--on-surface-variant); padding: 6px 2px; }
.pi { all: unset; box-sizing: border-box; cursor: pointer; display: flex; flex-direction: column; gap: 1px; width: 100%;
  padding: 7px 9px; border-radius: var(--radius-xs); border: 1px solid transparent; }
.pi:hover { background: var(--sc); border-color: var(--outline-variant); }
.pi b { font-weight: 500; font-size: 13px; color: var(--on-surface); }
.pi span { font-size: 11px; color: var(--outline); }
.cv { position: relative; min-width: 0; }
.notice { position: absolute; left: 50%; top: 12px; transform: translateX(-50%); background: var(--error-container);
  color: var(--on-error-container); padding: 6px 12px; border-radius: var(--radius-s); font-size: 13px; }
.insp { padding: 16px; max-height: 620px; overflow: auto; }
.insp .d { font-size: 12.5px; margin: 6px 0 4px; }
.k { font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--on-surface-variant);
  margin: 14px 0 6px; }
.srcs { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 6px; }
.how { padding-left: 18px; margin: 0; line-height: 1.6; font-size: 13px; color: var(--on-surface-variant); }
.how b { color: var(--on-surface); font-weight: 600; }
.okc { color: var(--ok); }
.warnl { color: var(--warn); }
.nestnote { font-size: 12.5px; margin: 8px 0; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; color: var(--warn); }
.nestbar { position: absolute; left: 12px; top: 12px; font-size: 12.5px; padding: 6px 10px; border-radius: var(--radius-s);
  background: var(--sc-high); border: 1px solid var(--outline-variant); display: flex; gap: 8px; align-items: center; }
.notice { max-width: 70%; }
.sug { text-transform: none; letter-spacing: 0; font-weight: 500; height: 28px; }
.sumbar { position: sticky; bottom: 0; margin: 14px -28px -24px; padding: 12px 28px; display: flex; gap: 16px;
  align-items: center; justify-content: space-between; background: color-mix(in srgb, var(--sc) 94%, transparent);
  border-top: 1px solid var(--outline-variant); backdrop-filter: blur(8px); z-index: 5; }
@media (max-width: 1100px) { .builder, .builder.ro { grid-template-columns: 1fr; } .pal, .insp { max-height: none; } }
</style>
