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
import { TARGETS, graphFromStages, newNode, stagesFromGraph } from '../workflow'

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
const GROUPS = ['Websites', 'Environment', 'Discovery', 'APIs', 'Secrets', 'Web archive', 'Network']
const palette = computed(() => {
  const s = q.value.trim().toLowerCase()
  const match = t => !s || [t.title, t.name, t.description, t.category].join(' ').toLowerCase().includes(s)
  const atoms = templates.value.filter(t => t.kind !== 'pipeline' && match(t))
  const groups = GROUPS.map(g => ({ name: g, items: atoms.filter(t => t.category === g && t.builtin) }))
  groups.push({ name: 'My presets', items: atoms.filter(t => !t.builtin) })
  groups.push({ name: 'Tools', items: atoms.filter(t => t.category === 'Tools') })
  groups.push({ name: 'Workflows (nested)', items: templates.value.filter(t => t.kind === 'pipeline' && match(t)
    && (!tmpl.value || t.id !== tmpl.value.id)) })
  return groups.filter(g => g.items.length)
})
const open = ref({ Websites: true, Discovery: true })
let seq = 0
function nextKey() { while (graph.value.nodes.some(n => n.key === 'n' + seq)) seq++; return 'n' + seq++ }
function add(t) {
  const node = newNode(t, nextKey())
  const sel = graph.value.nodes.find(n => n.key === selected.value)
  const from = sel && sel.produces !== 'findings' ? sel.key : TARGETS
  graph.value = { nodes: [...graph.value.nodes, node], edges: [...graph.value.edges, { from, to: node.key }] }
  selected.value = node.key
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
    if (n.key === sel.value.key || n.produces === 'findings' || reaches(sel.value.key, n.key)) continue
    opts.push({ value: n.key, label: n.label || n.title })
  }
  return opts.filter(o => !have.has(o.value))
})
const addSource = ref(null)
function onAddSource(v) {
  if (!v) return
  graph.value = { nodes: graph.value.nodes, edges: [...graph.value.edges, { from: v, to: selected.value }] }
  addSource.value = null
}
function dropSource(from) {
  graph.value = { nodes: graph.value.nodes, edges: graph.value.edges.filter(e => !(e.from === from && e.to === selected.value)) }
}
function removeSel() {
  const k = selected.value
  graph.value = { nodes: graph.value.nodes.filter(n => n.key !== k), edges: graph.value.edges.filter(e => e.from !== k && e.to !== k) }
  selected.value = ''
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
            <b>{{ t.title }}</b>
            <span>{{ ACCEPTS_LABEL[t.accepts] || t.accepts }} → {{ PRODUCES_LABEL[t.produces] || t.produces }}</span>
          </button>
        </div>
      </div>
    </aside>

    <!-- canvas -->
    <section class="cv">
      <WorkflowGraph ref="canvas" v-model="graph" :mode="readonly ? 'view' : 'edit'" :selected="selected"
                     :input-labels="inputLabels" :height="620" @select="k => selected = k" @invalid="onInvalid" />
      <div v-if="notice" class="notice">{{ notice }}</div>
    </section>

    <!-- inspector -->
    <aside class="insp card">
      <template v-if="sel">
        <div class="row" style="justify-content:space-between;align-items:flex-start;flex-wrap:nowrap">
          <h2 style="margin:0">{{ sel.label || sel.title }}</h2>
          <span class="tag plain">{{ sel.kind === 'pipeline' ? 'workflow' : (sel.kind === 'workflow' ? 'template' : 'tool') }}</span>
        </div>
        <p class="muted d">{{ selTemplate?.description }}</p>

        <div class="k">Step name <span class="muted" style="text-transform:none;letter-spacing:0;font-weight:400">(optional)</span></div>
        <input v-if="!readonly" :value="sel.label" :placeholder="sel.title" @input="e => patchSel({ label: e.target.value })" />
        <div v-else>{{ sel.label || sel.title }}</div>

        <div class="k">Takes</div>
        <Select v-if="!readonly" :model-value="sel.input" :options="inputOpts" @update:model-value="v => patchSel({ input: v })" />
        <div v-else>{{ inputLabels[sel.input] || sel.input }}</div>
        <div class="muted hint">{{ (inputs.find(i => i.value === sel.input) || {}).help }}</div>

        <div class="k">From</div>
        <div class="srcs">
          <span v-for="e in incoming" :key="e.from" class="chip">{{ label(e.from) }}
            <a v-if="!readonly" href="#" @click.prevent="dropSource(e.from)">✕</a></span>
          <span v-if="!incoming.length" class="err" style="margin:0">not connected</span>
        </div>
        <Select v-if="!readonly && sourceOpts.length" v-model="addSource" :options="sourceOpts" placeholder="+ add an input…"
                @change="onAddSource" />
        <div class="muted hint">Several inputs = their results combined, duplicates removed.</div>

        <div class="k">Gives</div>
        <div>{{ PRODUCES_LABEL[sel.produces] || sel.produces }}<span v-if="sel.produces === 'findings'" class="muted"> — the end of this branch</span></div>

        <div class="k">Extra arguments</div>
        <input v-if="!readonly" :value="sel.args" placeholder='e.g. --timeout 60   or   --opt-args="-tags cve"'
               @input="e => patchSel({ args: e.target.value })" />
        <code v-else>{{ sel.args || '—' }}</code>

        <button v-if="!readonly" class="ghost danger sm" style="margin-top:14px" @click="removeSel">Remove this step</button>
      </template>
      <template v-else>
        <h2 style="margin-top:0">How a workflow runs</h2>
        <ol class="how">
          <li>It starts from your <b>scan targets</b>.</li>
          <li>Each step runs <b>once per item</b> it receives — every run is a separate job that <b>any scanner</b> picks up, so the work spreads over the whole fleet.</li>
          <li>A step passes what it finds (hostnames, URLs, …) to the steps wired after it — as soon as each job finishes.</li>
          <li>Each step picks <b>which kind</b> of results it takes — the wire colours.</li>
          <li>Findings are the end of a branch.</li>
        </ol>
        <div class="muted hint" v-if="!readonly">Drag from a step's <b>gold dot</b> onto another step to wire them. Click a wire, then ✕ to remove it. Drag a step to move it.</div>
        <div class="muted hint" v-else>Click a step to see what it takes and gives.</div>
      </template>
    </aside>
  </div>

  <div v-if="!readonly" class="sumbar">
    <div>
      <b v-if="check.ok" class="okc">✓ Ready — {{ graph.nodes.length }} step(s), {{ check.plan.length }} once nested workflows are expanded</b>
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
.sumbar { position: sticky; bottom: 0; margin: 14px -28px -24px; padding: 12px 28px; display: flex; gap: 16px;
  align-items: center; justify-content: space-between; background: color-mix(in srgb, var(--sc) 94%, transparent);
  border-top: 1px solid var(--outline-variant); backdrop-filter: blur(8px); z-index: 5; }
@media (max-width: 1100px) { .builder, .builder.ro { grid-template-columns: 1fr; } .pal, .insp { max-height: none; } }
</style>
