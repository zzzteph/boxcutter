<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api'
import GraphCanvas from '../components/GraphCanvas.vue'

const route = useRoute()
const router = useRouter()

const catalog = ref([])
const name = ref('')
const help = ref('')
const severities = ref([])                 // workflow-level findings filter: keep only these (empty = all)
const SEVS = ['critical', 'high', 'medium', 'low', 'info']
const editingId = ref(null)
const err = ref('')
const busy = ref(false)
const ready = ref(false)                 // gate the canvas until catalog + (edit) template are loaded
const initialGraph = ref({ nodes: [], edges: [] })

// the canvas owns the boxes/wires and emits them here on every change
const gnodes = ref([])
const gedges = ref([])
function onGraph(g) { gnodes.value = g.nodes; gedges.value = g.edges }

const graph = computed(() => ({
  name: name.value.trim(), help: help.value.trim(), nodes: gnodes.value, edges: gedges.value,
  severities: severities.value,
}))

// live compile preview (debounced): the exact workflow YAML the runner gets, or the precise validation error
const preview = ref('')
const previewErr = ref('')
const segCount = ref(1)                   // how many fan-out stages the graph compiles to (1 = single process)
let tmr = null
watch([graph], () => { clearTimeout(tmr); tmr = setTimeout(runPreview, 350) }, { deep: true })
async function runPreview() {
  preview.value = ''; previewErr.value = ''
  if (!graph.value.name || !graph.value.nodes.length) return
  try {
    const r = await api.post('/templates/workflow/preview',
      { name: graph.value.name, help: graph.value.help, graph: graph.value })
    preview.value = r.yaml
    segCount.value = r.segments || 1
  } catch (e) { previewErr.value = e.message }
}

const canSave = computed(() => !!graph.value.name && graph.value.nodes.length > 0 && !previewErr.value && !busy.value)
async function save() {
  err.value = ''; busy.value = true
  try {
    const body = { name: graph.value.name, help: graph.value.help, graph: graph.value }
    if (editingId.value) body.template_id = editingId.value
    await api.post('/templates/workflow', body)
    router.push('/templates')
  } catch (e) { err.value = e.message } finally { busy.value = false }
}

async function load() {
  catalog.value = await api.get('/templates/tool-catalog')
  const tid = route.query.template
  if (tid) {
    try {
      const t = await api.get('/templates/' + tid)
      const g = t.spec?.graph
      if (g) {
        editingId.value = t.id
        name.value = g.name || t.name || ''
        help.value = g.help || ''
        severities.value = Array.isArray(g.severities) ? g.severities : []
        initialGraph.value = { nodes: g.nodes || [], edges: g.edges || [] }
      }
    } catch { /* fall through to an empty canvas */ }
  }
  ready.value = true
}
onMounted(load)
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center">
    <h1>{{ editingId ? 'Edit workflow' : 'Build workflow' }}</h1>
    <router-link to="/templates" class="btn ghost">← Templates</router-link>
  </div>

  <div class="card">
    <div class="formgrid">
      <div>
        <label>Name <span class="muted">— lowercase, digits, hyphens</span></label>
        <input v-model="name" placeholder="my-recon-scan" />
      </div>
      <div>
        <label>Description <span class="muted">— optional</span></label>
        <input v-model="help" placeholder="subfinder → httpx → nuclei" />
      </div>
    </div>
    <div style="margin-top:12px">
      <label>Keep findings of severity <span class="muted">— optional; leave all unchecked to keep every severity</span></label>
      <div class="row" style="gap:14px;flex-wrap:wrap;margin-top:4px">
        <label v-for="s in SEVS" :key="s" style="display:flex;align-items:center;gap:5px;font-size:13px;cursor:pointer">
          <input type="checkbox" :value="s" v-model="severities" style="width:auto" /> {{ s }}
        </label>
      </div>
    </div>
    <p class="muted" style="margin:10px 0 0">Chain tools into a pipeline: each box runs on the <b>Target</b>, or
      on the URLs a box wired into it produced. On a wired box, add a <b>condition</b> (contains / excludes a
      value) to run it only on matching URLs — e.g. <code>subfinder → httpx (contains "admin") → nuclei</code>.
      A <b>findings</b> tool is terminal — it has no output to wire on.</p>
  </div>

  <div class="card">
    <GraphCanvas v-if="ready" :initial="initialGraph" :catalog="catalog" @change="onGraph" />
  </div>

  <div class="split">
    <div class="card">
      <h2>Workflow preview</h2>
      <p class="muted" style="margin-top:0">The actual boxcutter workflow your boxes turn into — the recipe the
        scanner runs. It updates live as you wire boxes; you don't edit it here.</p>
      <p v-if="segCount > 1" class="muted" style="margin-top:0;color:var(--primary)">
        ⑂ Fans out across the fleet in <b>{{ segCount }} stages</b> — each stage after a fan-out wire runs as
        separate per-item jobs spread over every online scanner.</p>
      <p v-if="previewErr" class="err">{{ previewErr }}</p>
      <pre class="cmd" style="white-space:pre-wrap">{{ preview || (previewErr ? '' : 'Add a box and a name…') }}</pre>
    </div>
    <div class="card">
      <h2>Save</h2>
      <p class="muted" style="margin-top:0">Saved as a workflow template — pick it in New Scan, or use it as a
        pipeline stage.</p>
      <p v-if="err" class="err">{{ err }}</p>
      <button class="primary" :disabled="!canSave" @click="save">
        {{ busy ? 'Saving…' : (editingId ? 'Save changes' : 'Save workflow') }}</button>
    </div>
  </div>
</template>
