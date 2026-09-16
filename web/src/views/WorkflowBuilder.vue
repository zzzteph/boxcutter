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
}))

// live compile preview (debounced): the exact workflow YAML the runner gets, or the precise validation error
const preview = ref('')
const previewErr = ref('')
let tmr = null
watch([graph], () => { clearTimeout(tmr); tmr = setTimeout(runPreview, 350) }, { deep: true })
async function runPreview() {
  preview.value = ''; previewErr.value = ''
  if (!graph.value.name || !graph.value.nodes.length) return
  try {
    const r = await api.post('/templates/workflow/preview',
      { name: graph.value.name, help: graph.value.help, graph: graph.value })
    preview.value = r.yaml
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
    <p class="muted" style="margin:10px 0 0">Chain tools into a workflow: each box runs on the <b>Target</b>, or
      on the URLs a box wired into it produced. A <b>findings</b> tool is terminal — it has no output to wire on.</p>
  </div>

  <div class="card">
    <GraphCanvas v-if="ready" :initial="initialGraph" :catalog="catalog" @change="onGraph" />
  </div>

  <div class="split">
    <div class="card">
      <h2>Compiled workflow</h2>
      <p class="muted" style="margin-top:0">The exact workflow the engine runs — shipped to the scanner at run time.</p>
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
