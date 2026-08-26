<script setup>
import { ref, reactive, computed, watch, onMounted, onUnmounted } from 'vue'
import { api, isAdmin } from '../api'
import Select from '../components/Select.vue'

const PROVIDERS = ['anthropic', 'openai', 'litellm', 'ollama']
const profiles = ref([])
const admin = isAdmin()
const err = ref('')
const form = reactive({ name: '', provider: 'anthropic', model: '', proxy_url: '', api_key: '' })

// Local models (Ollama): one shared host the server pulls to and every agent runs against.
const ollama = ref({ reachable: false, base_url: '', models: [] })
const installed = computed(() => ollama.value.models.filter(m => m.installed).map(m => m.name))
let poll = null

async function load() { profiles.value = await api.get('/llm-profiles') }

async function loadCatalog() {
  try { ollama.value = await api.get('/ollama/catalog') } catch (e) { /* ollama is optional */ }
  const pulling = (ollama.value.models || []).some(m => m.pull && m.pull.status === 'pulling')
  if (pulling && !poll) poll = setInterval(loadCatalog, 2000)
  if (!pulling && poll) { clearInterval(poll); poll = null }
}

async function pull(name) {
  try {
    await api.post('/ollama/pull', { name })
    if (!poll) poll = setInterval(loadCatalog, 2000)
    await loadCatalog()
  } catch (e) { alert(e.message) }
}

async function wire(name) {
  try {
    const r = await api.post('/ollama/profile', { name })
    await load()
    alert(r.existed ? `Profile "${r.name}" already exists` : `Created profile "${r.name}"`)
  } catch (e) { alert(e.message) }
}

watch(() => form.provider, (p) => {
  if (p === 'ollama') {
    form.api_key = ''
    const b = (ollama.value.base_url || 'http://localhost:11434').replace(/\/$/, '')
    form.proxy_url = b + '/v1'
    if (!form.model && installed.value.length) form.model = installed.value[0]
  }
})

async function create() {
  err.value = ''
  try {
    await api.post('/llm-profiles', {
      name: form.name.trim(), provider: form.provider, model: form.model || null,
      proxy_url: form.proxy_url || null, api_key: form.api_key || null,
    })
    form.name = ''; form.model = ''; form.proxy_url = ''; form.api_key = ''
    await load()
  } catch (e) { err.value = e.message }
}

async function del(id) {
  if (!confirm('Delete this profile?')) return
  try { await api.del('/llm-profiles/' + id); await load() } catch (e) { alert(e.message) }
}

async function setKey(p) {
  const k = prompt(`API key for "${p.name}" (stored server-side, never shown again):`)
  if (!k) return
  try { await api.patch('/llm-profiles/' + p.id, { api_key: k }); await load() } catch (e) { alert(e.message) }
}

// Verify a profile without running a scan: pings the provider with a 1-token request (401 = bad key, etc.)
const testResult = reactive({})
async function testProfile(p) {
  testResult[p.id] = { testing: true }
  try {
    const r = await api.post('/llm-profiles/' + p.id + '/test')
    testResult[p.id] = { ok: r.ok, detail: r.error || r.detail || 'ok' }
  } catch (e) { testResult[p.id] = { ok: false, detail: e.message } }
}

onMounted(() => { load(); loadCatalog() })
onUnmounted(() => { if (poll) clearInterval(poll) })
</script>

<template>
  <h1>LLM Profiles</h1>
  <p class="muted">Predefined provider/model/key an <code>ai_agent</code> template references. The API key is
    write-only — stored server-side, delivered to a runner only at job time, never returned to the browser.</p>

  <!-- Local models: one shared Ollama the server pulls to and every agent runs against -->
  <div v-if="admin" class="card" style="margin:14px 0">
    <h2>Local models (Ollama)</h2>
    <p class="muted" style="font-size:13px">
      Small models that run on your own hardware — no API key, no per-token cost. This manages the
      <b>server host's</b> Ollama (used by the built-in agent); every other agent downloads to its own Ollama
      from its <code>:7070</code> control UI, and only claims jobs whose model it has.
      Host: <code>{{ ollama.base_url || 'localhost:11434' }}</code>
      <span :class="ollama.reachable ? 'ok' : 'bad'"> — {{ ollama.reachable ? 'reachable' : 'unreachable' }}</span>.
      Ollama is a separate service — run it as a sidecar container or on the host and set
      <code>OLLAMA_BASE_URL</code> (blank auto-detects <code>host.docker.internal</code>).
    </p>
    <table class="reflow">
      <thead><tr><th>Model</th><th>Size</th><th>Notes</th><th></th></tr></thead>
      <tbody>
        <tr v-for="m in ollama.models" :key="m.name">
          <td data-label="Model"><b>{{ m.name }}</b></td>
          <td data-label="Size">~{{ m.size_gb }} GB</td>
          <td data-label="Notes" class="muted">{{ m.note }}</td>
          <td data-label="">
            <div class="row" style="gap:6px;justify-content:flex-end">
              <span v-if="m.pull && m.pull.status === 'pulling'" class="muted">{{ m.pull.detail || 'downloading…' }}</span>
              <span v-else-if="m.pull && m.pull.status === 'error'" class="bad">{{ m.pull.detail }}</span>
              <button v-if="!m.installed && !(m.pull && m.pull.status === 'pulling')" @click="pull(m.name)">Download</button>
              <span v-if="m.installed" class="ok">installed</span>
              <button v-if="m.installed" @click="wire(m.name)">Use in a profile</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <div v-if="admin" class="card" style="margin:14px 0">
    <h2>New profile</h2>
    <div class="row" style="gap:14px;align-items:flex-start">
      <div style="flex:1;min-width:160px"><label>Name</label><input v-model="form.name" placeholder="claude-main" /></div>
      <div style="flex:1;min-width:140px"><label>Provider</label>
        <Select v-model="form.provider" :options="PROVIDERS" />
      </div>
      <div style="flex:1;min-width:160px"><label>Model</label>
        <Select v-if="form.provider === 'ollama' && installed.length" v-model="form.model" :options="installed" />
        <input v-else v-model="form.model"
               :placeholder="form.provider === 'ollama' ? 'download a model above first' : 'claude-sonnet-5'" />
      </div>
    </div>
    <template v-if="form.provider !== 'ollama'">
      <label>Proxy URL (optional)</label>
      <input v-model="form.proxy_url" placeholder="https://llm-proxy.internal" />
      <label>API key (write-only)</label>
      <input v-model="form.api_key" type="password" placeholder="sk-…" autocomplete="new-password" />
    </template>
    <p v-else class="muted" style="font-size:13px">Ollama needs no API key. Requests go to <code>{{ form.proxy_url }}</code>.</p>
    <p v-if="err" style="color:var(--bad)">{{ err }}</p>
    <button class="primary" style="margin-top:12px" :disabled="!form.name || !form.provider" @click="create">Create profile</button>
  </div>
  <p v-else class="muted" style="margin:14px 0">Only admins can create or delete profiles.</p>

  <div class="card tablecard">
  <table class="reflow">
    <thead><tr><th>Name</th><th>Provider</th><th>Model</th><th>Key</th><th></th></tr></thead>
    <tbody>
      <tr v-for="p in profiles" :key="p.id">
        <td data-label="Name"><b>{{ p.name }}</b></td>
        <td data-label="Provider">{{ p.provider }}</td>
        <td data-label="Model">{{ p.model || '—' }}</td>
        <td data-label="Key"><span :class="p.has_key ? 'ok' : 'muted'">{{ p.has_key ? 'set' : 'none' }}</span></td>
        <td data-label="">
          <div class="row" style="gap:6px">
            <button @click="testProfile(p)">{{ testResult[p.id]?.testing ? 'Testing…' : 'Test' }}</button>
            <button v-if="admin && p.provider !== 'ollama'" @click="setKey(p)">{{ p.has_key ? 'Replace key' : 'Set key' }}</button>
            <button v-if="admin" class="danger ghost" @click="del(p.id)">Delete</button>
          </div>
          <div v-if="testResult[p.id] && !testResult[p.id].testing" style="font-size:12px;margin-top:4px"
               :class="testResult[p.id].ok ? 'ok' : 'bad'">
            {{ testResult[p.id].ok ? '✓ works' : '✗ ' + testResult[p.id].detail }}
          </div>
        </td>
      </tr>
      <tr v-if="!profiles.length"><td colspan="5" class="muted">No profiles yet.</td></tr>
    </tbody>
  </table>
  </div>
</template>
