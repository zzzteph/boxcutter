<script setup>
import { ref, reactive, onMounted } from 'vue'
import { api, isAdmin } from '../api'
import Select from '../components/Select.vue'

const PROVIDERS = ['anthropic', 'openai', 'litellm']
const profiles = ref([])
const admin = isAdmin()
const err = ref('')
const form = reactive({ name: '', provider: 'anthropic', model: '', proxy_url: '', api_key: '' })

async function load() { profiles.value = await api.get('/llm-profiles') }
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
onMounted(load)
</script>

<template>
  <h1>LLM Profiles</h1>
  <p class="muted">Predefined provider/model/key an <code>ai_agent</code> template references. The API key is
    write-only — stored server-side, delivered to a runner only at job time, never returned to the browser.</p>

  <div v-if="admin" class="card" style="margin:14px 0">
    <h2>New profile</h2>
    <div class="row" style="gap:14px;align-items:flex-start">
      <div style="flex:1;min-width:160px"><label>Name</label><input v-model="form.name" placeholder="claude-main" /></div>
      <div style="flex:1;min-width:140px"><label>Provider</label>
        <Select v-model="form.provider" :options="PROVIDERS" />
      </div>
      <div style="flex:1;min-width:160px"><label>Model</label><input v-model="form.model" placeholder="claude-sonnet-5" /></div>
    </div>
    <label>Proxy URL (optional)</label>
    <input v-model="form.proxy_url" placeholder="https://llm-proxy.internal" />
    <label>API key (write-only)</label>
    <input v-model="form.api_key" type="password" placeholder="sk-…" autocomplete="new-password" />
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
            <button v-if="admin" @click="setKey(p)">{{ p.has_key ? 'Replace key' : 'Set key' }}</button>
            <button v-if="admin" class="danger ghost" @click="del(p.id)">Delete</button>
          </div>
        </td>
      </tr>
      <tr v-if="!profiles.length"><td colspan="5" class="muted">No profiles yet.</td></tr>
    </tbody>
  </table>
  </div>
</template>
