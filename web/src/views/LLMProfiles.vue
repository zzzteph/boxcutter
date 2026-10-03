<script setup>
import { ref, reactive, watch, onMounted } from 'vue'
import { api, isAdmin } from '../api'
import Select from '../components/Select.vue'
import ClaudeConsole from '../components/ClaudeConsole.vue'

const PROVIDERS = ['anthropic', 'openai', 'litellm', 'claude-code']
const profiles = ref([])
const admin = isAdmin()
const err = ref('')
const form = reactive({ name: '', provider: 'anthropic', model: '', proxy_url: '', api_key: '' })

async function load() { profiles.value = await api.get('/llm-profiles') }

watch(() => form.provider, (p) => {
  if (p === 'claude-code') {
    // No API key: rides the runner's own authenticated Claude Code login (CLAUDE_CODE_OAUTH_TOKEN / `claude`).
    form.api_key = ''
    form.proxy_url = ''
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
      <div style="flex:1;min-width:160px"><label>Model</label>
        <input v-model="form.model" placeholder="claude-sonnet-5" />
      </div>
    </div>
    <template v-if="form.provider !== 'claude-code'">
      <label>Proxy URL (optional)</label>
      <input v-model="form.proxy_url" placeholder="https://llm-proxy.internal" />
      <label>API key (write-only)</label>
      <input v-model="form.api_key" type="password" placeholder="sk-…" autocomplete="new-password" />
    </template>
    <p v-else class="muted" style="font-size:13px">No API key: rides this server's own authenticated Claude Code
      login (billed to your Claude subscription). Authorize it right here — create the profile, then click
      <b>⌨ Authorize in a console</b> on its row below and run <code>/login</code>. It persists on the data
      volume, so every claude-code run then uses it. (Or headless: <code>claude setup-token</code> →
      <code>CLAUDE_CODE_OAUTH_TOKEN</code>.)</p>
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
            <ClaudeConsole v-if="admin && p.provider === 'claude-code'" />
            <button v-if="admin && p.provider !== 'claude-code'" @click="setKey(p)">{{ p.has_key ? 'Replace key' : 'Set key' }}</button>
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
