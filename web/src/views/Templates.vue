<script setup>
import { ref, reactive, computed, watch, nextTick, onMounted } from 'vue'
import { api, isAdmin } from '../api'
import Select from '../components/Select.vue'

const KIND_LABEL = { tool: 'Tool', workflow: 'Workflow', ai_agent: 'AI agent' }
// The real stock boxcutter catalog (boxcutter --list-all / workflow --list / ai --list), with one-line
// descriptions so the picker is self-explanatory.
const CATALOG = {
  tool: [
    { name: 'subfinder', desc: 'Discover subdomains (Subfinder)' },
    { name: 'dnsx', desc: 'Resolve / brute-force DNS, filter wildcards' },
    { name: 'httpx', desc: 'Probe live HTTP services & tech' },
    { name: 'api-map', desc: 'Method-aware API path discovery' },
    { name: 'smart-enum', desc: 'Context-aware candidate path list' },
    { name: 'screenshot', desc: 'Screenshot a URL (headless chromium)' },
    { name: 'wayback', desc: 'Historical URLs from web archives' },
    { name: 'wayback-domains', desc: 'Wayback unique host list for a domain' },
    { name: 'katana-crawl', desc: 'Crawl a URL with Katana' },
    { name: 'zap-crawl', desc: 'Crawl with ZAP spider + AJAX' },
    { name: 'js-endpoints', desc: 'Extract API endpoints from a JS file' },
    { name: 'browser-crawl', desc: 'Headless-browser crawl (routes + XHR/fetch)' },
    { name: 'browser-login', desc: 'Log in via a real browser, return session' },
    { name: 'browser-actions', desc: 'Scripted headless-browser actions' },
    { name: 'visual-driver', desc: 'Drive a browser by screen coordinates' },
    { name: 'vision-verify', desc: 'Confirm JS execution (reflected/DOM XSS)' },
    { name: 'nuclei', desc: 'Nuclei vulnerability scan' },
    { name: 'sqlmap', desc: 'SQL-injection testing (sqlmap)' },
    { name: 'blind-oracle', desc: 'Blind SQLi / command-injection probes' },
    { name: 'bola-walk', desc: 'BOLA/IDOR cross-account authz diff' },
    { name: 'mass-assign', desc: 'Mass-assignment detection' },
    { name: 'dirb', desc: 'Directory brute-force (dirb)' },
    { name: 'dirsearch', desc: 'Directory brute-force (dirsearch)' },
    { name: 'zap-scan-url', desc: 'ZAP active scan of one URL' },
    { name: 'zap-scan-full', desc: 'Full ZAP scan (spider + AJAX + active)' },
    { name: 'zap-scan-openapi', desc: 'ZAP active scan from an OpenAPI spec' },
    { name: 'path-fuzz', desc: 'Brute-force a FUZZ position in a URL' },
    { name: 'path-bust', desc: 'Directory brute-force under a path' },
    { name: 'fuzz', desc: 'Fuzz params/path/body for injection' },
    { name: 'scan-secrets', desc: 'Scan a response for exposed secrets' },
    { name: 'git-extract', desc: 'Extract source from an exposed .git' },
    { name: 'swagger-parser', desc: 'Parse an OpenAPI/Swagger spec' },
    { name: 'swagger-endpoints', desc: 'List endpoints from a spec' },
    { name: 'swagger-specs', desc: 'Find OpenAPI/Swagger spec URLs' },
    { name: 'graphql-detect', desc: 'Find GraphQL endpoints' },
    { name: 'graphql-audit', desc: 'Audit a GraphQL endpoint' },
    { name: 'http-request', desc: 'Make a raw HTTP request' },
  ],
  workflow: [
    { name: 'endpoint-scan', desc: 'DAST one endpoint (fuzz + nuclei + sqlmap + zap)' },
    { name: 'env-nuclei', desc: 'subfinder → nuclei across the env' },
    { name: 'env-scan', desc: 'Enumerate subdomains, then web-full each' },
    { name: 'env-secrets', desc: 'Subdomains → crawl + secrets each host' },
    { name: 'env-takeover', desc: 'Subfinder → subdomain-takeover checks' },
    { name: 'env-wayback-secrets', desc: 'Subfinder → secrets on every subdomain' },
    { name: 'env-wayback', desc: 'Subfinder → wayback → endpoint-scan' },
    { name: 'graphql-scan', desc: 'Find + audit GraphQL endpoints' },
    { name: 'recon-http', desc: 'Recon, then live HTTP(S) services' },
    { name: 'recon', desc: 'Subdomains (subfinder + wayback), resolved' },
    { name: 'secrets-scan', desc: 'Gather JS, scan for secrets' },
    { name: 'swagger-fuzz', desc: 'Find spec(s), fuzz every endpoint' },
    { name: 'swagger-scan', desc: 'Find spec(s), DAST every endpoint' },
    { name: 'wayback-fuzz', desc: 'Wayback URLs → fuzz with your payload' },
    { name: 'wayback-scan', desc: 'Wayback URLs → sqlmap/fuzz/zap' },
    { name: 'web-crawl', desc: 'Katana + ZAP crawl, merged' },
    { name: 'web-full', desc: 'Probe liveness, then full web DAST' },
    { name: 'web-fuzz', desc: 'Web DAST, fuzz-only injection' },
    { name: 'web-nuclei', desc: 'Nuclei template passes on one URL' },
    { name: 'web-scan', desc: 'Full DAST of a known URL' },
    { name: 'web-sqlmap', desc: 'Web DAST, sqlmap-only injection' },
  ],
  ai_agent: [
    { name: 'irvin', desc: 'Pipeline bug-hunter (LLM)' },
    { name: 'logio', desc: 'Agentic login (auth only)' },
    { name: 'prawlio', desc: 'Authenticated crawl (login + crawl)' },
    { name: 'crawlio', desc: 'Code-verified endpoint crawler' },
    { name: 'juicy', desc: 'JS analyst (hidden URLs, DOM XSS, secrets)' },
    { name: 'bob', desc: 'Short surface scanner' },
    { name: 'travis', desc: 'Recon triage (rate a host)' },
    { name: 'caleb', desc: 'Multi-phase / multi-identity orchestrator' },
  ],
}
const CUSTOM = '__custom__'

const templates = ref([])
const profiles = ref([])
const err = ref('')
const loading = ref(true)
const editingId = ref(null)                            // null = creating; an id = editing that template
const form = reactive({ name: '', kind: 'tool', specName: 'httpx', customName: '', params: [], context: '', llm_profile_id: null, description: '' })
const isEditing = computed(() => editingId.value != null)

function addParam() { form.params.push({ flag: '', value: '' }) }
function rmParam(i) { form.params.splice(i, 1) }

const profileName = (id) => (profiles.value.find(p => p.id === id) || {}).name || ('#' + id)
const options = computed(() => CATALOG[form.kind] || [])
const kindOpts = Object.entries(KIND_LABEL).map(([value, label]) => ({ value, label }))
const specOpts = computed(() => [...options.value.map(o => ({ value: o.name, label: `${o.name} — ${o.desc}` })),
  { value: CUSTOM, label: 'Custom…' }])
const profileOpts = computed(() => profiles.value.map(p => ({ value: p.id, label: `${p.name} (${p.provider})` })))
const resolvedSpec = computed(() => (form.specName === CUSTOM ? form.customName.trim() : form.specName))
const selectedDesc = computed(() => (options.value.find(o => o.name === form.specName) || {}).desc || '')
const canCreate = computed(() => form.name.trim() && resolvedSpec.value &&
  (form.kind !== 'ai_agent' || form.llm_profile_id))

// render a template's params to a preview string (both structured params and legacy flat flags)
function specTokens(spec) {
  const out = []
  for (const p of (spec?.params || [])) { if (!p.flag) continue; out.push(p.flag); if (p.value !== '' && p.value != null) out.push(String(p.value)) }
  for (const f of (spec?.flags || [])) out.push(String(f))
  return out
}
const preview = computed(() => {
  const sub = form.kind === 'workflow' ? ['workflow'] : form.kind === 'ai_agent' ? ['ai'] : []
  return ['boxcutter', ...sub, resolvedSpec.value, ...specTokens({ params: form.params })].filter(Boolean).join(' ')
})

// when the kind changes, default the picker to that kind's first known item, and suggest a name
const suspendWatch = ref(false)                        // silence the auto-defaults while loading a template to edit
watch(() => form.kind, (k) => { if (!suspendWatch.value) form.specName = (CATALOG[k][0] || {}).name || CUSTOM })
watch(resolvedSpec, (s) => { if (!suspendWatch.value && s && !form.name.trim()) form.name = s })

async function load() {
  try {
    templates.value = await api.get('/templates')
    profiles.value = await api.get('/llm-profiles')
  } catch (e) { err.value = e.message } finally { loading.value = false }
}
function resetForm() {
  editingId.value = null
  form.name = ''; form.customName = ''; form.params = []; form.context = ''; form.llm_profile_id = null
  form.description = ''; form.kind = 'tool'; form.specName = (CATALOG.tool[0] || {}).name || CUSTOM
}
function cancelEdit() { resetForm(); err.value = '' }

// load an existing template into the form so it can be edited (the form doubles as the editor)
async function startEdit(t) {
  err.value = ''
  suspendWatch.value = true
  editingId.value = t.id
  form.kind = t.kind
  const known = (CATALOG[t.kind] || []).some(o => o.name === t.spec?.name)
  form.specName = known ? t.spec.name : CUSTOM
  form.customName = known ? '' : (t.spec?.name || '')
  form.name = t.name
  form.description = t.description || ''
  form.context = t.context || ''
  form.llm_profile_id = t.llm_profile_id || null
  form.params = (t.spec?.params || []).map(p => ({ flag: p.flag, value: p.value }))
  for (const f of (t.spec?.flags || [])) form.params.push({ flag: String(f), value: '' })
  await nextTick()
  suspendWatch.value = false
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

async function save() {
  err.value = ''
  try {
    const params = form.params.filter(p => p.flag.trim())
      .map(p => ({ flag: p.flag.trim().startsWith('-') ? p.flag.trim() : '--' + p.flag.trim(), value: p.value }))
    const body = {
      name: form.name.trim(), kind: form.kind,
      spec: { name: resolvedSpec.value, params, flags: [] },
      description: (form.description.trim() || selectedDesc.value || ''),
      context: form.kind === 'ai_agent' ? (form.context || null) : null,
      llm_profile_id: form.kind === 'ai_agent' ? form.llm_profile_id : null,
    }
    if (isEditing.value) await api.patch('/templates/' + editingId.value, body)
    else await api.post('/templates', body)
    resetForm()
    await load()
  } catch (e) { err.value = e.message }
}
async function del(id) {
  if (!confirm('Delete this template?')) return
  try { await api.del('/templates/' + id); if (editingId.value === id) resetForm(); await load() } catch (e) { alert(e.message) }
}
onMounted(load)
</script>

<template>
  <h1>Templates</h1>
  <div class="card" style="margin-bottom:18px" :class="{ editing: isEditing }">
    <div class="row" style="justify-content:space-between;align-items:center">
      <h2 style="margin:0">{{ isEditing ? 'Edit template' : 'New template' }}</h2>
      <button v-if="isEditing" class="ghost sm" @click="cancelEdit">Cancel</button>
    </div>
    <div class="row" style="gap:14px;align-items:flex-start">
      <div style="flex:1;min-width:140px">
        <label>Kind</label>
        <Select v-model="form.kind" :options="kindOpts" />
      </div>
      <div style="flex:2;min-width:220px">
        <label>{{ KIND_LABEL[form.kind] }}</label>
        <Select v-model="form.specName" :options="specOpts" />
        <input v-if="form.specName === CUSTOM" v-model="form.customName" placeholder="custom name" style="margin-top:6px" />
        <div v-else-if="selectedDesc" class="muted" style="font-size:12px;margin-top:4px">{{ selectedDesc }}</div>
      </div>
      <div style="flex:2;min-width:180px">
        <label>Name</label>
        <input v-model="form.name" :placeholder="resolvedSpec || 'My web scan'" />
      </div>
    </div>

    <label style="margin-top:14px">Boxcutter parameters
      <span class="muted">— flags passed to <code>{{ resolvedSpec || 'boxcutter' }}</code> for every scan using this template</span></label>
    <div v-for="(p, i) in form.params" :key="i" class="kvrow">
      <input v-model="p.flag" placeholder="--severity" />
      <input v-model="p.value" placeholder="high  (leave blank for a boolean flag)" />
      <button class="danger ghost icon" title="Remove" @click="rmParam(i)">✕</button>
    </div>
    <button class="tonal sm" @click="addParam">+ Add parameter</button>
    <pre class="cmd" style="margin-top:10px">{{ preview }}</pre>

    <label style="margin-top:14px">Description <span class="muted">— shown in the scan template picker</span></label>
    <textarea v-model="form.description" rows="2" :placeholder="selectedDesc || 'What this template does'"></textarea>

    <template v-if="form.kind === 'ai_agent'">
      <label>Default context (guidance for the agent — scans can override per run)</label>
      <textarea v-model="form.context" rows="2" placeholder="Focus on auth and access control"></textarea>
      <label>LLM profile</label>
      <Select v-model="form.llm_profile_id" :options="profileOpts" placeholder="Select a profile…" />
      <p v-if="!profiles.length" class="muted">
        No LLM profiles yet.
        <span v-if="isAdmin()">Create one under <router-link to="/llm-profiles">LLM Profiles</router-link>.</span>
        <span v-else>Ask an admin to create one.</span>
      </p>
    </template>
    <p v-if="err" style="color:var(--bad)">{{ err }}</p>
    <div class="row" style="margin-top:12px;gap:10px">
      <button class="primary" :disabled="!canCreate" @click="save">{{ isEditing ? 'Save changes' : 'Create template' }}</button>
      <button v-if="isEditing" class="ghost" @click="cancelEdit">Cancel</button>
    </div>
  </div>

  <div class="grid">
    <div v-for="t in templates" :key="t.id" class="card" :class="{ 'is-editing': t.id === editingId }">
      <div class="row" style="justify-content:space-between;align-items:flex-start">
        <b>{{ t.name }}</b><span class="tag" :class="'kind-' + t.kind">{{ KIND_LABEL[t.kind] || t.kind }}</span>
      </div>
      <div class="muted" style="margin-top:8px"><code>{{ t.spec.name }}</code></div>
      <div v-if="t.description" class="muted" style="font-size:12.5px;margin-top:6px;line-height:1.4">{{ t.description }}</div>
      <pre v-if="specTokens(t.spec).length" class="cmd sm">{{ specTokens(t.spec).join(' ') }}</pre>
      <div v-if="t.kind === 'ai_agent'" class="muted" style="font-size:12px;margin-top:4px">
        profile: {{ profileName(t.llm_profile_id) }}<span v-if="t.context"> · “{{ t.context }}”</span>
      </div>
      <div class="row" style="margin-top:10px;gap:8px">
        <button class="tonal sm" @click="startEdit(t)">Edit</button>
        <button class="danger ghost sm" @click="del(t.id)">Delete</button>
      </div>
    </div>
    <div v-if="loading" class="muted">Loading…</div>
    <div v-else-if="!templates.length" class="muted">No templates yet. Create one above.</div>
  </div>
</template>

<style scoped>
.card.editing, .card.is-editing { box-shadow: inset 0 0 0 1px var(--accent); }
</style>
