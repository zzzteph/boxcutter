<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'
import TemplatePicker from '../components/TemplatePicker.vue'
import Select from '../components/Select.vue'

const router = useRouter()
const templates = ref([])
const name = ref('')
const targets = ref('')
const templateId = ref(null)
const err = ref('')
const busy = ref(false)
// optional host-list file: for lists too large to paste (hundreds of thousands / millions). When set it is
// uploaded (streamed server-side) and takes precedence over the textarea.
const file = ref(null)
function onFile(e) { file.value = e.target.files?.[0] || null }
function clearFile() { file.value = null }

// scan-specific inputs (used mainly by AI-agent templates): context, creds, and arbitrary custom params
const vars = reactive({ context: '', creds: '', custom: [] })
function addCustom() { vars.custom.push({ key: '', value: '' }) }
function rmCustom(i) { vars.custom.splice(i, 1) }

const targetCount = computed(() => targets.value.split(/\s+/).filter(Boolean).length)
const selTmpl = computed(() => templates.value.find(t => t.id === templateId.value) || null)
const isAgent = computed(() => selTmpl.value?.kind === 'ai_agent')

// per-scan LLM profile override + reasoning dump (agent templates only)
const profiles = ref([])
const profileId = ref(null)
const showReasoning = ref(false)
const profileOpts = computed(() => profiles.value.map(p => ({ value: p.id, label: `${p.name} (${p.provider})` })))
const selProfile = computed(() => profiles.value.find(p => p.id === profileId.value) || null)
watch(templateId, () => { profileId.value = selTmpl.value?.llm_profile_id ?? null })

// progress flags the SERVER adds per kind (must mirror build_argv's _PROGRESS_FLAGS) so the preview is exact
const PROGRESS = { tool: ['--debug'], workflow: ['--steps', '--show-findings'], ai_agent: ['--debug'] }

function specTokens(spec) {
  const out = []
  for (const p of (spec?.params || [])) {
    if (!p.flag) continue
    out.push(p.flag)
    if (p.value !== '' && p.value != null) out.push(String(p.value))
  }
  for (const f of (spec?.flags || [])) out.push(String(f))
  return out
}
// a live "this is what will run" preview, like a command you'd type on your laptop
const preview = computed(() => {
  const t = selTmpl.value
  if (!t) return ''
  const sub = t.kind === 'workflow' ? ['workflow'] : t.kind === 'ai_agent' ? ['ai'] : []
  const parts = ['boxcutter', ...sub, t.spec?.name, '<target>', ...specTokens(t.spec)]
  if (isAgent.value) {
    const p = selProfile.value
    if (p) {
      parts.push('--provider', p.provider)
      if (p.model) parts.push('--model', p.model)
      if (p.proxy_url) parts.push('--llm-proxy-url', p.proxy_url)
    }
    const ctx = vars.context.trim() || t.context || ''
    if (ctx) parts.push('--context', q(ctx))
    if (vars.creds.trim()) parts.push('--creds', q(vars.creds.trim()))
    if (showReasoning.value) parts.push('--reasoning', '8000')
  }
  for (const c of vars.custom) {
    if (!c.key.trim()) continue
    parts.push(c.key.startsWith('-') ? c.key.trim() : '--' + c.key.trim())
    if (c.value !== '' && c.value != null) parts.push(q(String(c.value)))
  }
  for (const f of (PROGRESS[t.kind] || [])) parts.push(f)
  return parts.filter(Boolean).join(' ')
})
function q(s) { return /\s/.test(s) ? `"${s}"` : s }

function varsPayload() {
  const v = {}
  if (isAgent.value) {
    if (vars.context.trim()) v.context = vars.context.trim()
    if (vars.creds.trim()) v.creds = vars.creds.trim()
    if (profileId.value) v.llm_profile_id = profileId.value
    if (showReasoning.value) v.reasoning = 8000
  }
  const custom = vars.custom.filter(c => c.key.trim()).map(c => ({ key: c.key.trim(), value: c.value }))
  if (custom.length) v.custom = custom
  return v
}

async function load() {
  templates.value = await api.get('/templates')
  profiles.value = await api.get('/llm-profiles')
  if (!templateId.value && templates.value[0]) templateId.value = templates.value[0].id
}
async function create() {
  err.value = ''; busy.value = true
  try {
    let r
    if (file.value) {
      // large host lists: upload the file (server streams it) instead of posting a JSON array
      const fd = new FormData()
      fd.append('name', name.value)
      fd.append('template_id', String(templateId.value))
      fd.append('vars', JSON.stringify(varsPayload()))
      fd.append('file', file.value)
      r = await api.postForm('/scans/upload', fd)
    } else {
      r = await api.post('/scans', {
        name: name.value, template_id: templateId.value,
        targets: targets.value.split(/\s+/).filter(Boolean),
        vars: varsPayload(),
      })
    }
    router.push('/scans/' + r.id)
  } catch (e) { err.value = e.message } finally { busy.value = false }
}
onMounted(load)
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center">
    <h1>New scan</h1>
    <router-link to="/scans" class="btn ghost">← Scans</router-link>
  </div>

  <div class="split">
    <div class="card">
      <h2>Scan</h2>
      <div class="formgrid">
        <div>
          <label>Name</label>
          <input v-model="name" placeholder="Acme external" @keyup.enter="create" />
        </div>
        <div>
          <label>Template</label>
          <TemplatePicker v-model="templateId" :templates="templates" />
          <div v-if="selTmpl?.description" class="muted" style="font-size:12.5px;margin-top:6px;line-height:1.4">
            {{ selTmpl.description }}</div>
        </div>
      </div>

      <label>Targets (one per line or space separated)
        <span class="muted">— {{ targetCount }} asset(s)</span></label>
      <textarea v-model="targets" rows="10" :disabled="!!file"
        placeholder="example.com&#10;https://api.example.com&#10;10.0.0.0/24"></textarea>

      <label style="margin-top:12px">…or upload a host list <span class="muted">— one per line; blank lines and
        # comments ignored. Use this for very large lists (100k–millions).</span></label>
      <div v-if="!file" class="row">
        <input type="file" accept=".txt,.csv,.list,text/plain" @change="onFile" />
      </div>
      <div v-else class="row" style="align-items:center;gap:8px">
        <span class="tag">📄 {{ file.name }}</span>
        <span class="muted" style="font-size:12px">{{ (file.size / 1048576).toFixed(2) }} MB — streamed on upload</span>
        <button class="ghost sm" @click="clearFile">Remove</button>
      </div>

      <p v-if="err" class="err">{{ err }}</p>
      <p v-if="!templates.length" class="muted">No templates yet —
        <router-link to="/templates">create one</router-link> first.</p>
      <button class="primary" style="margin-top:14px"
        :disabled="busy || !name || !templateId || (!targets && !file)"
        @click="create">{{ busy ? 'Starting…' : 'Start scan' }}</button>
    </div>

    <div class="card">
      <h2>Inputs <span v-if="selTmpl" class="tag" :class="'kind-' + selTmpl.kind">{{ selTmpl.kind }}</span></h2>

      <template v-if="isAgent">
        <p class="muted" style="margin-top:0">These values are specific to <b>this</b> scan / customer and are
          passed to the agent at run time — not stored on the shared template.</p>
        <label>LLM profile <span class="muted">— overrides the template's for this scan</span></label>
        <Select v-model="profileId" :options="profileOpts" placeholder="Use the template's profile" />
        <label style="display:flex;align-items:center;gap:8px;margin-top:12px;cursor:pointer">
          <input type="checkbox" v-model="showReasoning" style="width:auto" />
          Show the agent's reasoning — stream WHY it picks each tool into the live log
        </label>
        <label>Context (engagement / scope guidance)</label>
        <textarea v-model="vars.context" rows="3"
          :placeholder="selTmpl?.context || 'Staging env. Focus on auth & access control. In-scope: app.example.com'"></textarea>
        <label>Credentials (optional — used for authenticated testing)</label>
        <input v-model="vars.creds" placeholder="user:pass  or  token=…" />
      </template>
      <p v-else class="muted" style="margin-top:0">
        Tool &amp; workflow parameters come from the template. Add any <b>scan-specific</b> extras below.
      </p>

      <label style="margin-top:6px">Custom parameters (this scan)</label>
      <div v-for="(c, i) in vars.custom" :key="i" class="kvrow">
        <input v-model="c.key" placeholder="--flag or key" />
        <input v-model="c.value" placeholder="value (blank = boolean)" />
        <button class="danger ghost icon" title="Remove" @click="rmCustom(i)">✕</button>
      </div>
      <button class="tonal sm" @click="addCustom">+ Add parameter</button>

      <label style="margin-top:14px">Command preview</label>
      <pre class="cmd">{{ preview || 'Pick a template…' }}</pre>
      <p v-if="isAgent && selProfile" class="muted" style="font-size:12px">
        The API key for <b>{{ selProfile.name }}</b> is delivered as an env var at run time (never shown or logged).
        <span v-if="!selProfile.has_key" style="color:var(--bad)"> — ⚠ this profile has NO key set; the scan will fail with “an LLM is required”.</span>
      </p>
    </div>
  </div>
</template>
