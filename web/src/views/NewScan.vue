<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'
import TemplatePicker from '../components/TemplatePicker.vue'

const router = useRouter()
const templates = ref([])
const name = ref('')
const targets = ref('')
const templateId = ref(null)
const err = ref('')
const busy = ref(false)

// scan-specific inputs (used mainly by AI-agent templates): context, creds, and arbitrary custom params
const vars = reactive({ context: '', creds: '', custom: [] })
function addCustom() { vars.custom.push({ key: '', value: '' }) }
function rmCustom(i) { vars.custom.splice(i, 1) }

const targetCount = computed(() => targets.value.split(/\s+/).filter(Boolean).length)
const selTmpl = computed(() => templates.value.find(t => t.id === templateId.value) || null)
const isAgent = computed(() => selTmpl.value?.kind === 'ai_agent')

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
  const parts = ['boxcutter', ...sub, t.spec?.name, ...specTokens(t.spec)]
  if (isAgent.value) {
    const ctx = vars.context.trim() || t.context || ''
    if (ctx) parts.push('--context', q(ctx))
    if (vars.creds.trim()) parts.push('--creds', q(vars.creds.trim()))
  }
  for (const c of vars.custom) {
    if (!c.key.trim()) continue
    parts.push(c.key.startsWith('-') ? c.key.trim() : '--' + c.key.trim())
    if (c.value !== '' && c.value != null) parts.push(q(String(c.value)))
  }
  return parts.filter(Boolean).join(' ')
})
function q(s) { return /\s/.test(s) ? `"${s}"` : s }

function varsPayload() {
  const v = {}
  if (isAgent.value) {
    if (vars.context.trim()) v.context = vars.context.trim()
    if (vars.creds.trim()) v.creds = vars.creds.trim()
  }
  const custom = vars.custom.filter(c => c.key.trim()).map(c => ({ key: c.key.trim(), value: c.value }))
  if (custom.length) v.custom = custom
  return v
}

async function load() {
  templates.value = await api.get('/templates')
  if (!templateId.value && templates.value[0]) templateId.value = templates.value[0].id
}
async function create() {
  err.value = ''; busy.value = true
  try {
    const r = await api.post('/scans', {
      name: name.value, template_id: templateId.value,
      targets: targets.value.split(/\s+/).filter(Boolean),
      vars: varsPayload(),
    })
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
      <textarea v-model="targets" rows="10"
        placeholder="example.com&#10;https://api.example.com&#10;10.0.0.0/24"></textarea>

      <p v-if="err" class="err">{{ err }}</p>
      <p v-if="!templates.length" class="muted">No templates yet —
        <router-link to="/templates">create one</router-link> first.</p>
      <button class="primary" style="margin-top:14px" :disabled="busy || !name || !targets || !templateId"
        @click="create">{{ busy ? 'Starting…' : 'Start scan' }}</button>
    </div>

    <div class="card">
      <h2>Inputs <span v-if="selTmpl" class="tag" :class="'kind-' + selTmpl.kind">{{ selTmpl.kind }}</span></h2>

      <template v-if="isAgent">
        <p class="muted" style="margin-top:0">These values are specific to <b>this</b> scan / customer and are
          passed to the agent at run time — not stored on the shared template.</p>
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
    </div>
  </div>
</template>
