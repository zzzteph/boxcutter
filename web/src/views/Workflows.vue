<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'
import { ACCEPTS_LABEL, PRODUCES_LABEL } from '../util'

const router = useRouter()
const templates = ref([])
const q = ref('')
const loading = ref(true)
const byId = computed(() => Object.fromEntries(templates.value.map(t => [t.id, t])))
const match = (t) => { const s = q.value.trim().toLowerCase(); return !s || [t.title, t.description, t.category].join(' ').toLowerCase().includes(s) }
const mine = computed(() => templates.value.filter(t => !t.builtin && t.kind === 'pipeline' && match(t)))
const CATS = ['Websites', 'Environment', 'Discovery', 'APIs', 'Secrets', 'Web archive']
// the "-external" twins (liveless after httpx) are listed on their base workflow's card, not as cards of their own
const isTwin = (t) => String(t.variant_of || '').endsWith('-distributed')
const twinOf = computed(() => Object.fromEntries(templates.value.filter(isTwin).map(t => [t.variant_of, t])))
const builtin = computed(() => CATS.map(c => ({ name: c, items: templates.value.filter(t => t.builtin && t.kind === 'pipeline'
  && !isTwin(t) && t.category === c && match(t)) })).filter(g => g.items.length))

// "subfinder → dnsx → httpx → nuclei ×5 …" - the step titles in order, repeats folded
function chain(t) {
  const names = (t.spec.stages || []).map(s => byId.value[s.template_id] || {})
    .map(x => (x.kind === 'merge' ? '⇉' : (x.title || '?').split(' — ')[0]))
  const out = []
  for (const n of names) {
    const last = out[out.length - 1]
    if (last && last.n === n) last.c++
    else out.push({ n, c: 1 })
  }
  const txt = out.map(x => x.c > 1 ? `${x.n} ×${x.c}` : x.n)
  return txt.slice(0, 6).join(' → ') + (txt.length > 6 ? ` → … (+${txt.length - 6})` : '')
}
async function remove(t) {
  if (!confirm(`Delete the workflow "${t.title}"?`)) return
  try { await api.del('/templates/' + t.id); templates.value = await api.get('/templates') } catch (e) { alert(e.message) }
}
onMounted(async () => { try { templates.value = await api.get('/templates') } finally { loading.value = false } })
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center">
    <div>
      <h1 style="margin:0">Workflows</h1>
      <div class="muted">A workflow is a graph of steps. Every step runs once per item it receives — each run a separate job
        on any scanner — and hands what it finds to the next steps.</div>
    </div>
    <div class="row" style="gap:8px">
      <input v-model="q" placeholder="filter…" style="max-width:200px" />
      <router-link to="/workflows/new" class="btn primary">+ New workflow</router-link>
    </div>
  </div>

  <h2 style="margin-top:22px">My workflows</h2>
  <div v-if="!loading && !mine.length && !q" class="card empty">
    <b>You haven't built a workflow yet.</b>
    <div class="muted">Open the builder, add <i>Find subdomains</i>, then <i>httpx</i>, then <i>nuclei</i> — and wire them
      left to right. Or duplicate a built-in one below and change it.</div>
    <router-link to="/workflows/new" class="btn primary" style="margin-top:10px">Open the workflow builder</router-link>
  </div>
  <div class="grid">
    <div v-for="t in mine" :key="t.id" class="card wcard">
      <div class="row" style="justify-content:space-between;flex-wrap:nowrap"><b>{{ t.title }}</b><span class="muted nw">{{ t.steps }} steps</span></div>
      <div class="chain">{{ chain(t) }}</div>
      <div class="muted io">needs {{ ACCEPTS_LABEL[t.accepts] || t.accepts }} · gives {{ PRODUCES_LABEL[t.produces] || t.produces }}</div>
      <div class="row acts">
        <router-link :to="'/workflows/' + t.id" class="btn sm">Edit</router-link>
        <router-link :to="'/scans/new?template=' + t.id" class="btn sm primary">Scan</router-link>
        <span class="spacer" />
        <button class="sm ghost danger" @click="remove(t)">Delete</button>
      </div>
    </div>
  </div>

  <h2 style="margin-top:26px">Built-in workflows</h2>
  <div class="muted" style="font-size:12.5px">Every bundled scan template that loops over hosts or URLs, rebuilt as a
    workflow of single tools so its work spreads over all scanners — every box it runs is on its graph. Read-only — duplicate one to change it.</div>
  <div v-for="g in builtin" :key="g.name">
    <div class="cat">{{ g.name }}</div>
    <div class="grid">
      <div v-for="t in g.items" :key="t.id" class="card wcard">
        <div class="row" style="justify-content:space-between;flex-wrap:nowrap"><b>{{ t.title }}</b><span class="muted nw">{{ t.steps }} steps</span></div>
        <div class="chain">{{ chain(t) }}</div>
        <div class="muted io">needs {{ ACCEPTS_LABEL[t.accepts] || t.accepts }} · gives {{ PRODUCES_LABEL[t.produces] || t.produces }}</div>
        <div v-if="twinOf[t.name]" class="twin">🌐 Also as <router-link :to="'/workflows/' + twinOf[t.name].id">internet-reachable only</router-link>
          <span class="muted">— a liveless check {{ (twinOf[t.name].spec.stages || []).some(s => (byId[s.template_id] || {}).name === 'httpx') ? 'after httpx' : 'on the targets first' }}</span></div>
        <div class="row acts">
          <router-link :to="'/workflows/' + t.id" class="btn sm">Open</router-link>
          <router-link :to="'/scans/new?template=' + t.id" class="btn sm primary">Scan</router-link>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.empty { text-align: center; padding: 28px; margin-bottom: 12px; }
.wcard { display: flex; flex-direction: column; gap: 8px; }
.chain { font: 12px/1.5 var(--mono); color: var(--accent-ink); }
.io { font-size: 12px; }
.nw { white-space: nowrap; font-size: 12.5px; }
.acts { margin-top: auto; gap: 6px; }
.spacer { flex: 1; }
.twin { font-size: 12px; }
.cat { margin: 16px 0 8px; font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--on-surface-variant); }
</style>
