<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'
import { ACCEPTS_LABEL, PRODUCES_LABEL } from '../util'

const router = useRouter()
const templates = ref([])
const q = ref('')
const loading = ref(true)

const mine = computed(() => templates.value.filter(t => !t.builtin && t.kind === 'pipeline'))
const presets = computed(() => templates.value.filter(t => !t.builtin && t.kind !== 'pipeline'))
const builtin = computed(() => {
  const s = q.value.trim().toLowerCase()
  return templates.value.filter(t => t.builtin && t.kind === 'pipeline' &&
    (!s || [t.title, t.description, t.category].join(' ').toLowerCase().includes(s)))
})
const CAT_ORDER = ['Websites', 'Environment', 'Discovery', 'APIs', 'Secrets', 'Web archive']
const builtinGroups = computed(() => {
  const by = {}
  for (const t of builtin.value) (by[t.category] = by[t.category] || []).push(t)
  return CAT_ORDER.filter(c => by[c]).map(c => ({ name: c, items: by[c] }))
})

async function load() {
  try { templates.value = await api.get('/templates') } finally { loading.value = false }
}
async function remove(t) {
  if (!confirm(`Delete "${t.title}"?`)) return
  try { await api.del('/templates/' + t.id); await load() } catch (e) { alert(e.message) }
}
async function duplicate(t) {
  try {
    const full = await api.get('/templates/' + t.id)
    const copy = await api.post('/templates', { title: t.title + ' (copy)', description: t.description,
      kind: 'pipeline', stages: full.spec.stages })
    router.push('/pipelines/' + copy.id)
  } catch (e) { alert(e.message) }
}
onMounted(load)
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center">
    <div>
      <h1 style="margin:0">Pipelines</h1>
      <div class="muted">Chain scan types: what one step finds (hostnames, URLs, …) becomes the targets of the next — every
        item a separate job, spread over all scanners.</div>
    </div>
    <router-link to="/pipelines/new" class="btn primary">+ New pipeline</router-link>
  </div>

  <h2 style="margin-top:22px">My pipelines</h2>
  <div v-if="!loading && !mine.length" class="card empty">
    <b>No pipelines yet.</b>
    <div class="muted">For example: <i>Find subdomains</i> → <i>httpx</i> → <i>Nuclei on each live site</i>. Pick the first
      step, then what should run on its results.</div>
    <router-link to="/pipelines/new" class="btn primary" style="margin-top:10px">Build a pipeline</router-link>
  </div>
  <div class="grid">
    <div v-for="t in mine" :key="t.id" class="card pcard">
      <div class="row" style="justify-content:space-between"><b>{{ t.title }}</b><span class="muted">{{ t.steps }} steps</span></div>
      <div class="muted desc">{{ t.description || 'needs ' + (ACCEPTS_LABEL[t.accepts] || t.accepts) + ' · gives ' + (PRODUCES_LABEL[t.produces] || t.produces) }}</div>
      <div class="row acts">
        <router-link :to="'/scans/new?template=' + t.id" class="btn sm primary">Scan</router-link>
        <router-link :to="'/pipelines/' + t.id" class="btn sm ghost">Edit</router-link>
        <button class="sm ghost" @click="duplicate(t)">Duplicate</button>
        <button class="sm ghost danger" @click="remove(t)">Delete</button>
      </div>
    </div>
  </div>

  <template v-if="presets.length">
    <h2 style="margin-top:22px">My presets</h2>
    <div class="grid">
      <div v-for="t in presets" :key="t.id" class="card pcard">
        <b>{{ t.title }}</b>
        <div class="muted desc">{{ t.spec.base }} {{ (t.spec.params || []).map(p => p.flag + ' ' + p.value).join(' ') }}</div>
        <div class="row acts">
          <router-link :to="'/scans/new?template=' + t.id" class="btn sm primary">Scan</router-link>
          <button class="sm ghost danger" @click="remove(t)">Delete</button>
        </div>
      </div>
    </div>
  </template>

  <div class="row" style="justify-content:space-between;margin-top:26px">
    <div>
      <h2 style="margin:0">Built-in distributed workflows</h2>
      <div class="muted" style="font-size:12.5px">Every bundled workflow that loops over hosts or URLs, rebuilt as a
        pipeline so the work spreads over all scanners. Also available from New scan via “Distribute across scanners”.</div>
    </div>
    <input v-model="q" placeholder="filter…" style="max-width:220px" />
  </div>
  <div v-for="g in builtinGroups" :key="g.name">
    <div class="cat">{{ g.name }}</div>
    <div class="grid">
      <div v-for="t in g.items" :key="t.id" class="card pcard">
        <div class="row" style="justify-content:space-between"><b>{{ t.title }}</b><span class="muted">{{ t.steps }} steps</span></div>
        <div class="muted desc">{{ t.description }}</div>
        <div class="row acts">
          <router-link :to="'/scans/new?template=' + t.id" class="btn sm primary">Scan</router-link>
          <router-link :to="'/pipelines/' + t.id" class="btn sm ghost">View steps</router-link>
          <button class="sm ghost" @click="duplicate(t)">Duplicate &amp; edit</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.empty { text-align: center; padding: 28px; margin-bottom: 12px; }
.pcard { display: flex; flex-direction: column; gap: 8px; }
.desc { font-size: 12.5px; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
.acts { margin-top: auto; gap: 6px; }
.cat { margin: 16px 0 8px; font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--on-surface-variant); }
</style>
