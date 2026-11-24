<script setup>
// Pick WHAT to run, as cards instead of a long dropdown, in two tabs:
//   Workflows - graphs of steps; every step's results become separate jobs for the next step, spread over all
//               scanners (the built-in ones + yours)
//   Templates - one job per target: a bundled scan template or a single tool
// Only what fits the input is shown (a domain, a URL, an IP, ...), with a short "Recommended" row first, groups by
// purpose and a search box.
import { ref, computed, watch } from 'vue'
import { fits, ACCEPTS_LABEL, PRODUCES_LABEL, DEPTH_LABEL, KIND_LABEL } from '../util'

const props = defineProps({
  templates: { type: Array, default: () => [] },
  kind: { type: String, default: '' },
  modelValue: { default: null },
})
const emit = defineEmits(['update:modelValue'])

const tab = ref('workflows')
const q = ref('')
const showAll = ref(false)
const showTools = ref(false)

const RECOMMENDED = {
  domain: ['env-scan', 'recon-http', 'env-nuclei', 'env-takeover'],
  url: ['web-full', 'web-nuclei', 'spa-scan', 'web-crawl'],
  endpoint: ['endpoint-scan', 'web-nuclei', 'fuzz'],
  ip: ['web-full', 'nuclei'],
  network: ['ip-discover', 'ping-scan'],
  '': ['web-full', 'env-scan', 'recon-http', 'web-nuclei'],
}
const GROUP_ORDER = ['Websites', 'Environment', 'Discovery', 'APIs', 'Secrets', 'Web archive', 'Network', 'Custom']

const isWf = (t) => t.kind === 'pipeline'
const pool = computed(() => props.templates.filter(t => (tab.value === 'workflows' ? isWf(t) : !isWf(t))))
const matches = computed(() => {
  const s = q.value.trim().toLowerCase()
  return pool.value.filter(t => (showAll.value || fits(t, props.kind)) &&
    (!s || [t.title, t.name, t.description, t.category].join(' ').toLowerCase().includes(s)))
})
const recommended = computed(() => {
  if (q.value.trim()) return []
  const names = RECOMMENDED[props.kind] || []
  const wanted = tab.value === 'workflows' ? names.map(n => n + '-distributed') : names
  return wanted.map(n => matches.value.find(t => t.name === n)).filter(Boolean)
})
const groups = computed(() => {
  const rec = new Set(recommended.value.map(t => t.id))
  const by = {}
  for (const t of matches.value) {
    if (rec.has(t.id) || t.category === 'Tools') continue
    const g = t.builtin ? t.category : 'Custom'
    ;(by[g] = by[g] || []).push(t)
  }
  return GROUP_ORDER.filter(g => by[g]).map(g => ({
    name: g === 'Custom' ? (tab.value === 'workflows' ? 'My workflows' : 'My presets') : g, items: by[g] }))
})
const tools = computed(() => matches.value.filter(t => t.category === 'Tools' && !recommended.value.some(r => r.id === t.id)))
const hidden = computed(() => showAll.value ? 0 : pool.value.filter(t => !fits(t, props.kind)).length)
const counts = computed(() => ({
  workflows: props.templates.filter(t => isWf(t) && fits(t, props.kind)).length,
  templates: props.templates.filter(t => !isWf(t) && fits(t, props.kind)).length,
}))
const selected = computed(() => props.templates.find(t => t.id === props.modelValue) || null)

function pick(t) { emit('update:modelValue', t.id) }
// open the right tab for a pre-selected template
watch(selected, (t) => {
  if (!t) return
  tab.value = isWf(t) ? 'workflows' : 'templates'
  if (t.category === 'Tools') showTools.value = true
}, { immediate: true })
</script>

<template>
  <div class="stp">
    <div class="tabs2">
      <button type="button" :class="{ on: tab === 'workflows' }" @click="tab = 'workflows'">
        <b>Workflows</b> <span class="cnt">{{ counts.workflows }}</span>
        <span class="sub">multi-step · work spreads over all scanners</span></button>
      <button type="button" :class="{ on: tab === 'templates' }" @click="tab = 'templates'">
        <b>Templates</b> <span class="cnt">{{ counts.templates }}</span>
        <span class="sub">one job per target</span></button>
    </div>

    <div class="stp-bar">
      <input v-model="q" :placeholder="tab === 'workflows' ? 'Search workflows…' : 'Search templates and tools…'" class="stp-search" />
      <label v-if="kind" class="stp-all"><input type="checkbox" v-model="showAll" /> include ones that don't fit {{ KIND_LABEL[kind] || kind }}</label>
    </div>

    <template v-if="recommended.length">
      <div class="stp-h">Recommended<span v-if="kind"> for {{ KIND_LABEL[kind] || kind }}</span></div>
      <div class="stp-grid">
        <button v-for="t in recommended" :key="t.id" type="button" class="stp-card rec" :class="{ on: modelValue === t.id }" @click="pick(t)">
          <div class="stp-top"><b>{{ t.title }}</b><span class="stp-depth" :class="'d-' + t.depth">{{ DEPTH_LABEL[t.depth] }}</span></div>
          <div class="stp-desc">{{ t.description }}</div>
          <div class="stp-io">needs {{ ACCEPTS_LABEL[t.accepts] || t.accepts }} · gives {{ PRODUCES_LABEL[t.produces] || t.produces }}
            <span v-if="isWf(t)" class="stp-steps">· {{ t.steps }} steps</span></div>
        </button>
      </div>
    </template>

    <div v-for="g in groups" :key="g.name">
      <div class="stp-h">{{ g.name }}</div>
      <div class="stp-grid">
        <button v-for="t in g.items" :key="t.id" type="button" class="stp-card" :class="{ on: modelValue === t.id }" @click="pick(t)">
          <div class="stp-top"><b>{{ t.title }}</b><span class="stp-depth" :class="'d-' + t.depth">{{ DEPTH_LABEL[t.depth] }}</span></div>
          <div class="stp-desc">{{ t.description }}</div>
          <div class="stp-io">needs {{ ACCEPTS_LABEL[t.accepts] || t.accepts }} · gives {{ PRODUCES_LABEL[t.produces] || t.produces }}
            <span v-if="isWf(t)" class="stp-steps">· {{ t.steps }} steps</span></div>
        </button>
      </div>
    </div>

    <div v-if="tools.length" class="stp-tools">
      <button type="button" class="ghost sm" @click="showTools = !showTools">{{ showTools ? '▾' : '▸' }} Single tools ({{ tools.length }})</button>
      <div v-if="showTools" class="stp-grid tight">
        <button v-for="t in tools" :key="t.id" type="button" class="stp-card sm" :class="{ on: modelValue === t.id }" @click="pick(t)">
          <div class="stp-top"><b>{{ t.title }}</b></div>
          <div class="stp-desc">{{ t.description }}</div>
          <div class="stp-io">needs {{ ACCEPTS_LABEL[t.accepts] || t.accepts }} · gives {{ PRODUCES_LABEL[t.produces] || t.produces }}</div>
        </button>
      </div>
    </div>

    <div v-if="!matches.length" class="muted stp-empty">Nothing matches<span v-if="q"> “{{ q }}”</span>.
      <a v-if="hidden" href="#" @click.prevent="showAll = true">Show all</a></div>
    <div v-else-if="hidden && !q" class="muted stp-hint">{{ hidden }} more need a different kind of target.
      <a href="#" @click.prevent="showAll = true">Show them</a></div>
  </div>
</template>

<style scoped>
.tabs2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px; }
.tabs2 button { all: unset; box-sizing: border-box; cursor: pointer; padding: 10px 14px; border-radius: var(--radius-s);
  border: 1px solid var(--outline-variant); background: var(--sc-low); display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px; }
.tabs2 button:hover { border-color: var(--outline); }
.tabs2 button.on { border-color: var(--accent); background: var(--primary-container); }
.tabs2 b { font-weight: 600; color: var(--on-surface); }
.tabs2 .on b { color: var(--accent-ink); }
.tabs2 .cnt { font-size: 12px; color: var(--outline); }
.tabs2 .sub { flex-basis: 100%; font-size: 12px; color: var(--on-surface-variant); }
.stp-bar { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }
.stp-search { max-width: 420px; }
.stp-all { display: inline-flex; align-items: center; gap: 6px; margin: 0; font-weight: 400; cursor: pointer; }
.stp-all input { width: auto; }
.stp-h { margin: 16px 0 8px; font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--on-surface-variant); }
.stp-grid { display: grid; gap: 10px; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); }
.stp-grid.tight { grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); margin-top: 8px; }
.stp-card { all: unset; box-sizing: border-box; cursor: pointer; display: flex; flex-direction: column; gap: 6px;
  padding: 12px 14px; border-radius: var(--radius-s); background: var(--sc-low); border: 1px solid var(--outline-variant);
  transition: border-color .12s, background .12s, box-shadow .12s; min-height: 108px; }
.stp-card.sm { min-height: 0; }
.stp-card:hover { border-color: var(--outline); background: var(--sc); }
.stp-card:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.stp-card.on { border-color: var(--accent); background: var(--primary-container); box-shadow: var(--glow); }
.stp-card.rec { border-left: 3px solid var(--accent); }
.stp-top { display: flex; justify-content: space-between; gap: 8px; align-items: baseline; }
.stp-top b { font-weight: 600; color: var(--on-surface); }
.stp-desc { font-size: 12.5px; color: var(--on-surface-variant); line-height: 1.45; display: -webkit-box; -webkit-line-clamp: 3;
  -webkit-box-orient: vertical; overflow: hidden; }
.stp-card.on .stp-desc { -webkit-line-clamp: unset; }
.stp-io { margin-top: auto; font-size: 11.5px; color: var(--outline); }
.stp-steps { color: var(--accent-ink); }
.stp-depth { font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; flex: none; }
.d-quick { color: var(--ok); } .d-standard { color: var(--accent-ink); } .d-deep { color: var(--high); }
.stp-tools { margin-top: 16px; }
.stp-empty, .stp-hint { margin-top: 12px; font-size: 13px; }
@media (max-width: 640px) { .tabs2 { grid-template-columns: 1fr; } }
</style>
