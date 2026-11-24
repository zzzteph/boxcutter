<script setup>
// Pick WHAT to run, as cards instead of a long dropdown:
//  * only the scan types that fit the input (a domain, a URL, an IP, ... or what a previous pipeline step makes),
//  * a short "Recommended" row first, then groups by purpose, single tools folded away under "Advanced",
//  * a search box over names and descriptions,
//  * for built-in workflows that have one, a switch to run the DISTRIBUTED version (spread over every scanner).
// v-model = the chosen base template id; v-model:distributed = whether to use its distributed variant.
import { ref, computed, watch } from 'vue'
import { fits, ACCEPTS_LABEL, PRODUCES_LABEL, DEPTH_LABEL, KIND_LABEL } from '../util'

const props = defineProps({
  templates: { type: Array, default: () => [] },
  kind: { type: String, default: '' },              // domain|url|endpoint|ip|network|hosts|urls|items|''
  modelValue: { default: null },
  distributed: { type: Boolean, default: false },
  allowDistributed: { type: Boolean, default: true },
  exclude: { type: Array, default: () => [] },      // template ids to hide (e.g. the pipeline being edited)
})
const emit = defineEmits(['update:modelValue', 'update:distributed'])

const q = ref('')
const showAll = ref(false)
const showTools = ref(false)

const RECOMMENDED = {
  domain: ['env-scan', 'recon-http', 'env-nuclei', 'env-takeover'],
  url: ['web-full', 'web-nuclei', 'spa-scan', 'web-crawl'],
  endpoint: ['endpoint-scan', 'web-nuclei', 'fuzz'],
  ip: ['web-full', 'nuclei'],
  network: ['ip-discover'],
  hosts: ['httpx', 'web-full', 'nuclei'],
  urls: ['web-nuclei', 'web-scan', 'endpoint-scan'],
  items: ['web-nuclei', 'endpoint-scan', 'scan-secrets'],
}
const GROUP_ORDER = ['Websites', 'Environment', 'Discovery', 'APIs', 'Secrets', 'Web archive', 'Network', 'Custom']

const variants = computed(() => {
  const m = {}
  for (const t of props.templates) if (t.kind === 'pipeline' && t.builtin && t.variant_of) m[t.variant_of] = t
  return m
})
// the cards: everything except the built-in distributed variants (reached through the switch on their workflow)
const base = computed(() => props.templates.filter(t =>
  !(t.kind === 'pipeline' && t.builtin) && !props.exclude.includes(t.id)))
const matches = computed(() => {
  const s = q.value.trim().toLowerCase()
  return base.value.filter(t => (showAll.value || fits(t, props.kind)) &&
    (!s || [t.title, t.name, t.description, t.category].join(' ').toLowerCase().includes(s)))
})
const recommended = computed(() => {
  if (q.value.trim()) return []
  const names = RECOMMENDED[props.kind] || (props.kind ? [] : ['web-full', 'env-scan', 'recon-http', 'web-nuclei'])
  return names.map(n => matches.value.find(t => t.name === n)).filter(Boolean)
})
const groups = computed(() => {
  const rec = new Set(recommended.value.map(t => t.id))
  const by = {}
  for (const t of matches.value) {
    if (rec.has(t.id) || t.category === 'Tools') continue
    const g = t.builtin ? t.category : 'Custom'
    ;(by[g] = by[g] || []).push(t)
  }
  return GROUP_ORDER.filter(g => by[g]).map(g => ({ name: g === 'Custom' ? 'My pipelines & presets' : g, items: by[g] }))
})
const tools = computed(() => matches.value.filter(t => t.category === 'Tools' && !recommended.value.some(r => r.id === t.id)))
const hiddenByKind = computed(() => showAll.value ? 0 : base.value.filter(t => !fits(t, props.kind)).length)

const selected = computed(() => props.templates.find(t => t.id === props.modelValue) || null)
const selVariant = computed(() => selected.value ? variants.value[selected.value.name] : null)

function pick(t) {
  emit('update:modelValue', t.id)
  if (!variants.value[t.name]) emit('update:distributed', false)
}
// open the tools group automatically when the chosen template lives there
watch(() => props.modelValue, () => { if (selected.value && selected.value.category === 'Tools') showTools.value = true },
  { immediate: true })
</script>

<template>
  <div class="stp">
    <div class="stp-bar">
      <input v-model="q" placeholder="Search scan types… (e.g. nuclei, secrets, api)" class="stp-search" />
      <label v-if="kind" class="stp-all"><input type="checkbox" v-model="showAll" /> show types that don't fit {{ KIND_LABEL[kind] || kind }}</label>
    </div>

    <div v-if="allowDistributed && selected && selVariant" class="stp-switch top" @click="emit('update:distributed', !distributed)">
      <span class="sw" :class="{ on: distributed }"><span></span></span>
      <div>
        <b>Distribute across scanners</b>
        <div class="muted">Runs “{{ selected.title }}” as a {{ selVariant.steps }}-step pipeline: every host / URL it finds
          becomes its own job, shared by all connected scanners. Same checks, much faster with several scanners.</div>
      </div>
    </div>
    <template v-if="recommended.length">
      <div class="stp-h">Recommended<span v-if="kind"> for {{ KIND_LABEL[kind] || kind }}</span></div>
      <div class="stp-grid">
        <button v-for="t in recommended" :key="t.id" type="button" class="stp-card rec"
                :class="{ on: modelValue === t.id }" @click="pick(t)">
          <div class="stp-top"><b>{{ t.title }}</b><span class="stp-depth" :class="'d-' + t.depth">{{ DEPTH_LABEL[t.depth] }}</span></div>
          <div class="stp-desc">{{ t.description }}</div>
          <div class="stp-io">needs {{ ACCEPTS_LABEL[t.accepts] || t.accepts }} · gives {{ PRODUCES_LABEL[t.produces] || t.produces }}
            <span v-if="variants[t.name]" class="stp-dist" title="Has a distributed version">⇉ distributable</span></div>
        </button>
      </div>
    </template>

    <div v-for="g in groups" :key="g.name">
      <div class="stp-h">{{ g.name }}</div>
      <div class="stp-grid">
        <button v-for="t in g.items" :key="t.id" type="button" class="stp-card"
                :class="{ on: modelValue === t.id }" @click="pick(t)">
          <div class="stp-top"><b>{{ t.title }}</b><span class="stp-depth" :class="'d-' + t.depth">{{ DEPTH_LABEL[t.depth] }}</span></div>
          <div class="stp-desc">{{ t.description || (t.kind === 'pipeline' ? t.steps + '-step pipeline' : '') }}</div>
          <div class="stp-io">needs {{ ACCEPTS_LABEL[t.accepts] || t.accepts }} · gives {{ PRODUCES_LABEL[t.produces] || t.produces }}
            <span v-if="variants[t.name]" class="stp-dist">⇉ distributable</span>
            <span v-if="t.kind === 'pipeline'" class="stp-dist">⇉ pipeline · {{ t.steps }} steps</span></div>
        </button>
      </div>
    </div>

    <div v-if="tools.length" class="stp-tools">
      <button type="button" class="ghost sm" @click="showTools = !showTools">
        {{ showTools ? '▾' : '▸' }} Advanced: single tools ({{ tools.length }})</button>
      <div v-if="showTools" class="stp-grid tight">
        <button v-for="t in tools" :key="t.id" type="button" class="stp-card sm"
                :class="{ on: modelValue === t.id }" @click="pick(t)">
          <div class="stp-top"><b>{{ t.title }}</b></div>
          <div class="stp-desc">{{ t.description }}</div>
          <div class="stp-io">needs {{ ACCEPTS_LABEL[t.accepts] || t.accepts }} · gives {{ PRODUCES_LABEL[t.produces] || t.produces }}</div>
        </button>
      </div>
    </div>

    <div v-if="!matches.length" class="muted stp-empty">
      Nothing matches<span v-if="q"> “{{ q }}”</span>.
      <a v-if="hiddenByKind" href="#" @click.prevent="showAll = true">Show all {{ base.length }} scan types</a>
    </div>
    <div v-else-if="hiddenByKind && !q" class="muted stp-hint">{{ hiddenByKind }} scan types are hidden because they need a
      different kind of target. <a href="#" @click.prevent="showAll = true">Show them</a></div>

  </div>
</template>

<style scoped>
.stp-bar { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; margin-bottom: 4px; }
.stp-search { max-width: 420px; }
.stp-all { display: inline-flex; align-items: center; gap: 6px; margin: 0; font-weight: 400; cursor: pointer; }
.stp-all input { width: auto; }
.stp-h { margin: 16px 0 8px; font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase;
  color: var(--on-surface-variant); }
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
.stp-desc { font-size: 12.5px; color: var(--on-surface-variant); line-height: 1.45; display: -webkit-box;
  -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
.stp-card.on .stp-desc { -webkit-line-clamp: unset; }
.stp-io { margin-top: auto; font-size: 11.5px; color: var(--outline); }
.stp-dist { color: var(--accent-ink); margin-left: 6px; white-space: nowrap; }
.stp-depth { font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; flex: none; }
.d-quick { color: var(--ok); } .d-standard { color: var(--accent-ink); } .d-deep { color: var(--high); }
.stp-tools { margin-top: 16px; }
.stp-empty, .stp-hint { margin-top: 12px; font-size: 13px; }
.stp-switch { display: flex; gap: 12px; align-items: flex-start; margin-top: 12px; padding: 12px 14px; cursor: pointer;
  border-radius: var(--radius-s); background: var(--sc); border: 1px dashed var(--outline-variant); }
.stp-switch .muted { font-size: 12.5px; margin-top: 2px; }
.sw { flex: none; width: 38px; height: 22px; border-radius: 999px; background: var(--sc-highest); position: relative;
  transition: background .15s; margin-top: 2px; }
.sw span { position: absolute; top: 3px; left: 3px; width: 16px; height: 16px; border-radius: 50%; background: var(--on-surface-variant);
  transition: left .15s, background .15s; }
.sw.on { background: var(--primary-container); }
.sw.on span { left: 19px; background: var(--accent); }
</style>
