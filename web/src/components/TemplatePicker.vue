<script setup>
// A searchable, grouped template picker. A flat <Select> is unusable once there are dozens of templates,
// so this filters as you type, groups by kind (Tools / Workflows / AI agents), and shows each template's
// description so you can tell what you're picking. Arrow keys + Enter select; Escape / click-outside close.
import { ref, computed, nextTick, onMounted, onUnmounted } from 'vue'

const props = defineProps({
  modelValue: { default: null },
  templates: { type: Array, default: () => [] },
  placeholder: { type: String, default: 'Search templates…' },
})
const emit = defineEmits(['update:modelValue'])

const KIND_LABEL = { tool: 'Tool', workflow: 'Workflow', ai_agent: 'AI agent' }
const ORDER = [['tool', 'Tools'], ['workflow', 'Workflows'], ['ai_agent', 'AI agents']]

const open = ref(false)
const q = ref('')
const root = ref(null)
const box = ref(null)
const active = ref(0)                                   // index into the flattened, filtered list

const selected = computed(() => props.templates.find(t => t.id === props.modelValue) || null)

const groups = computed(() => {
  const term = q.value.trim().toLowerCase()
  const match = (t) => !term || [t.name, t.kind, t.spec?.name, t.description]
    .filter(Boolean).some(s => String(s).toLowerCase().includes(term))
  return ORDER.map(([k, label]) => ({ k, label, items: props.templates.filter(t => t.kind === k && match(t)) }))
    .filter(g => g.items.length)
})
// flat list in display order, so arrow keys move across group boundaries
const flat = computed(() => groups.value.flatMap(g => g.items))

function labelFor(t) { return KIND_LABEL[t?.kind] || t?.kind || '' }

async function show() {
  open.value = true; q.value = ''; active.value = Math.max(0, flat.value.findIndex(t => t.id === props.modelValue))
  await nextTick(); box.value?.focus()
}
function pick(t) { emit('update:modelValue', t.id); open.value = false }
function move(d) {
  const n = flat.value.length; if (!n) return
  active.value = (active.value + d + n) % n
  nextTick(() => root.value?.querySelector('.tp-item.active')?.scrollIntoView({ block: 'nearest' }))
}
function onKey(e) {
  if (!open.value) return
  if (e.key === 'ArrowDown') { e.preventDefault(); move(1) }
  else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1) }
  else if (e.key === 'Enter') { e.preventDefault(); const t = flat.value[active.value]; if (t) pick(t) }
  else if (e.key === 'Escape') { open.value = false }
}
function onDoc(e) { if (root.value && !root.value.contains(e.target)) open.value = false }
onMounted(() => document.addEventListener('click', onDoc))
onUnmounted(() => document.removeEventListener('click', onDoc))
</script>

<template>
  <div class="tp" ref="root">
    <button type="button" class="sel-btn tp-btn" :class="{ open }" @click.stop="open ? (open = false) : show()">
      <template v-if="selected">
        <span class="tp-cur">
          <span class="tp-name">{{ selected.name }}</span>
          <span class="tag sm" :class="'kind-' + selected.kind">{{ labelFor(selected) }}</span>
        </span>
      </template>
      <span v-else class="sel-ph">Select a template…</span>
      <span class="sel-caret" aria-hidden="true"></span>
    </button>

    <div v-if="open" class="menu-panel tp-panel" @click.stop>
      <input ref="box" v-model="q" class="tp-search" :placeholder="placeholder" @keydown="onKey" />
      <div class="tp-list">
        <template v-for="g in groups" :key="g.k">
          <div class="tp-group">{{ g.label }} <span class="muted">· {{ g.items.length }}</span></div>
          <button v-for="t in g.items" :key="t.id" type="button" class="tp-item"
            :class="{ on: t.id === modelValue, active: flat[active] && flat[active].id === t.id }"
            @click.stop="pick(t)" @mousemove="active = flat.findIndex(x => x.id === t.id)">
            <div class="tp-row">
              <span class="tp-name">{{ t.name }}</span>
              <code class="tp-spec">{{ t.spec?.name }}</code>
            </div>
            <div v-if="t.description" class="tp-desc">{{ t.description }}</div>
          </button>
        </template>
        <div v-if="!flat.length" class="menu-empty">No templates match “{{ q }}”.</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.tp { position: relative; width: 100%; }
.tp-btn { width: 100%; }
.tp-cur { display: inline-flex; align-items: center; gap: 8px; min-width: 0; }
.tp-name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tp-panel { padding: 0; max-height: min(60vh, 460px); display: flex; flex-direction: column; }
.tp-search {
  margin: 0; border: 0; border-bottom: 1px solid var(--line); border-radius: 0;
  background: var(--panel-2, var(--panel)); font-size: 14px; padding: 12px 14px;
}
.tp-search:focus { outline: none; box-shadow: none; }
.tp-list { overflow-y: auto; padding: 6px; }
.tp-group {
  font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted);
  padding: 10px 10px 4px; position: sticky; top: 0; background: var(--panel); z-index: 1;
}
.tp-item {
  display: block; width: 100%; text-align: left; border: 0; background: transparent; cursor: pointer;
  color: var(--fg); padding: 8px 10px; border-radius: 8px;
}
.tp-item.active { background: var(--hover, rgba(255, 255, 255, .06)); }
.tp-item.on { box-shadow: inset 0 0 0 1px var(--accent); }
.tp-row { display: flex; align-items: baseline; gap: 8px; }
.tp-row .tp-name { font-weight: 600; }
.tp-spec { font-size: 12px; color: var(--muted); margin-left: auto; }
.tp-desc { font-size: 12px; color: var(--muted); margin-top: 2px; line-height: 1.35; }
</style>
