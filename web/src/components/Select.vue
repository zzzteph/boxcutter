<script setup>
// A styled dropdown that replaces the native <select> (whose open list the OS renders, ignoring our theme).
// Options: array of strings, or {value, label, disabled?}. Full width by default; pass `auto` for filters.
import { ref, computed, onMounted, onUnmounted } from 'vue'

const props = defineProps({
  modelValue: { default: null },
  options: { type: Array, default: () => [] },
  placeholder: { type: String, default: 'Select…' },
  disabled: { type: Boolean, default: false },
  auto: { type: Boolean, default: false },        // shrink-to-content (filters) vs full width (form fields)
  right: { type: Boolean, default: false },       // align the panel to the right edge
})
const emit = defineEmits(['update:modelValue', 'change'])

const open = ref(false)
const root = ref(null)
const norm = computed(() => props.options.map(o => (o && typeof o === 'object' ? o : { value: o, label: String(o) })))
const current = computed(() => norm.value.find(o => o.value === props.modelValue))
const shown = computed(() => (current.value ? current.value.label : props.placeholder))

function pick(o) { if (o.disabled) return; emit('update:modelValue', o.value); emit('change', o.value); open.value = false }
function toggle() { if (!props.disabled) open.value = !open.value }
function onDoc(e) { if (root.value && !root.value.contains(e.target)) open.value = false }
function onKey(e) { if (e.key === 'Escape') open.value = false }
onMounted(() => { document.addEventListener('click', onDoc); document.addEventListener('keydown', onKey) })
onUnmounted(() => { document.removeEventListener('click', onDoc); document.removeEventListener('keydown', onKey) })
</script>

<template>
  <div class="sel" :class="{ auto, disabled }" ref="root">
    <button type="button" class="sel-btn" :class="{ open }" :disabled="disabled" @click.stop="toggle">
      <span :class="{ 'sel-ph': !current }">{{ shown }}</span>
      <span class="sel-caret" aria-hidden="true"></span>
    </button>
    <div v-if="open" class="menu-panel" :class="{ right }">
      <button v-for="o in norm" :key="String(o.value)" type="button" class="menu-item"
        :class="{ on: o.value === modelValue, disabled: o.disabled }" @click.stop="pick(o)">
        {{ o.label }}
      </button>
      <div v-if="!norm.length" class="menu-empty">No options</div>
    </div>
  </div>
</template>
