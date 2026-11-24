<script setup>
// A cron schedule with a time zone: one-click presets, the raw 5-field expression for anything else, and a live
// check from the server - what it means in plain English and the next three runs.
import { ref, computed, watch, onMounted } from 'vue'
import { api } from '../api'
import { toDate } from '../util'

const props = defineProps({
  cron: { type: String, default: '0 3 * * *' },
  timezone: { type: String, default: '' },
})
const emit = defineEmits(['update:cron', 'update:timezone', 'valid'])

const PRESETS = [
  { label: 'Every hour', cron: '0 * * * *' },
  { label: 'Every 6 hours', cron: '0 */6 * * *' },
  { label: 'Daily at 03:00', cron: '0 3 * * *' },
  { label: 'Weekdays at 09:00', cron: '0 9 * * 1-5' },
  { label: 'Mondays at 03:00', cron: '0 3 * * 1' },
  { label: '1st of the month', cron: '0 3 1 * *' },
]
const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
const zones = (() => { try { return Intl.supportedValuesOf('timeZone') } catch { return ['UTC', browserTz] } })()
const expr = ref(props.cron)
const tz = ref(props.timezone || browserTz)
const info = ref({ ok: false, error: '', description: '', next: [] })

watch(() => props.cron, v => { if (v !== expr.value) expr.value = v })
watch(() => props.timezone, v => { if (v && v !== tz.value) tz.value = v })
let t = null
watch([expr, tz], () => {
  emit('update:cron', expr.value); emit('update:timezone', tz.value)
  clearTimeout(t)
  t = setTimeout(check, 250)
})
async function check() {
  try {
    info.value = await api.get(`/schedulers/cron-preview?expr=${encodeURIComponent(expr.value)}&tz=${encodeURIComponent(tz.value)}`)
  } catch (e) { info.value = { ok: false, error: e.message, next: [] } }
  emit('valid', !!info.value.ok, info.value.description || '')
}
const fmt = computed(() => new Intl.DateTimeFormat(undefined, { timeZone: tz.value, weekday: 'short', day: 'numeric',
  month: 'short', hour: '2-digit', minute: '2-digit' }))
function when(iso) { try { return fmt.value.format(toDate(iso)) } catch { return iso } }
onMounted(() => { emit('update:timezone', tz.value); check() })
</script>

<template>
  <div class="cron">
    <div class="presets">
      <button v-for="p in PRESETS" :key="p.cron" type="button" class="pre" :class="{ on: expr.trim() === p.cron }"
              @click="expr = p.cron">{{ p.label }}</button>
    </div>
    <div class="fields">
      <div class="f-expr">
        <label>Cron expression</label>
        <input v-model="expr" class="mono" spellcheck="false" placeholder="minute hour day month weekday" />
        <div class="fhint">minute · hour · day of month · month · day of week</div>
      </div>
      <div class="f-tz">
        <label>Time zone</label>
        <input v-model="tz" list="bc-tz-list" spellcheck="false" />
        <datalist id="bc-tz-list"><option v-for="z in zones" :key="z" :value="z" /></datalist>
      </div>
    </div>
    <div class="preview" :class="{ bad: !info.ok }">
      <template v-if="info.ok">
        <b>✓ {{ info.description }}</b>
        <span class="muted"> · next: {{ info.next.map(when).join(', ') }}</span>
      </template>
      <template v-else>✗ {{ info.error || 'checking…' }}</template>
    </div>
  </div>
</template>

<style scoped>
.presets { display: flex; flex-wrap: wrap; gap: 6px; }
.pre { height: 32px; padding: 0 12px; text-transform: none; letter-spacing: 0; font-weight: 500; font-size: 12.5px;
  border-color: var(--outline-variant); color: var(--on-surface-variant); }
.pre.on { background: var(--primary-container); color: var(--accent-ink); border-color: var(--accent); }
.fields { display: grid; grid-template-columns: minmax(220px, 1fr) minmax(200px, 280px); gap: 12px; }
.mono { font-family: var(--mono); letter-spacing: .04em; }
.fhint { font-size: 11.5px; color: var(--outline); margin-top: 4px; font-family: var(--mono); }
.preview { margin-top: 10px; font-size: 13px; color: var(--ok); }
.preview .muted { color: var(--on-surface-variant); }
.preview.bad { color: var(--error); }
@media (max-width: 640px) { .fields { grid-template-columns: 1fr; } }
</style>
