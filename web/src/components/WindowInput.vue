<script setup>
// Scan window (business hours): the hours of the week a scan may run, in one time zone. Presets for the usual
// cases, and a 7 x 24 grid to paint any other pattern (click or drag across hours; click a day to toggle it).
// v-model: null (any time) or {tz, grid: 7 strings of 24 '0'/'1', Monday first} - what the server stores.
import { ref, computed, watch } from 'vue'

const props = defineProps({ modelValue: { type: Object, default: null } })
const emit = defineEmits(['update:modelValue'])

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
const zones = (() => { try { return Intl.supportedValuesOf('timeZone') } catch { return ['UTC', browserTz] } })()
const row = (from, to) => Array.from({ length: 24 }, (_, h) => (h >= from && h < to ? '1' : '0')).join('')
const PRESETS = {
  business: () => [...Array(5).fill(row(9, 18)), row(0, 0), row(0, 0)],
  outside: () => [...Array(5).fill(row(0, 9).split('').map((c, h) => (h >= 18 ? '1' : c)).join('')), row(0, 24), row(0, 24)],
  nights: () => Array(7).fill(row(0, 6).split('').map((c, h) => (h >= 22 ? '1' : c)).join('')),
}

const grid = ref(props.modelValue ? [...props.modelValue.grid] : PRESETS.business())
const tz = ref(props.modelValue ? props.modelValue.tz : browserTz)
const mode = ref(props.modelValue ? detect(props.modelValue.grid) : 'any')

function detect(g) {
  for (const [k, f] of Object.entries(PRESETS)) if (f().join() === g.join()) return k
  return 'custom'
}
function setMode(m) {
  mode.value = m
  if (PRESETS[m]) grid.value = PRESETS[m]()
  push()
}
function push() {
  emit('update:modelValue', mode.value === 'any' ? null : { tz: tz.value || 'UTC', grid: [...grid.value] })
}
watch(tz, push)
watch(() => props.modelValue, (v) => {
  if (!v) { if (mode.value !== 'any') mode.value = 'any'; return }
  if (v.grid.join() !== grid.value.join()) { grid.value = [...v.grid]; mode.value = detect(v.grid) }
  if (v.tz && v.tz !== tz.value) tz.value = v.tz
})

// painting: mousedown on a cell picks paint-on / paint-off from that cell, drag extends it
const paint = ref(null)
function cell(d, h) { return grid.value[d][h] === '1' }
function set(d, h, on) {
  const r = grid.value[d].split(''); r[h] = on ? '1' : '0'
  grid.value = grid.value.map((x, i) => (i === d ? r.join('') : x))
}
function down(d, h) { paint.value = !cell(d, h); set(d, h, paint.value) }
function enter(d, h) { if (paint.value !== null) set(d, h, paint.value) }
function up() { if (paint.value !== null) { paint.value = null; mode.value = detect(grid.value); push() } }
function toggleDay(d) {
  const on = !grid.value[d].includes('1')
  grid.value = grid.value.map((x, i) => (i === d ? row(0, on ? 24 : 0) : x)); mode.value = detect(grid.value); push()
}
function toggleHour(h) {
  const on = !grid.value.every(r => r[h] === '1')
  grid.value = grid.value.map((r) => { const a = r.split(''); a[h] = on ? '1' : '0'; return a.join('') })
  mode.value = detect(grid.value); push()
}

// "Mon–Fri 09:00–18:00" - the same wording as the server
function ranges(r) {
  const out = []
  for (let h = 0; h < 24;) {
    if (r[h] === '1') { const s = h; while (h < 24 && r[h] === '1') h++; out.push(`${String(s).padStart(2, '0')}:00–${String(h).padStart(2, '0')}:00`) } else h++
  }
  return out.join(', ')
}
const text = computed(() => {
  if (mode.value === 'any') return 'Any time'
  const per = grid.value.map(ranges)
  const groups = []
  per.forEach((t, d) => { const g = groups[groups.length - 1]; if (g && g.t === t && g.b === d - 1) g.b = d; else groups.push({ a: d, b: d, t }) })
  const parts = groups.filter(g => g.t).map(g => {
    const days = g.a === 0 && g.b === 6 ? 'Every day' : g.a === g.b ? DAYS[g.a] : g.b > g.a + 1 ? `${DAYS[g.a]}–${DAYS[g.b]}` : `${DAYS[g.a]}, ${DAYS[g.b]}`
    return `${days} ${g.t}`
  })
  return parts.length ? parts.join(' · ') : 'no hours picked'
})
const empty = computed(() => mode.value !== 'any' && !grid.value.some(r => r.includes('1')))

// open now? / when does it change - evaluated in the window's time zone
function local(d) {
  try {
    const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: tz.value, weekday: 'short', hour: '2-digit', hourCycle: 'h23' })
      .formatToParts(d).map(x => [x.type, x.value]))
    return { day: DAYS.indexOf(p.weekday), hour: Number(p.hour) }
  } catch { return { day: (d.getDay() + 6) % 7, hour: d.getHours() } }
}
const status = computed(() => {
  if (mode.value === 'any' || empty.value) return ''
  const now = new Date()
  const isOpen = (d) => { const l = local(d); return grid.value[l.day][l.hour] === '1' }
  const open = isOpen(now)
  const start = new Date(now); start.setMinutes(0, 0, 0)
  for (let i = 1; i <= 24 * 8; i++) {
    const t = new Date(start.getTime() + i * 3600e3)
    if (isOpen(t) !== open) {
      const f = new Intl.DateTimeFormat(undefined, { timeZone: tz.value, weekday: 'short', hour: '2-digit', minute: '2-digit' })
      return open ? `open now · closes ${f.format(t)}` : `closed now · opens ${f.format(t)}`
    }
  }
  return open ? 'open now' : 'closed'
})
</script>

<template>
  <div class="win" @mouseup="up" @mouseleave="up">
    <div class="seg">
      <button type="button" :class="{ on: mode === 'any' }" @click="setMode('any')">Any time</button>
      <button type="button" :class="{ on: mode === 'business' }" @click="setMode('business')">Business hours</button>
      <button type="button" :class="{ on: mode === 'outside' }" @click="setMode('outside')">Outside business hours</button>
      <button type="button" :class="{ on: mode === 'nights' }" @click="setMode('nights')">Nights</button>
      <button type="button" :class="{ on: mode === 'custom' }" @click="mode = 'custom'; push()">Custom</button>
    </div>
    <template v-if="mode !== 'any'">
      <div class="grid" role="grid" aria-label="Hours the scan may run">
        <div class="corner"></div>
        <button v-for="h in 24" :key="'h' + h" type="button" class="hh" :title="`Toggle ${h - 1}:00 on every day`" @click="toggleHour(h - 1)">
          {{ (h - 1) % 3 === 0 ? String(h - 1).padStart(2, '0') : '' }}</button>
        <template v-for="(d, di) in DAYS" :key="d">
          <button type="button" class="dd" :title="`Toggle all of ${d}`" @click="toggleDay(di)">{{ d }}</button>
          <div v-for="h in 24" :key="d + h" class="c" :class="{ on: cell(di, h - 1) }"
               :title="`${d} ${String(h - 1).padStart(2, '0')}:00–${String(h).padStart(2, '0')}:00`"
               @mousedown.prevent="down(di, h - 1)" @mouseenter="enter(di, h - 1)"></div>
        </template>
      </div>
      <div class="foot">
        <div class="tzf">
          <label>Time zone</label>
          <input v-model="tz" list="bc-tz-list-w" spellcheck="false" />
          <datalist id="bc-tz-list-w"><option v-for="z in zones" :key="z" :value="z" /></datalist>
        </div>
        <div class="sum">
          <b :class="{ bad: empty }">{{ empty ? 'Pick at least one hour' : text }}</b>
          <span v-if="status" class="muted"> · {{ status }}</span>
          <div class="muted note">Jobs are only handed out inside the window. Jobs already running when it closes finish;
            nothing new starts until it opens again. Drag across the grid to paint hours.</div>
        </div>
      </div>
    </template>
    <div v-else class="muted note" style="margin-top:8px">Jobs run whenever a scanner is free.</div>
  </div>
</template>

<style scoped>
.seg { display: inline-flex; flex-wrap: wrap; border: 1px solid var(--outline-variant); border-radius: var(--radius-xl); overflow: hidden; }
.seg button { border: 0; border-radius: 0; height: 34px; text-transform: none; letter-spacing: 0; font-weight: 500; font-size: 12.5px;
  color: var(--on-surface-variant); background: transparent; }
.seg button + button { border-left: 1px solid var(--outline-variant); }
.seg button.on { background: var(--primary-container); color: var(--accent-ink); }
.seg button:hover { box-shadow: none; color: var(--on-surface); background: var(--sc); }
.grid { display: grid; grid-template-columns: 40px repeat(24, minmax(14px, 1fr)); gap: 2px; margin-top: 12px; user-select: none;
  max-width: 760px; }
.corner { height: 16px; }
.hh, .dd { all: unset; cursor: pointer; font-size: 10.5px; color: var(--outline); text-align: center; font-family: var(--mono); }
.hh { height: 16px; text-align: left; }
.dd { text-align: left; font-family: var(--primary-fnt); font-size: 12px; color: var(--on-surface-variant); line-height: 20px; }
.hh:hover, .dd:hover { color: var(--accent-ink); }
.c { height: 20px; border-radius: 3px; background: var(--sc-high); cursor: pointer; }
.c:hover { outline: 1px solid var(--outline); }
.c.on { background: var(--accent); }
.foot { display: flex; gap: 18px; align-items: flex-start; margin-top: 10px; flex-wrap: wrap; }
.tzf { width: 240px; }
.sum { flex: 1; min-width: 240px; padding-top: 22px; font-size: 13px; }
.sum .bad { color: var(--error); }
.note { font-size: 12px; margin-top: 4px; line-height: 1.45; }
</style>
