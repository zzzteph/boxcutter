<script setup>
// The workflow graph. One component, three modes:
//   edit  - the Workflow builder: drag nodes, drag from a node's output port (right) onto another node to wire it,
//           click a wire to remove it. Emits the new {nodes, edges} via update:modelValue.
//   view  - a read-only diagram (built-in workflows, the New scan preview).
//   live  - a running scan: every node shows its state, job progress, what it found and its findings; wires out
//           of a running step are animated so you can watch data flow through the workflow.
// Data: nodes [{key, title, kind, category, produces, input, args, steps, x, y}], edges [{from, to}]. The scan's
// own targets are the fixed source node '@targets'. Layout is automatic (left -> right by depth) unless nodes
// carry saved x/y; "Tidy" re-runs it. Pan by dragging the background, zoom with the buttons or ctrl/cmd + wheel.
import { ref, reactive, computed, watch, onMounted, onBeforeUnmount, nextTick } from 'vue'

const props = defineProps({
  modelValue: { type: Object, default: () => ({ nodes: [], edges: [] }) },
  mode: { type: String, default: 'view' },            // edit | view | live
  states: { type: Object, default: () => ({}) },      // live: { key: {state, jobs, items, findings} }
  selected: { type: String, default: '' },
  height: { type: Number, default: 480 },
  inputLabels: { type: Object, default: () => ({}) },
})
const emit = defineEmits(['update:modelValue', 'select', 'invalid'])

const T = '@targets'
const W = 236
const H = computed(() => (props.mode === 'live' ? 100 : 76))
const PORT_Y = 26
const COL_GAP = 64
const ROW_GAP = 14

const EDGE_COLOR = { all: '#8f9099', hosts: '#4f9dde', urls: '#3fae9f', 'param-urls': '#9b7bd4',
  'js-urls': '#e0a03a', writes: '#e5704b' }
const CAT_COLOR = { Websites: '#e5704b', Environment: '#d65db1', Discovery: '#4f9dde', APIs: '#3fae9f',
  Secrets: '#e0a03a', 'Web archive': '#9b7bd4', Network: '#6b8f3a', Tools: '#8f9099', Custom: '#b28739' }
const PRODUCES = { findings: 'findings', hosts: 'hostnames', urls: 'URLs', items: 'URLs & requests' }

const nodes = computed(() => props.modelValue.nodes || [])
const edges = computed(() => props.modelValue.edges || [])
const editing = computed(() => props.mode === 'edit')

// ---- positions: saved x/y, else auto layout ----
const pos = reactive({})                     // key -> {x, y}
function depthMap() {
  const d = { [T]: 0 }
  for (const n of nodes.value) d[n.key] = 1
  for (let pass = 0; pass <= nodes.value.length; pass++) {
    let changed = false
    for (const e of edges.value) {
      const v = (d[e.from] ?? 0) + 1
      if (v > (d[e.to] ?? 1)) { d[e.to] = v; changed = true }
    }
    if (!changed) break
  }
  return d
}
function layout() {
  const d = depthMap()
  const cols = {}
  for (const n of nodes.value) (cols[d[n.key]] = cols[d[n.key]] || []).push(n.key)
  const order = { [T]: 0 }
  const keys = Object.keys(cols).map(Number).sort((a, b) => a - b)
  for (const c of keys) {
    // order each column by the average row of its parents (fewer crossing wires)
    const bary = (k) => {
      const ps = edges.value.filter(e => e.to === k).map(e => order[e.from] ?? 0)
      return ps.length ? ps.reduce((a, b) => a + b, 0) / ps.length : 0
    }
    cols[c].sort((a, b) => bary(a) - bary(b) || nodes.value.findIndex(n => n.key === a) - nodes.value.findIndex(n => n.key === b))
    cols[c].forEach((k, i) => { order[k] = i })
  }
  const tallest = Math.max(1, ...keys.map(c => cols[c].length))
  const colH = (n) => n * H.value + (n - 1) * ROW_GAP
  const maxH = colH(tallest)
  pos[T] = { x: 0, y: Math.max(0, (maxH - 64) / 2) }
  for (const c of keys) {
    const top = (maxH - colH(cols[c].length)) / 2
    cols[c].forEach((k, i) => { pos[k] = { x: 150 + (c - 1) * (W + COL_GAP) + 40, y: top + i * (H.value + ROW_GAP) } })
  }
}
function syncPositions(force = false) {
  for (const k of Object.keys(pos)) if (k !== T && !nodes.value.some(n => n.key === k)) delete pos[k]
  if (force) { layout(); return }
  for (const n of nodes.value) if (Number.isFinite(n.x) && Number.isFinite(n.y)) pos[n.key] = { x: n.x, y: n.y }
  const missing = nodes.value.filter(n => !pos[n.key])
  if (missing.length === nodes.value.length) { layout(); return }
  if (!pos[T]) {
    const placed = nodes.value.filter(n => pos[n.key])
    const ys = placed.map(n => pos[n.key].y)
    pos[T] = { x: Math.min(...placed.map(n => pos[n.key].x)) - 190, y: (Math.min(...ys) + Math.max(...ys)) / 2 }
  }
  // a step added in the builder lands next to the step it is wired from (or the targets), never on top of another
  for (const n of missing) {
    const e = edges.value.find(x => x.to === n.key && pos[x.from])
    const p = e ? pos[e.from] : pos[T]
    const x = p.x + ((e ? e.from : T) === T ? 190 : W + COL_GAP)
    let y = p.y
    const busy = () => Object.entries(pos).some(([k, q]) => k !== n.key && Math.abs(q.x - x) < W && Math.abs(q.y - y) < H.value + ROW_GAP / 2)
    let guard = 0
    while (busy() && guard++ < 50) y += H.value + ROW_GAP
    pos[n.key] = { x, y }
  }
}

// ---- view transform ----
const box = ref(null)
const view = reactive({ x: 20, y: 20, z: 1 })
function bounds() {
  const ps = Object.entries(pos)
  if (!ps.length) return { x0: 0, y0: 0, x1: W, y1: H.value }
  const x0 = Math.min(...ps.map(([, p]) => p.x)), y0 = Math.min(...ps.map(([, p]) => p.y))
  const x1 = Math.max(...ps.map(([k, p]) => p.x + (k === T ? 150 : W))), y1 = Math.max(...ps.map(([, p]) => p.y + H.value))
  return { x0, y0, x1, y1 }
}
// fit the whole graph; `minZ` stops a big workflow from shrinking into unreadable text on first load (the Fit
// button passes a lower floor to show everything). If it can't fit, the start (scan targets) stays in view.
function fit(minZ = 0.5) {
  const el = box.value
  if (!el) return
  const b = bounds()
  const w = el.clientWidth - 40, h = props.height - 40
  const z = Math.max(minZ, Math.min(1.05, w / (b.x1 - b.x0), h / (b.y1 - b.y0)))
  view.z = z
  view.x = 20 - b.x0 * z + Math.max(0, (w - (b.x1 - b.x0) * z) / 2)
  const tallBy = (b.y1 - b.y0) * z - h
  view.y = tallBy > 0 ? 20 - (pos[T].y + 32) * z + h / 2 : 20 - b.y0 * z + (h - (b.y1 - b.y0) * z) / 2
  if (tallBy > 0) view.y = Math.min(20 - b.y0 * z, Math.max(view.y, 20 + h - b.y1 * z))
}
function ensureVisible() {                    // builder: re-fit when a new step lands outside the visible area
  const el = box.value
  if (!el) return
  const b = bounds()
  const sx0 = b.x0 * view.z + view.x, sx1 = b.x1 * view.z + view.x, sy0 = b.y0 * view.z + view.y, sy1 = b.y1 * view.z + view.y
  if (sx0 < 0 || sy0 < 0 || sx1 > el.clientWidth || sy1 > props.height) fit(0.5)
}
function zoomBy(f) {
  const el = box.value
  const cx = el ? el.clientWidth / 2 : 0, cy = props.height / 2
  const nz = Math.max(0.3, Math.min(1.8, view.z * f))
  view.x = cx - (cx - view.x) * (nz / view.z); view.y = cy - (cy - view.y) * (nz / view.z); view.z = nz
}
function onWheel(e) {
  if (!(e.ctrlKey || e.metaKey)) return
  e.preventDefault()
  zoomBy(e.deltaY < 0 ? 1.1 : 1 / 1.1)
}
function toWorld(e) {
  const r = box.value.getBoundingClientRect()
  return { x: (e.clientX - r.left - view.x) / view.z, y: (e.clientY - r.top - view.y) / view.z }
}

// ---- interaction: pan, node drag, wiring ----
const drag = reactive({ kind: '', key: '', sx: 0, sy: 0, ox: 0, oy: 0, moved: false, wx: 0, wy: 0, over: '' })
const selEdge = ref(-1)
function onBgDown(e) {
  if (e.button !== 0) return
  selEdge.value = -1
  Object.assign(drag, { kind: 'pan', sx: e.clientX, sy: e.clientY, ox: view.x, oy: view.y, moved: false })
}
function onNodeDown(e, key) {
  if (e.button !== 0) return
  e.stopPropagation()
  selEdge.value = -1
  if (!editing.value) { Object.assign(drag, { kind: 'click', key, sx: e.clientX, sy: e.clientY, moved: false }); return }
  Object.assign(drag, { kind: 'node', key, sx: e.clientX, sy: e.clientY, ox: pos[key].x, oy: pos[key].y, moved: false })
}
function onPortDown(e, key) {
  e.stopPropagation()
  const w = toWorld(e)
  Object.assign(drag, { kind: 'wire', key, wx: w.x, wy: w.y, moved: true, over: '' })
}
function onMove(e) {
  if (!drag.kind) return
  const dx = e.clientX - drag.sx, dy = e.clientY - drag.sy
  if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true
  if (drag.kind === 'pan') { view.x = drag.ox + dx; view.y = drag.oy + dy }
  else if (drag.kind === 'node') { pos[drag.key] = { x: drag.ox + dx / view.z, y: drag.oy + dy / view.z } }
  else if (drag.kind === 'wire') {
    const w = toWorld(e); drag.wx = w.x; drag.wy = w.y
    const hit = document.elementFromPoint(e.clientX, e.clientY)?.closest('[data-node]')
    drag.over = hit ? hit.getAttribute('data-node') : ''
  }
}
function onUp() {
  if (drag.kind === 'node') {
    if (!drag.moved) emit('select', drag.key)
    else emitPositions()
  } else if (drag.kind === 'click') {
    if (!drag.moved) emit('select', drag.key)
  } else if (drag.kind === 'pan' && !drag.moved) {
    emit('select', '')
  } else if (drag.kind === 'wire' && drag.over) {
    connect(drag.key, drag.over)
  }
  drag.kind = ''
  drag.over = ''
}
function reaches(from, to) {                   // is `to` reachable from `from` following wires?
  const seen = new Set([from]), stack = [from]
  while (stack.length) {
    const k = stack.pop()
    if (k === to) return true
    for (const e of edges.value) if (e.from === k && !seen.has(e.to)) { seen.add(e.to); stack.push(e.to) }
  }
  return false
}
function connect(from, to) {
  if (to === T || from === to) return
  const src = nodes.value.find(n => n.key === from)
  if (src && src.produces === 'findings') { emit('invalid', `“${src.title}” only produces findings — nothing to pass on`); return }
  if (edges.value.some(e => e.from === from && e.to === to)) return
  if (reaches(to, from)) { emit('invalid', 'that wire would make a loop — data must flow one way'); return }
  emit('update:modelValue', { nodes: nodes.value, edges: [...edges.value, { from, to }] })
  emit('select', to)
}
function removeEdge(i) {
  const e = edges.value[i]
  if (!e) return
  emit('update:modelValue', { nodes: nodes.value, edges: edges.value.filter((_, j) => j !== i) })
  selEdge.value = -1
}
function removeNode(key) {
  emit('update:modelValue', { nodes: nodes.value.filter(n => n.key !== key),
    edges: edges.value.filter(e => e.from !== key && e.to !== key) })
  emit('select', '')
}
function emitPositions() {
  emit('update:modelValue', { nodes: nodes.value.map(n => ({ ...n, x: pos[n.key]?.x, y: pos[n.key]?.y })), edges: edges.value })
}
function tidy() { syncPositions(true); if (editing.value) emitPositions(); nextTick(() => fit()) }
function onKey(e) {
  if (!editing.value || selEdge.value < 0) return
  if ((e.key === 'Delete' || e.key === 'Backspace') && !/input|textarea|select/i.test(e.target.tagName)) removeEdge(selEdge.value)
}

// ---- drawing ----
function port(key, side) {
  const p = pos[key] || { x: 0, y: 0 }
  if (side === 'out') return { x: p.x + (key === T ? 150 : W), y: p.y + PORT_Y }
  return { x: p.x, y: p.y + PORT_Y }
}
function curve(a, b) {
  const dx = Math.max(40, Math.abs(b.x - a.x) / 2)
  return `M${a.x},${a.y} C${a.x + dx},${a.y} ${b.x - dx},${b.y} ${b.x},${b.y}`
}
const nodeByKey = computed(() => Object.fromEntries(nodes.value.map(n => [n.key, n])))
const paths = computed(() => edges.value.map((e, i) => {
  const a = port(e.from, 'out'), b = port(e.to, 'in')
  const to = nodeByKey.value[e.to]
  const input = to ? to.input : 'all'
  const st = props.states[e.from]
  const flowing = props.mode === 'live' && (e.from === T ? isLive.value : st && st.state === 'running')
  const dim = props.mode === 'live' && props.states[e.to] && ['waiting', 'skipped'].includes(props.states[e.to].state)
  return { i, d: curve(a, b), color: EDGE_COLOR[input] || EDGE_COLOR.all, flowing, dim,
    mid: { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 } }
}))
const isLive = computed(() => Object.values(props.states).some(s => s.state === 'running'))
const ghost = computed(() => drag.kind === 'wire' ? curve(port(drag.key, 'out'), { x: drag.wx, y: drag.wy }) : '')
const worldSize = computed(() => { const b = bounds(); return { w: b.x1 + 400, h: b.y1 + 400 } })
const legend = computed(() => {
  const used = new Set(nodes.value.filter(n => edges.value.some(e => e.to === n.key)).map(n => n.input || 'all'))
  return Object.keys(EDGE_COLOR).filter(k => used.has(k)).map(k => ({ k, color: EDGE_COLOR[k], label: props.inputLabels[k] || k }))
})
const targetsState = computed(() => props.states[T] || null)
function pct(s) { const j = s && s.jobs; return j && j.total ? Math.round(100 * (j.done + j.failed + (j.cancelled || 0)) / j.total) : 0 }
function nodeClass(n) {
  const s = props.states[n.key]
  return { sel: props.selected === n.key, over: drag.kind === 'wire' && drag.over === n.key && drag.key !== n.key,
    ['ns-' + (s ? s.state : 'none')]: props.mode === 'live' }
}

watch(() => nodes.value.map(n => n.key).join(',') + '|' + edges.value.length + '|' + props.mode, (now, before) => {
  const wasEmpty = !before || before.startsWith('|')
  syncPositions(props.mode !== 'edit')
  if (props.mode !== 'edit' || wasEmpty) nextTick(() => fit())
  else nextTick(ensureVisible)
})
onMounted(() => {
  syncPositions(); nextTick(() => fit())
  window.addEventListener('mousemove', onMove); window.addEventListener('mouseup', onUp); window.addEventListener('keydown', onKey)
})
onBeforeUnmount(() => {
  window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp); window.removeEventListener('keydown', onKey)
})
defineExpose({ fit, tidy })
</script>

<template>
  <div ref="box" class="wg" :class="['m-' + mode, { panning: drag.kind === 'pan' && drag.moved }]" :style="{ height: height + 'px' }"
       @mousedown="onBgDown" @wheel="onWheel">
    <div class="wg-world" :style="{ transform: `translate(${view.x}px, ${view.y}px) scale(${view.z})` }">
      <svg class="wg-edges" :width="worldSize.w" :height="worldSize.h">
        <g v-for="p in paths" :key="p.i" class="wg-edge" :class="{ sel: selEdge === p.i, dim: p.dim }">
          <path :d="p.d" class="hit" @mousedown.stop="editing && (selEdge = p.i)" />
          <path :d="p.d" class="line" :stroke="p.color" :class="{ flowing: p.flowing }" />
        </g>
        <path v-if="ghost" :d="ghost" class="ghost" />
      </svg>
      <button v-for="p in paths.filter(p => p.i === selEdge)" :key="'x' + p.i" type="button" class="edge-x"
              :style="{ left: p.mid.x - 12 + 'px', top: p.mid.y - 12 + 'px' }" title="Remove this wire"
              @mousedown.stop @click.stop="removeEdge(p.i)">✕</button>

      <!-- the scan's own targets: where every workflow starts -->
      <div class="wg-src" :data-node="'@targets'" :style="{ left: pos['@targets']?.x + 'px', top: pos['@targets']?.y + 'px' }"
           @mousedown="onNodeDown($event, '@targets')">
        <div class="src-t">◎ Scan targets</div>
        <div class="src-s">{{ targetsState ? targetsState.count + ' target(s)' : 'what you scan' }}</div>
        <span class="port out" @mousedown="editing && onPortDown($event, '@targets')" :class="{ wired: editing }"></span>
      </div>

      <div v-for="n in nodes" :key="n.key" class="wg-node" :class="nodeClass(n)" :data-node="n.key"
           :style="{ left: pos[n.key]?.x + 'px', top: pos[n.key]?.y + 'px', height: H + 'px', '--cat': CAT_COLOR[n.category] || CAT_COLOR.Custom }"
           @mousedown="onNodeDown($event, n.key)">
        <span class="port in"></span>
        <div class="n-head">
          <span class="dot"></span>
          <b :title="n.label || n.title">{{ n.label || n.title }}</b>
          <span class="n-kind">{{ n.kind === 'pipeline' ? 'workflow' : (n.kind === 'workflow' ? 'template' : 'tool') }}</span>
          <button v-if="editing" type="button" class="n-x" title="Remove step" @mousedown.stop @click.stop="removeNode(n.key)">✕</button>
        </div>
        <div class="n-io">
          <span class="in-l" :style="{ color: EDGE_COLOR[n.input] || EDGE_COLOR.all }">in: {{ inputLabels[n.input] || n.input || 'everything' }}</span>
          <span class="out-l">→ {{ PRODUCES[n.produces] || n.produces }}</span>
        </div>
        <div class="n-args" v-if="mode !== 'live'" :class="{ desc: !n.args }">{{ n.args || (n.kind === 'pipeline'
          ? (n.steps || '?') + ' steps inside' : (n.label ? n.title : n.description)) }}</div>
        <template v-if="mode === 'live'">
          <div class="n-bar"><div :style="{ width: pct(states[n.key]) + '%' }"></div></div>
          <div class="n-live" v-if="states[n.key]">
            <span class="st">{{ states[n.key].state }}</span>
            <span>{{ states[n.key].jobs.done + states[n.key].jobs.failed }}/{{ states[n.key].jobs.total }} jobs</span>
            <span v-if="states[n.key].jobs.running" class="run">{{ states[n.key].jobs.running }} running</span>
          </div>
          <div class="n-live" v-if="states[n.key]">
            <span v-if="states[n.key].items">{{ states[n.key].items }} found</span>
            <span v-if="states[n.key].findings" class="fnd">{{ states[n.key].findings }} findings</span>
            <span v-if="states[n.key].jobs.failed" class="bad">{{ states[n.key].jobs.failed }} failed</span>
          </div>
        </template>
        <span v-if="n.produces !== 'findings'" class="port out" :class="{ wired: editing }"
              @mousedown="editing && onPortDown($event, n.key)" title="Drag to another step to pass these results on"></span>
        <span v-else class="term" title="Findings are the end of a branch">⊣</span>
      </div>
    </div>

    <div class="wg-tools" @mousedown.stop>
      <button type="button" class="ghost sm" title="Zoom out" @click="zoomBy(1 / 1.2)">−</button>
      <button type="button" class="ghost sm" title="Zoom in" @click="zoomBy(1.2)">+</button>
      <button type="button" class="ghost sm" title="Show the whole workflow" @click="fit(0.15)">Fit</button>
      <button v-if="editing" type="button" class="ghost sm" title="Re-arrange automatically" @click="tidy">Tidy</button>
    </div>
    <div v-if="legend.length" class="wg-legend" @mousedown.stop>
      <span v-for="l in legend" :key="l.k"><i :style="{ background: l.color }"></i>{{ l.label }}</span>
    </div>
    <div v-if="editing && !nodes.length" class="wg-empty">Add a first step from the list on the left — it will run on your scan targets.</div>
  </div>
</template>

<style scoped>
.wg { position: relative; overflow: hidden; border-radius: var(--radius-s); background: var(--sc-lowest);
  background-image: radial-gradient(circle, rgba(255,255,255,.05) 1px, transparent 1px); background-size: 22px 22px;
  cursor: grab; user-select: none; }
.wg.panning { cursor: grabbing; }
.wg-world { position: absolute; left: 0; top: 0; transform-origin: 0 0; }
.wg-edges { position: absolute; left: 0; top: 0; overflow: visible; pointer-events: none; }
.wg-edge .hit { stroke: transparent; stroke-width: 14; fill: none; pointer-events: stroke; cursor: pointer; }
.m-view .wg-edge .hit, .m-live .wg-edge .hit { pointer-events: none; }
.wg-edge .line { fill: none; stroke-width: 2.2; opacity: .85; }
.wg-edge.sel .line { stroke-width: 4; opacity: 1; filter: drop-shadow(0 0 4px rgba(255,255,255,.35)); }
.wg-edge.dim .line { opacity: .3; }
.line.flowing { stroke-dasharray: 7 6; animation: flow .9s linear infinite; }
@keyframes flow { to { stroke-dashoffset: -26; } }
.ghost { fill: none; stroke: var(--accent); stroke-width: 2; stroke-dasharray: 5 5; }
.edge-x { position: absolute; width: 24px; height: 24px; padding: 0; border-radius: 50%; font-size: 11px;
  background: var(--error); color: var(--on-error); border: 0; z-index: 3; }

.wg-src, .wg-node { position: absolute; box-sizing: border-box; border-radius: 10px; cursor: pointer; }
.wg-src { width: 150px; padding: 10px 12px; background: var(--sc-high); border: 1px dashed var(--outline); }
.src-t { font-weight: 600; font-size: 13px; color: var(--on-surface); }
.src-s { font-size: 11.5px; color: var(--on-surface-variant); margin-top: 3px; }
.wg-node { width: 236px; padding: 8px 12px 7px 14px; background: var(--sc); border: 1px solid var(--outline-variant);
  box-shadow: var(--e1); display: flex; flex-direction: column; gap: 4px; overflow: visible; }
.m-edit .wg-node { cursor: move; }
.wg-node::before { content: ""; position: absolute; left: 0; top: 8px; bottom: 8px; width: 3px; border-radius: 0 3px 3px 0; background: var(--cat); }
.wg-node.sel { border-color: var(--accent); box-shadow: var(--glow), var(--e2); }
.wg-node.over { border-color: var(--ok); box-shadow: 0 0 0 2px var(--ok); }
.n-head { display: flex; align-items: center; gap: 7px; min-width: 0; }
.n-head .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--cat); flex: none; }
.n-head b { font-weight: 600; font-size: 13px; color: var(--on-surface); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; }
.n-kind { font-size: 9.5px; text-transform: uppercase; letter-spacing: .06em; color: var(--outline); flex: none; }
.n-x { height: 20px; width: 20px; padding: 0; border: 0; border-radius: 50%; font-size: 10px; color: var(--on-surface-variant);
  background: transparent; display: none; flex: none; }
.wg-node:hover .n-x { display: inline-flex; }
.n-x:hover { background: var(--error); color: var(--on-error); box-shadow: none; }
.n-io { display: flex; justify-content: space-between; gap: 6px; font-size: 11.5px; }
.out-l { color: var(--on-surface-variant); white-space: nowrap; }
.in-l { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.n-args { font: 11px var(--mono); color: var(--outline); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.n-args.desc { font-family: var(--primary-fnt); font-size: 11.5px; }
.n-bar { height: 4px; border-radius: 4px; background: var(--sc-highest); overflow: hidden; margin-top: 2px; }
.n-bar > div { height: 100%; background: var(--accent); transition: width .4s; }
.n-live { display: flex; gap: 8px; font-size: 11.5px; color: var(--on-surface-variant); white-space: nowrap; overflow: hidden; }
.n-live .st { text-transform: capitalize; color: var(--on-surface); font-weight: 600; }
.n-live .run { color: var(--accent-ink); }
.n-live .fnd { color: var(--high); font-weight: 600; }
.n-live .bad { color: var(--error); }
/* live states */
.ns-waiting { opacity: .55; border-style: dashed; }
.ns-skipped { opacity: .35; border-style: dashed; }
.ns-running { border-color: var(--accent); animation: pulse 1.6s ease-in-out infinite; }
.ns-running .n-bar > div { background-image: linear-gradient(90deg, transparent, rgba(255,255,255,.4), transparent);
  background-size: 40% 100%; background-repeat: no-repeat; animation: prog 1.2s linear infinite; background-color: var(--accent); }
.ns-done { border-color: color-mix(in srgb, var(--ok) 55%, var(--outline-variant)); }
.ns-done .n-bar > div { background: var(--ok); }
.ns-done .n-live .st { color: var(--ok); }
.ns-stopped .n-live .st { color: var(--error); }
@keyframes pulse { 0%, 100% { box-shadow: 0 0 0 0 rgba(178,135,57,.0); } 50% { box-shadow: 0 0 0 5px rgba(178,135,57,.18); } }
@keyframes prog { 0% { background-position: -40% 0; } 100% { background-position: 140% 0; } }

.port { position: absolute; width: 12px; height: 12px; border-radius: 50%; top: 20px; background: var(--sc-highest);
  border: 2px solid var(--outline); box-sizing: border-box; }
.port.in { left: -7px; }
.port.out { right: -7px; }
.port.out.wired { cursor: crosshair; background: var(--accent); border-color: var(--accent-bright); }
.port.out.wired:hover { transform: scale(1.35); }
.term { position: absolute; right: -4px; top: 16px; color: var(--high); font-weight: 700; font-size: 14px; }
.wg-src .port.out { top: 20px; }

.wg-tools { position: absolute; right: 10px; top: 10px; display: flex; gap: 4px; background: var(--sc);
  border-radius: var(--radius-s); padding: 3px; border: 1px solid var(--outline-variant); }
.wg-tools button { height: 28px; padding: 0 10px; }
.wg-legend { position: absolute; left: 10px; bottom: 10px; display: flex; gap: 12px; flex-wrap: wrap; font-size: 11.5px;
  color: var(--on-surface-variant); background: color-mix(in srgb, var(--sc) 85%, transparent); padding: 5px 10px;
  border-radius: var(--radius-s); border: 1px solid var(--outline-variant); cursor: default; }
.wg-legend i { display: inline-block; width: 14px; height: 3px; border-radius: 2px; margin-right: 5px; vertical-align: middle; }
.wg-empty { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); color: var(--on-surface-variant);
  font-size: 13px; pointer-events: none; text-align: center; max-width: 320px; }
</style>
