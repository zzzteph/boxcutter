<script setup>
// A small dependency-free node-graph editor: draggable tool boxes wired producer -> consumer. Boxes are
// absolutely-positioned divs; edges are SVG bezier paths under them. Ports are typed from the tool catalog —
// a `findings` (terminal) tool has NO output port, so it can't feed a downstream box. A box takes at most one
// input (dropping a new wire onto an occupied input replaces it), which keeps the graph a DAG the compiler
// accepts. Owns its own {nodes, edges} state and emits `change`; seed edit mode via :initial.
import { ref, reactive, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'
import Select from './Select.vue'

const props = defineProps({
  initial: { type: Object, default: () => ({ nodes: [], edges: [] }) },
  catalog: { type: Array, default: () => [] },
})
const emit = defineEmits(['change'])

const BOX_W = 190
const PORT_DY = 26            // wire anchor: this far below a box's top-left

const nodes = reactive([])    // {id, tool, args, x, y}
const edges = reactive([])    // {from, to}
let seq = 0

const canvas = ref(null)
const drag = reactive({ mode: null, id: null, ox: 0, oy: 0, fromId: null, mx: 0, my: 0 })

const kindOf = (tool) => props.catalog.find(t => t.name === tool)?.kind || ''
const isTerminal = (tool) => !!props.catalog.find(t => t.name === tool)?.terminal
const toolOpts = computed(() => props.catalog.map(t => ({ value: t.name, label: `${t.name} · ${t.kind}` })))
const addTool = ref('')

function emitChange() {
  emit('change', {
    nodes: nodes.map(n => ({ id: n.id, tool: n.tool, args: n.args, x: n.x, y: n.y })),
    edges: edges.map(e => ({ from: e.from, to: e.to })),
  })
}

function addNode(tool) {
  if (!tool) return
  const id = 'b' + (++seq)
  // stagger new boxes so they don't stack exactly on top of each other
  nodes.push({ id, tool, args: '', x: 40 + (nodes.length % 4) * 40, y: 40 + (nodes.length % 6) * 30 })
  addTool.value = ''
  emitChange()
}
function removeNode(id) {
  const i = nodes.findIndex(n => n.id === id)
  if (i >= 0) nodes.splice(i, 1)
  for (let j = edges.length - 1; j >= 0; j--) if (edges[j].from === id || edges[j].to === id) edges.splice(j, 1)
  emitChange()
}
function removeEdge(from, to) {
  const i = edges.findIndex(e => e.from === from && e.to === to)
  if (i >= 0) { edges.splice(i, 1); emitChange() }
}
function setArgs(n, v) { n.args = v; emitChange() }

// ---- geometry (canvas-local coords) ----
const nodeById = (id) => nodes.find(n => n.id === id)
const outPort = (n) => ({ x: n.x + BOX_W, y: n.y + PORT_DY })
const inPort = (n) => ({ x: n.x, y: n.y + PORT_DY })
function bezier(a, b) {
  const dx = Math.max(40, Math.abs(b.x - a.x) / 2)
  return `M ${a.x} ${a.y} C ${a.x + dx} ${a.y}, ${b.x - dx} ${b.y}, ${b.x} ${b.y}`
}
const edgePaths = computed(() => edges.map(e => {
  const a = nodeById(e.from), b = nodeById(e.to)
  return a && b ? { from: e.from, to: e.to, d: bezier(outPort(a), inPort(b)) } : null
}).filter(Boolean))
const tempPath = computed(() => {
  if (drag.mode !== 'wire') return ''
  const a = nodeById(drag.fromId)
  return a ? bezier(outPort(a), { x: drag.mx, y: drag.my }) : ''
})

function local(e) {
  const r = canvas.value.getBoundingClientRect()
  return { x: e.clientX - r.left, y: e.clientY - r.top }
}

// ---- move a box ----
function startMove(e, n) {
  if (e.button !== 0) return
  const p = local(e)
  drag.mode = 'move'; drag.id = n.id; drag.ox = p.x - n.x; drag.oy = p.y - n.y
  window.addEventListener('pointermove', onMove); window.addEventListener('pointerup', endDrag)
}
// ---- drag a wire from an output port ----
function startWire(e, n) {
  if (e.button !== 0) return
  e.stopPropagation()
  const p = local(e)
  drag.mode = 'wire'; drag.fromId = n.id; drag.mx = p.x; drag.my = p.y
  window.addEventListener('pointermove', onMove); window.addEventListener('pointerup', endDrag)
}
function onMove(e) {
  const p = local(e)
  if (drag.mode === 'move') {
    const n = nodeById(drag.id)
    if (n) { n.x = Math.max(0, p.x - drag.ox); n.y = Math.max(0, p.y - drag.oy) }
  } else if (drag.mode === 'wire') {
    drag.mx = p.x; drag.my = p.y
  }
}
function endDrag(e) {
  if (drag.mode === 'wire') {
    const p = local(e)
    const target = nodes.find(n => n.id !== drag.fromId &&
      Math.hypot(inPort(n).x - p.x, inPort(n).y - p.y) <= 16)     // dropped on a box's input port?
    if (target) connect(drag.fromId, target.id)
  }
  if (drag.mode === 'move') emitChange()          // persist the new position
  window.removeEventListener('pointermove', onMove); window.removeEventListener('pointerup', endDrag)
  drag.mode = null; drag.id = null; drag.fromId = null
}
function connect(from, to) {
  if (from === to) return
  if (isTerminal(nodeById(from)?.tool)) return    // a findings box has no output (shouldn't happen: no port)
  // a box takes at most one input — replace any existing incoming edge on the target
  for (let i = edges.length - 1; i >= 0; i--) if (edges[i].to === to) edges.splice(i, 1)
  // reject a direct back-edge (from is already downstream of to) to avoid the obvious 2-cycle; the server
  // validates deeper cycles and surfaces the message.
  if (edges.some(e => e.from === to && e.to === from)) return
  edges.push({ from, to })
  emitChange()
}

onMounted(() => {
  for (const n of (props.initial?.nodes || [])) {
    nodes.push({ id: n.id, tool: n.tool, args: n.args || '', x: n.x ?? 40, y: n.y ?? 40 })
    const num = parseInt(String(n.id).replace(/\D/g, '')); if (num > seq) seq = num
  }
  for (const e of (props.initial?.edges || [])) edges.push({ from: e.from, to: e.to })
  nextTick(emitChange)
})
onBeforeUnmount(() => {
  window.removeEventListener('pointermove', onMove); window.removeEventListener('pointerup', endDrag)
})
</script>

<template>
  <div class="gc">
    <div class="gc-bar">
      <div class="gc-add"><Select v-model="addTool" :options="toolOpts" placeholder="+ add a tool box…" @change="addNode" /></div>
      <span class="muted" style="font-size:12px">Drag a box to move · drag its right dot onto another box's left dot to wire · findings tools have no output.</span>
    </div>
    <div ref="canvas" class="gc-canvas" :class="{ wiring: drag.mode === 'wire' }">
      <svg class="gc-edges">
        <path v-if="tempPath" :d="tempPath" class="gc-edge gc-temp" />
        <g v-for="p in edgePaths" :key="p.from + '>' + p.to">
          <path :d="p.d" class="gc-edge-hit" @click="removeEdge(p.from, p.to)" />
          <path :d="p.d" class="gc-edge" />
        </g>
      </svg>

      <div v-for="n in nodes" :key="n.id" class="gc-node" :style="{ left: n.x + 'px', top: n.y + 'px', width: BOX_W + 'px' }">
        <div class="gc-in" :title="'input'"></div>
        <div v-if="!isTerminal(n.tool)" class="gc-out" title="drag to wire" @pointerdown="startWire($event, n)"></div>
        <div class="gc-node-head" @pointerdown="startMove($event, n)">
          <span class="gc-tool">{{ n.tool }}</span>
          <span class="tag sm" :class="isTerminal(n.tool) ? 'kind-ai_agent' : 'kind-workflow'">{{ kindOf(n.tool) }}</span>
          <button class="danger ghost icon gc-x" title="Remove" @pointerdown.stop @click="removeNode(n.id)">✕</button>
        </div>
        <input class="gc-args" :value="n.args" placeholder="args (optional)"
               @pointerdown.stop @input="setArgs(n, $event.target.value)" />
      </div>

      <div v-if="!nodes.length" class="gc-empty">Add a tool box to start.</div>
    </div>
  </div>
</template>

<style scoped>
.gc { display: flex; flex-direction: column; gap: 8px; }
.gc-bar { display: flex; align-items: center; gap: 12px; }
.gc-add { width: 260px; }
.gc-canvas {
  position: relative; height: 460px; border: 1px solid var(--line, var(--border, #ddd)); border-radius: 10px;
  background: var(--panel-2, var(--panel)); overflow: hidden;
  background-image: radial-gradient(var(--line, #e3e3e3) 1px, transparent 1px); background-size: 20px 20px;
}
.gc-canvas.wiring { cursor: crosshair; }
.gc-edges { position: absolute; inset: 0; width: 100%; height: 100%; pointer-events: none; overflow: visible; }
.gc-edge { fill: none; stroke: var(--accent, #5865f2); stroke-width: 2; }
.gc-edge.gc-temp { stroke-dasharray: 5 4; opacity: .7; }
.gc-edge-hit { fill: none; stroke: transparent; stroke-width: 12; pointer-events: stroke; cursor: pointer; }
.gc-node {
  position: absolute; border: 1px solid var(--line, #ccc); border-radius: 8px; background: var(--panel, #fff);
  box-shadow: 0 1px 3px rgba(0,0,0,.12); user-select: none;
}
.gc-node-head { display: flex; align-items: center; gap: 6px; padding: 8px 10px; cursor: grab; }
.gc-node-head:active { cursor: grabbing; }
.gc-tool { font-weight: 600; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.gc-x { margin-left: auto; }
.gc-args { margin: 0 8px 8px; width: calc(100% - 16px); font-size: 12px; }
.gc-in, .gc-out {
  position: absolute; top: 18px; width: 14px; height: 14px; border-radius: 50%;
  background: var(--panel, #fff); border: 2px solid var(--accent, #5865f2);
}
.gc-in { left: -8px; }
.gc-out { right: -8px; cursor: crosshair; background: var(--accent, #5865f2); }
.gc-empty { position: absolute; inset: 0; display: grid; place-items: center; color: var(--muted); font-size: 13px; }
</style>
