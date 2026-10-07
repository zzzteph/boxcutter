<script setup>
// A small dependency-free node-graph editor: draggable tool boxes wired producer -> consumer. Boxes are
// absolutely-positioned divs; edges are SVG bezier paths under them. Ports are typed from the tool catalog —
// a `findings` (terminal) tool has NO output port, so it can't feed a downstream box. A box may take MULTIPLE
// inputs (fan-in): it then runs on the UNION of every upstream's URLs. The graph stays a DAG (direct back-edges
// are rejected; the server validates deeper cycles). Owns its {nodes, edges} state and emits `change`; seed via
// :initial. The canvas is zoomable (the +/− controls or ctrl/⌘ + wheel).
import { ref, reactive, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'

const props = defineProps({
  initial: { type: Object, default: () => ({ nodes: [], edges: [] }) },
  catalog: { type: Array, default: () => [] },
  // LIVE/read-only mode: render a saved graph as a running-scan monitor — no editing, boxes coloured by state.
  live: { type: Boolean, default: false },
  states: { type: Object, default: () => ({}) },   // { nodeId: {state, items, findings, running, done} }
  selected: { type: String, default: '' },         // the box the parent has drilled into
})
const emit = defineEmits(['change', 'select'])
const stateOf = (id) => props.states[id] || null
function selectNode(n) { if (props.live) emit('select', n.id) }

const BOX_W = 190
const PORT_DY = 26            // wire anchor: this far below a box's top-left

const nodes = reactive([])    // {id, tool, args, x, y}
const edges = reactive([])    // {from, to}
let seq = 0

const canvas = ref(null)
const drag = reactive({ mode: null, id: null, ox: 0, oy: 0, fromId: null, mx: 0, my: 0, px: 0, py: 0 })

// pan: a view offset for the whole world, so you can drag the empty canvas to move everything around. Applied
// as a translate BEFORE the zoom scale; pointer->world conversion subtracts it (see local()).
const pan = reactive({ x: 0, y: 0 })

// zoom: the node/edge world is scaled from the top-left; pointer coords are divided by it (see local()).
const zoom = ref(1)
function zoomBy(d) { zoom.value = Math.min(1.6, Math.max(0.4, Math.round((zoom.value + d) * 100) / 100)) }
function zoomReset() { zoom.value = 1; pan.x = 0; pan.y = 0 }
function onWheel(e) { if (e.ctrlKey || e.metaKey) { e.preventDefault(); zoomBy(e.deltaY < 0 ? 0.1 : -0.1) } }

// Auto-arrange into clean left->right layers by wiring DEPTH (longest path from a root): roots in column 0, each
// box one column right of its deepest parent, same-depth boxes stacked. On by default - it re-tidies on every
// structural change (add box / wire / remove) so the graph stays readable; turn it off to hand-place boxes.
const autoArrange = ref(true)
let raf = null
// smoothly tween every box from where it is now to its layout target, so boxes AND their wires glide together
// (edges follow because they're bound to n.x/n.y) — far less disorienting than everything teleporting at once.
function animateTo(targets) {
  cancelAnimationFrame(raf)
  const start = nodes.filter(n => targets[n.id]).map(n => ({ n, x0: n.x, y0: n.y, x1: targets[n.id].x, y1: targets[n.id].y }))
  const t0 = performance.now(), dur = 360, ease = (t) => 1 - Math.pow(1 - t, 3)
  function step(now) {
    const e = ease(Math.min(1, (now - t0) / dur))
    for (const s of start) { s.n.x = s.x0 + (s.x1 - s.x0) * e; s.n.y = s.y0 + (s.y1 - s.y0) * e }
    if ((now - t0) < dur) raf = requestAnimationFrame(step)
    else { for (const s of start) { s.n.x = s.x1; s.n.y = s.y1 } emitChange() }
  }
  raf = requestAnimationFrame(step)
}
function tidy(resetZoom = false) {
  if (!nodes.length) return
  if (resetZoom) zoomReset()
  const depth = {}
  for (const n of nodes) depth[n.id] = 0
  for (let pass = 0; pass < nodes.length; pass++) {      // relax to a fixpoint (DAG -> converges)
    let changed = false
    for (const e of edges) {
      const d = (depth[e.from] || 0) + 1
      if (d > (depth[e.to] || 0)) { depth[e.to] = d; changed = true }
    }
    if (!changed) break
  }
  const layers = {}
  for (const n of nodes) (layers[depth[n.id] || 0] ||= []).push(n)
  const COL_X = 40, COL_GAP = 260, ROW_Y = 24, ROW_GAP = 26
  const cols = Object.keys(layers).map(Number).sort((a, b) => a - b)
  for (const d of cols) layers[d].sort((a, b) => a.y - b.y)   // keep each column's existing top-to-bottom order
  // vertically CENTER the whole block in the (now large) canvas so tidy fills the space nicely, not a thin strip
  const worldH = ((canvas.value && canvas.value.clientHeight) || 540) / zoom.value
  const colH = (d) => layers[d].reduce((s, n) => s + nodeH(n.id) + ROW_GAP, 0) - ROW_GAP
  const tallest = Math.max(0, ...cols.map(colH))
  const startY = Math.max(ROW_Y, (worldH - tallest) / 2)
  // stack each column by the boxes' ACTUAL rendered heights (a filter box is much taller than a plain tool), so
  // tall boxes never overlap the one below. Compute targets, then glide the boxes there.
  const targets = {}
  for (const d of cols) {
    let y = startY
    for (const n of layers[d]) { targets[n.id] = { x: COL_X + d * COL_GAP, y }; y += nodeH(n.id) + ROW_GAP }
  }
  animateTo(targets)
}
function nodeH(id) {        // measured box height (DOM), so the auto-layout accounts for tall boxes; fallback ~150
  const el = canvas.value && canvas.value.querySelector(`[data-id="${id}"]`)
  return (el && el.offsetHeight) || 150
}
function autoLayout() { tidy(true) }                     // the manual Tidy button (also recenters zoom)
// after an add/wire/remove: re-tidy if auto-arrange is on, else just persist. Manual drags never trigger this.
function structural() { if (autoArrange.value) tidy(false); else emitChange() }
function toggleAuto() { autoArrange.value = !autoArrange.value; if (autoArrange.value) tidy(true) }

// right-click on the canvas -> a TWO-LEVEL context menu: pick a group, then a box (with its info) from that
// group's submenu. `group` is the currently-opened group (null = show only the group list).
const ctx = reactive({ open: false, cx: 0, cy: 0, wx: 0, wy: 0, group: '', up: false, maxh: 400 })
const activeGroup = computed(() => grouped.value.find(g => g.group === ctx.group) || null)
// keep the menu on-screen: clamp its left edge, and anchor it from the top OR bottom (flip up near the bottom
// edge) with a max-height that fits the available space, so it never spills off-screen and scrolls when tall.
const ctxMenuStyle = computed(() => ({
  left: ctx.cx + 'px', maxHeight: ctx.maxh + 'px',
  [ctx.up ? 'bottom' : 'top']: ctx.cy + 'px',
}))
function onContextMenu(e) {
  if (props.live) return                                  // read-only: no add-box menu
  const r = canvas.value.getBoundingClientRect()
  ctx.wx = (e.clientX - r.left - pan.x) / zoom.value      // world coords (undo pan + zoom) for the new box
  ctx.wy = (e.clientY - r.top - pan.y) / zoom.value
  const vw = window.innerWidth, vh = window.innerHeight
  ctx.cx = Math.max(8, Math.min(e.clientX, vw - 320))     // keep the ~310px-wide menu fully on-screen
  const below = vh - e.clientY - 12
  if (below < 280 && e.clientY > vh / 2) {                // near the bottom: anchor to the bottom, grow upward
    ctx.up = true; ctx.cy = vh - e.clientY; ctx.maxh = e.clientY - 12
  } else {
    ctx.up = false; ctx.cy = e.clientY; ctx.maxh = below
  }
  ctx.group = ''                                          // always start at the group list
  ctx.open = true
}
// drop the box where the cursor was (top-left at the click point). Auto-arrange still governs: with it ON the
// box snaps into the tidy layout; turn it OFF to hand-place and the drop position is kept exactly.
function ctxAdd(tool) { addNode(tool, Math.max(0, ctx.wx), Math.max(0, ctx.wy), !autoArrange.value); ctx.open = false }
function closeCtx() { ctx.open = false; ctx.group = '' }

const kindOf = (tool) => props.catalog.find(t => t.name === tool)?.kind || ''
const isTerminal = (tool) => !!props.catalog.find(t => t.name === tool)?.terminal
const hasInput = (id) => edges.some(e => e.to === id)   // is this box fed by an upstream box?

// a distinct colour per pipeline GROUP (recon / crawl / scanners / fuzz / …) so you can read the graph at a
// glance instead of a wall of same-coloured boxes. Keyed by the catalog's `group`.
const GROUP_COLOR = {
  Recon: '#4f9dde', Crawl: '#9b7bd4', 'Vuln scanners': '#e5704b', Fuzzing: '#e0a03a', Secrets: '#d65db1',
  'API specs': '#3fae9f', GraphQL: '#e5556f', Flow: '#7c8794', Generic: '#6b8f3a', Other: '#8f9099',
}
const groupOf = (tool) => props.catalog.find(t => t.name === tool)?.group || 'Other'
const colorOf = (tool) => GROUP_COLOR[groupOf(tool)] || GROUP_COLOR.Other

// ---- wiring compatibility (#6) + fan-out boundaries (#3) ----
const FLOW = new Set(['aggregate', 'filter', 'limit', 'hosts'])
const isFlow = (tool) => FLOW.has(tool)
// the EFFECTIVE output kind of a box: a normal box is its catalog kind; a flow box is 'findings' only when every
// input it has is findings (it filters the findings set), else it passes URLs/items. Mirrors the compiler so the
// canvas rejects exactly the wirings the server would.
function outKind(id, seen) {
  const n = nodeById(id)
  if (!n) return ''
  if (!isFlow(n.tool)) return kindOf(n.tool)
  seen = seen || new Set()
  if (seen.has(id)) return 'urls'
  seen.add(id)
  const parents = edges.filter(e => e.to === id).map(e => e.from)
  return parents.length && parents.every(p => outKind(p, seen) === 'findings') ? 'findings' : 'urls'
}
// the EFFECTIVE input type a box receives: the scan target (a host/URL) when nothing feeds it, else what its
// upstream boxes emit (findings if any parent emits findings, else their URLs/items).
function inKind(id) {
  const parents = edges.filter(e => e.to === id).map(e => e.from)
  if (!parents.length) return 'target'
  const kinds = parents.map(p => outKind(p))
  return kinds.includes('findings') ? 'findings' : (kinds[0] || 'urls')
}

// #10: give each data TYPE a distinct colour + port SHAPE, so you can read at a glance what flows in and out of
// each box (and a mismatch stands out). Applied to the in/out dots below.
const KIND_COLOR = { target: '#8f9099', urls: '#4f9dde', items: '#3fae9f', endpoints: '#9b7bd4',
                     findings: '#e5556f', screenshots: '#e0a03a' }
const KIND_SHAPE = { target: 'circle', urls: 'circle', items: 'square', endpoints: 'pill',
                     findings: 'diamond', screenshots: 'square' }
const kindColor = (k) => KIND_COLOR[k] || 'var(--accent, #5865f2)'
const kindShape = (k) => 'gc-port-' + (KIND_SHAPE[k] || 'circle')
// plain-language gloss for each data type — "items" especially isn't self-explanatory.
const KIND_HELP = {
  target: 'the scan target you enter (a host, URL or domain)',
  urls: 'hostnames / URLs this step found — each one becomes a target for the next box',
  items: 'a list of results this step produced (live URLs, endpoints or records) — each one becomes a target for the next box',
  endpoints: 'host:port services, e.g. from a port scan',
  findings: 'security issues — terminal: a findings box can only feed a filter / limit box',
  screenshots: 'captured page images',
}
const kindHelp = (k) => KIND_HELP[k] || ''

// #9: the tool's one-line description (from the catalog), shown on the box so you know what it does.
const descOf = (tool) => props.catalog.find(t => t.name === tool)?.description || ''
// a SPECIFIC noun for what the box produces (e.g. httpx -> "live HTTP services (URLs)") instead of the generic
// output kind ("items"), which is shared by many unrelated tools. Falls back to the kind.
const producesOf = (tool) => props.catalog.find(t => t.name === tool)?.produces || kindOf(tool) || 'items'
// what the box needs as input (e.g. "a domain", "a URL") — so you know what to give it / wire into it.
const acceptsOf = (tool) => props.catalog.find(t => t.name === tool)?.accepts || ''

// ---- data-flow emulation: a REPRESENTATION (not a real scan) of the example values that flow between boxes,
// so you can see what a box produces and what the next box down the wire will receive. Keyed off the data TYPE
// and propagated along the chain (each box "takes" what its upstream "gives").
const showFlow = ref(true)
const KIND_SAMPLE = {
  target: ['example.com'],
  urls: ['api.example.com', 'admin.example.com', 'shop.example.com'],
  items: ['https://api.example.com', 'https://admin.example.com'],
  endpoints: ['example.com:443', 'example.com:8080'],
  findings: ['[high] SQL injection — /login', '[medium] exposed .git'],
  screenshots: ['api.example.com.png', 'admin.example.com.png'],
}
const sampleFor = (kind) => KIND_SAMPLE[kind] || KIND_SAMPLE.urls
// what a box RECEIVES: the scan target when nothing feeds it, else its upstream's output type.
function takeInfo(id) {
  if (!edges.some(e => e.to === id)) return { kind: 'target', eg: KIND_SAMPLE.target }
  const k = inKind(id)
  return { kind: k, eg: sampleFor(k) }
}
// what a box GIVES: example values of its own output type.
function giveInfo(id) {
  const k = outKind(id)
  return { kind: k, eg: sampleFor(k) }
}
const egText = (arr) => arr.slice(0, 2).join(', ') + (arr.length > 2 ? ' …' : '')

// a transient "why that wasn't allowed" banner for rejected wirings
const warnMsg = ref('')
let warnTmr = null
function warn(m) { warnMsg.value = m; clearTimeout(warnTmr); warnTmr = setTimeout(() => { warnMsg.value = '' }, 4500) }

// arg validation (#7): a box's extra args that the tool would reject at run time. Tool-native scanner flags must
// go through --opt-args (so we don't validate inside that passthrough). Empty for a tool with no known flag list.
const flagsOf = (tool) => props.catalog.find(t => t.name === tool)?.flags || []
function argIssues(n) {
  const allowed = flagsOf(n.tool)
  if (!allowed.length || !n.args) return []
  const bad = []
  let skip = false
  for (const t of String(n.args).trim().split(/\s+/).filter(Boolean)) {
    if (skip) { skip = false; continue }               // value after --opt-args is forwarded verbatim
    if (/^-/.test(t) && !/^-[\d.]/.test(t)) {
      const f = t.split('=')[0]
      if (!allowed.includes(f)) bad.push(f)
      else if (f === '--opt-args') skip = true
    }
  }
  return [...new Set(bad)]
}

const findEdge = (from, to) => edges.find(e => e.from === from && e.to === to)
// toggle a wire between CHAIN (runs in one process) and FAN-OUT (the downstream boxes become their own stage,
// run as separate per-item jobs across the whole fleet). See compile_pipeline / scans._builder_stages.
function toggleSplit(from, to) {
  const e = findEdge(from, to)
  if (!e) return
  const toTool = nodeById(to)?.tool
  if (!e.split && isFlow(toTool)) {           // can't fan OUT into a flow box — it combines items in one process
    warn(`${toTool} combines items in one process — a fan-out can't feed it. Put the fan-out AFTER it.`)
    return
  }
  e.split = !e.split
  if (e.split && !e.item_filter) e.item_filter = 'all'
  structural()
}
function setEdgeFilter(from, to, f) { const e = findEdge(from, to); if (e) { e.item_filter = f; emitChange() } }
// the "add a box" PALETTE: the catalog arrives sorted by pipeline stage; group it so you click a tool to drop
// a box, instead of hunting in a dropdown.
const paletteOpen = ref(false)
const grouped = computed(() => {
  const order = []; const map = {}
  for (const t of props.catalog) {
    const g = t.group || 'Other'
    if (!map[g]) { map[g] = { group: g, tools: [] }; order.push(map[g]) }
    map[g].tools.push(t)
  }
  return order
})
function pick(tool) { addNode(tool) }      // keep the palette open so several boxes can be added in a row

// the `filter` box carries MULTIPLE conditions (all must pass): each row is contains(keep)/excludes(reject)+text.
// (Per-box contains/excludes was removed — use a dedicated `filter` box for that.)
const condsOf = (n) => n.conditions || []
function addCond(n) { if (!n.conditions) n.conditions = []; n.conditions.push({ mode: 'contains', value: '' }); emitChange() }
function rmCond(n, i) { (n.conditions || []).splice(i, 1); emitChange() }
function toggleCondRow(n, i) { const c = n.conditions[i]; c.mode = c.mode === 'excludes' ? 'contains' : 'excludes'; emitChange() }
function setCondRowVal(n, i, v) { n.conditions[i].value = v; emitChange() }

// per-box "repeat until stable": re-run this box on its own newly-discovered URLs until nothing new (bounded).
const repeatOf = (n) => n.repeat || null
function toggleRepeat(n) { n.repeat = n.repeat ? null : { max: 3 }; emitChange() }
function setRepeatMax(n, v) { n.repeat = { max: Math.max(1, Math.min(10, parseInt(v, 10) || 3)) }; emitChange() }

function emitChange() {
  emit('change', {
    nodes: nodes.map(n => ({ id: n.id, tool: n.tool, args: n.args, optargs: n.optargs || '', x: n.x, y: n.y,
                             when: n.when || null, conditions: n.conditions || null, repeat: n.repeat || null })),
    edges: edges.map(e => e.split
      ? { from: e.from, to: e.to, split: true, item_filter: e.item_filter || 'all' }
      : { from: e.from, to: e.to }),
  })
}

function addNode(tool, px, py, fixed) {
  if (!tool) return
  const id = 'b' + (++seq)
  // px/py set when added via right-click (drop at the cursor); else stagger so boxes don't stack exactly
  nodes.push({ id, tool, args: '', optargs: '', when: null, conditions: tool === 'filter' ? [{ mode: 'contains', value: '' }] : null, repeat: null, x: px ?? (40 + (nodes.length % 4) * 40), y: py ?? (40 + (nodes.length % 6) * 30) })
  // a deliberately-placed box (right-click drop) keeps its spot — persist without auto-arranging it away.
  if (fixed) emitChange(); else structural()
}
function removeNode(id) {
  const i = nodes.findIndex(n => n.id === id)
  if (i >= 0) nodes.splice(i, 1)
  for (let j = edges.length - 1; j >= 0; j--) if (edges[j].from === id || edges[j].to === id) edges.splice(j, 1)
  structural()
}
function removeEdge(from, to) {
  const i = edges.findIndex(e => e.from === from && e.to === to)
  if (i >= 0) { edges.splice(i, 1); structural() }
}
function setArgs(n, v) { n.args = v; emitChange() }
function setOptArgs(n, v) { n.optargs = v; emitChange() }
// does this tool accept --opt-args (verbatim passthrough to the underlying binary)? only then show the field.
const optArgsSupported = (tool) => flagsOf(tool).includes('--opt-args')

// ---- geometry (canvas-local coords) ----
const nodeById = (id) => nodes.find(n => n.id === id)
const outPort = (n) => ({ x: n.x + BOX_W, y: n.y + PORT_DY })
const inPort = (n) => ({ x: n.x, y: n.y + PORT_DY })
function bezier(a, b) {
  const dx = Math.max(40, Math.abs(b.x - a.x) / 2)
  return `M ${a.x} ${a.y} C ${a.x + dx} ${a.y}, ${b.x - dx} ${b.y}, ${b.x} ${b.y}`
}
// rounded right-angle path through waypoints (each interior corner filleted by radius r)
function roundedPath(pts, r) {
  let d = `M ${pts[0][0]} ${pts[0][1]}`
  for (let i = 1; i < pts.length - 1; i++) {
    const [px, py] = pts[i - 1], [x, y] = pts[i], [nx, ny] = pts[i + 1]
    const l1 = Math.hypot(px - x, py - y) || 1, l2 = Math.hypot(nx - x, ny - y) || 1
    const d1 = Math.min(r, l1 / 2), d2 = Math.min(r, l2 / 2)
    d += ` L ${x + (px - x) / l1 * d1} ${y + (py - y) / l1 * d1}`
    d += ` Q ${x} ${y} ${x + (nx - x) / l2 * d2} ${y + (ny - y) / l2 * d2}`
  }
  const last = pts[pts.length - 1]
  return d + ` L ${last[0]} ${last[1]}`
}
const minNodeY = computed(() => nodes.length ? Math.min(...nodes.map(n => n.y)) : 0)
const EDGE_GUT = 26                  // how far into the gutter the over-the-top risers sit
const SPAN_OVER = 230               // a wire wider than this skips a column → route it over the top, not through
// an edge wide enough to cross an intermediate column is routed UP into the clear lane above every box, across,
// and back DOWN — so a connection never passes under a box it doesn't belong to. Adjacent boxes keep the curve.
const edgePaths = computed(() => edges.map(e => {
  const a = nodeById(e.from), b = nodeById(e.to)
  if (!a || !b) return null
  const pa = outPort(a), pb = inPort(b)
  let d, mx, my
  if (pb.x - pa.x > SPAN_OVER) {
    const lane = Math.min(pa.y, pb.y, minNodeY.value) - 34       // horizontal channel above all boxes = clear
    const x1 = pa.x + EDGE_GUT, x2 = pb.x - EDGE_GUT
    d = roundedPath([[pa.x, pa.y], [x1, pa.y], [x1, lane], [x2, lane], [x2, pb.y], [pb.x, pb.y]], 12)
    mx = (x1 + x2) / 2; my = lane
  } else {
    d = bezier(pa, pb); mx = (pa.x + pb.x) / 2; my = (pa.y + pb.y) / 2
  }
  return { from: e.from, to: e.to, d, split: !!e.split, filter: e.item_filter || 'all', mx, my }
}).filter(Boolean))
const tempPath = computed(() => {
  if (drag.mode !== 'wire') return ''
  const a = nodeById(drag.fromId)
  return a ? bezier(outPort(a), { x: drag.mx, y: drag.my }) : ''
})

function local(e) {
  const r = canvas.value.getBoundingClientRect()
  // the world is translated by pan then scaled from 0,0 — undo both to get world coords
  return { x: (e.clientX - r.left - pan.x) / zoom.value, y: (e.clientY - r.top - pan.y) / zoom.value }
}

// ---- pan the whole canvas by dragging empty background ----
function startPan(e) {
  if (e.button !== 0) return
  // only grab EMPTY canvas — not a box, port, wire, label or control (those start their own drag / click)
  const cl = e.target && e.target.classList
  if (!cl || !(cl.contains('gc-world') || cl.contains('gc-canvas') || cl.contains('gc-edges')
               || cl.contains('gc-empty'))) return
  drag.mode = 'pan'; drag.px = e.clientX - pan.x; drag.py = e.clientY - pan.y
  window.addEventListener('pointermove', onMove); window.addEventListener('pointerup', endDrag)
}

// ---- move a box ----
function startMove(e, n) {
  if (e.button !== 0 || props.live) return                // live mode is read-only (no dragging boxes)
  const p = local(e)
  drag.mode = 'move'; drag.id = n.id; drag.ox = p.x - n.x; drag.oy = p.y - n.y
  window.addEventListener('pointermove', onMove); window.addEventListener('pointerup', endDrag)
}
// ---- drag a wire from an output port ----
function startWire(e, n) {
  if (e.button !== 0 || props.live) return
  e.stopPropagation()
  const p = local(e)
  drag.mode = 'wire'; drag.fromId = n.id; drag.mx = p.x; drag.my = p.y
  window.addEventListener('pointermove', onMove); window.addEventListener('pointerup', endDrag)
}
function onMove(e) {
  if (drag.mode === 'pan') { pan.x = e.clientX - drag.px; pan.y = e.clientY - drag.py; return }
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
  if (edges.some(e => e.from === from && e.to === to)) return   // already wired — no duplicate
  // reject a direct back-edge (from is already downstream of to) to avoid the obvious 2-cycle; the server
  // validates deeper cycles and surfaces the message.
  if (edges.some(e => e.from === to && e.to === from)) return
  // compatibility (#6): a box that outputs FINDINGS can only feed a flow box (filter/limit/aggregate/hosts),
  // never a scanner/tool that needs a target — the same rule the compiler enforces. Block it here with a reason
  // so you don't discover it only when the preview turns red.
  const fromTool = nodeById(from)?.tool, toTool = nodeById(to)?.tool
  if (outKind(from) === 'findings' && !isFlow(toTool)) {
    warn(`${fromTool} outputs findings — it can only feed a flow box (filter, limit, aggregate, hosts), not ${toTool}.`)
    return
  }
  // AUTO fan-out: a wire into a heavy per-target tool (nuclei/sqlmap/zap/harvest/…) defaults to fan-out, so its
  // work is distributed across the whole fleet without you toggling anything. Light/batch/domain tools stay a
  // single step. Only on the box's FIRST wire-in (avoids creating a fan-in across a split, which can't compile);
  // you can always toggle any wire. Findings/other types can't be fanned out as targets.
  const auto = fanoutOf(toTool) && ['urls', 'items', 'endpoints'].includes(outKind(from)) && !edges.some(e => e.to === to)
  // fan-in allowed: a box may have several incoming edges; it runs on the union of its upstreams' URLs.
  edges.push(auto ? { from, to, split: true, item_filter: 'all' } : { from, to })
  structural()
}
const fanoutOf = (tool) => !!props.catalog.find(t => t.name === tool)?.fanout

onMounted(() => {
  for (const n of (props.initial?.nodes || [])) {
    nodes.push({ id: n.id, tool: n.tool, args: n.args || '', optargs: n.optargs || '', when: n.when || null, conditions: n.conditions || null, repeat: n.repeat || null, x: n.x ?? 40, y: n.y ?? 40 })
    const num = parseInt(String(n.id).replace(/\D/g, '')); if (num > seq) seq = num
  }
  for (const e of (props.initial?.edges || []))
    edges.push({ from: e.from, to: e.to, split: !!e.split, item_filter: e.item_filter || 'all' })
  // tidy a loaded/seeded graph once the boxes have rendered (so a saved mess lays itself out), then persist.
  nextTick(() => { if (autoArrange.value && nodes.length) tidy(false); else emitChange() })
})
onBeforeUnmount(() => {
  window.removeEventListener('pointermove', onMove); window.removeEventListener('pointerup', endDrag)
  cancelAnimationFrame(raf)
})
</script>

<template>
  <div class="gc">
    <div class="gc-bar">
      <button v-if="!live" class="gc-addbtn" @click="paletteOpen = !paletteOpen">{{ paletteOpen ? '✕ Close' : '➕ Add a box' }}</button>
      <span v-if="!live" class="muted" style="font-size:12px">A box with no wire in runs on the <b>scan Target</b> (the
        host/URL/domain you give the scan) · a wired box runs on what feeds it · drag a box's right dot onto
        another's left dot to wire · a box can take several inputs · a wire into a heavy scanner
        <b>auto fan-outs</b> across the fleet (click any wire to toggle chain ↔ fan-out).</span>
      <span v-else class="muted" style="font-size:12px">Live run — <b style="color:var(--bad)">red</b> = running,
        <b style="color:var(--good)">green</b> = done, grey = waiting. Click a box for its logs across every agent.</span>
      <span class="gc-zoom">
        <button v-if="!live" class="gc-zbtn" :class="{ on: autoArrange }"
                title="Keep the graph auto-arranged on every change (off = place boxes by hand)"
                @click="toggleAuto">auto {{ autoArrange ? 'on' : 'off' }}</button>
        <button class="gc-zbtn gc-tidy" title="Auto-arrange the boxes into tidy left→right layers now" @click="autoLayout">⤢ Tidy</button>
        <button v-if="!live" class="gc-zbtn" :class="{ on: showFlow }"
                title="Show an example of the data flowing in and out of each box (a representation by type, not a real scan)"
                @click="showFlow = !showFlow">flow {{ showFlow ? 'on' : 'off' }}</button>
        <button class="gc-zbtn" title="Zoom out" @click="zoomBy(-0.1)">−</button>
        <button class="gc-zbtn gc-zlabel" title="Reset zoom" @click="zoomReset">{{ Math.round(zoom * 100) }}%</button>
        <button class="gc-zbtn" title="Zoom in" @click="zoomBy(0.1)">+</button>
      </span>
    </div>
    <div v-if="!live" class="gc-legend">
      <span class="muted" style="font-size:11px">port types:</span>
      <span v-for="(c, k) in KIND_COLOR" :key="k" class="gc-leg" :title="kindHelp(k)">
        <span class="gc-legdot" :class="'gc-port-' + (KIND_SHAPE[k] || 'circle')" :style="{ background: c, borderColor: c }"></span>{{ k }}
      </span>
    </div>
    <div v-if="warnMsg" class="gc-warn">⚠ {{ warnMsg }}</div>
    <div v-if="paletteOpen" class="gc-palette">
      <div v-for="g in grouped" :key="g.group" class="gc-pcol">
        <div class="gc-pgroup"><span class="gc-dot" :style="{ background: GROUP_COLOR[g.group] || '#8f9099' }"></span>{{ g.group }}</div>
        <button v-for="t in g.tools" :key="t.name" class="gc-chip"
                :style="{ borderLeft: '3px solid ' + (GROUP_COLOR[g.group] || '#8f9099') }" @click="pick(t.name)">
          <span class="gc-chiphead"><span class="gc-chipn">{{ t.name }}</span><span class="gc-chipk">out: {{ t.produces || t.kind }}</span></span>
          <span class="gc-chipd">{{ t.description || 'no description' }}</span>
        </button>
      </div>
    </div>
    <div ref="canvas" class="gc-canvas" :class="{ wiring: drag.mode === 'wire', panning: drag.mode === 'pan' }"
         @wheel="onWheel" @pointerdown="startPan" @contextmenu.prevent="onContextMenu">
      <div class="gc-world" :style="{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`, transformOrigin: '0 0' }">
      <svg class="gc-edges">
        <path v-if="tempPath" :d="tempPath" class="gc-edge gc-temp" />
        <g v-for="p in edgePaths" :key="p.from + '>' + p.to">
          <path :d="p.d" class="gc-edge-hit" @click="removeEdge(p.from, p.to)" />
          <path :d="p.d" class="gc-edge" :class="{ 'gc-edge-split': p.split }" />
        </g>
      </svg>

      <!-- per-wire control: toggle CHAIN <-> FAN-OUT, and (when fanned out) how items feed the next stage -->
      <div v-for="p in edgePaths" :key="'e' + p.from + '>' + p.to" class="gc-elabel"
           :style="{ left: p.mx + 'px', top: p.my + 'px' }">
        <!-- LIVE: a fan-out wire is a HUB — the upstream jobs' results merge, then split into N jobs. Show the
             regroup with real numbers (done/total) so the merge→fan is visible; a chain wire shows nothing. -->
        <template v-if="live">
          <span v-if="p.split" class="gc-hub"
                title="Fan-out hub: the results of the boxes before this merge into one deduped set, then split into jobs spread across the fleet.">
            ⑂ merge → {{ (stateOf(p.to) || {}).done || 0 }}/{{ (stateOf(p.to) || {}).total || 0 }} jobs</span>
        </template>
        <template v-else>
          <button class="gc-split" :class="{ on: p.split }" @click="toggleSplit(p.from, p.to)"
            :title="p.split ? 'Fan-out: the boxes before this merge into one deduped set (a hub), then split into separate jobs across the whole fleet. Click for a single-process chain.' : 'Chain: runs in one process on one agent. Click to FAN OUT the downstream work across the fleet.'">
            {{ p.split ? '⑂ fan-out' : '→ chain' }}</button>
          <select v-if="p.split" class="gc-efilter" :value="p.filter"
            title="which of this stage's items become the next stage's targets"
            @change="setEdgeFilter(p.from, p.to, $event.target.value)">
            <option value="all">all items</option>
            <option value="urls">URLs only</option>
          </select>
        </template>
      </div>

      <div v-for="n in nodes" :key="n.id" class="gc-node" :data-id="n.id"
           :class="[live ? 'gc-live gc-st-' + (stateOf(n.id)?.state || 'pending') : '', { 'gc-sel': live && selected === n.id }]"
           :style="{ left: n.x + 'px', top: n.y + 'px', width: BOX_W + 'px', borderLeftColor: colorOf(n.tool), borderLeftWidth: '3px' }"
           @click="selectNode(n)">
        <div class="gc-in" :class="kindShape(inKind(n.id))" :style="{ borderColor: kindColor(inKind(n.id)) }"
             :title="'input (' + inKind(n.id) + '): ' + kindHelp(inKind(n.id))"></div>
        <div v-if="!isTerminal(n.tool)" class="gc-out" :class="kindShape(outKind(n.id))"
             :style="{ background: kindColor(outKind(n.id)), borderColor: kindColor(outKind(n.id)) }"
             :title="'output (' + outKind(n.id) + '): ' + kindHelp(outKind(n.id)) + (live ? '' : ' — drag to wire')"
             @pointerdown="startWire($event, n)"></div>
        <div class="gc-node-head" @pointerdown="startMove($event, n)">
          <span class="gc-tool">{{ n.tool }}</span>
          <span v-if="live && stateOf(n.id)" class="gc-statepill" :class="'gc-sp-' + (stateOf(n.id).state || 'pending')">{{ stateOf(n.id).state || 'pending' }}</span>
          <span v-else class="gc-kind" :class="isTerminal(n.tool) ? 'terminal' : 'chain'"
                :style="isTerminal(n.tool) ? null : { background: colorOf(n.tool) }"
                :title="'outputs ' + producesOf(n.tool) + ' (' + (kindOf(n.tool) || 'items') + ') — ' + kindHelp(kindOf(n.tool) || 'items')">{{ kindOf(n.tool) || 'items' }}</span>
          <button v-if="!live" class="danger ghost icon gc-x" title="Remove" @pointerdown.stop @click="removeNode(n.id)">✕</button>
        </div>
        <div class="gc-io"
             title="A box with no wire in runs on the scan's Target (the host/URL/domain you give the scan in New Scan). A wired box runs on what the boxes feeding it produced.">
          in: {{ hasInput(n.id) ? 'wired input' : 'scan Target' }}<span v-if="acceptsOf(n.tool)" class="gc-needs"> · needs {{ acceptsOf(n.tool) }}</span> →
          out: {{ producesOf(n.tool) }}{{ isTerminal(n.tool) ? ' (terminal)' : '' }}
        </div>
        <div v-if="descOf(n.tool)" class="gc-desc" :title="descOf(n.tool)">{{ descOf(n.tool) }}</div>
        <!-- LIVE: real counts this box produced + how many agents are on it -->
        <div v-if="live && stateOf(n.id)" class="gc-livecounts">
          <span v-if="stateOf(n.id).running" class="gc-lc-run">▶ {{ stateOf(n.id).running }} running</span>
          <span v-if="stateOf(n.id).total" class="gc-lc-item">{{ stateOf(n.id).done }}/{{ stateOf(n.id).total }} assets</span>
          <span class="muted" style="font-size:10px">click for logs</span>
        </div>
        <!-- data-flow emulation: example values this box takes in and gives out (by type, propagated along wires) -->
        <div v-if="!live && showFlow" class="gc-flow">
          <div class="gc-flowrow" :title="'receives ' + takeInfo(n.id).kind + ' — e.g. ' + takeInfo(n.id).eg.join(', ')">
            <span class="gc-flowtag" :style="{ background: kindColor(takeInfo(n.id).kind) }">in</span>
            <span class="gc-floweg">{{ egText(takeInfo(n.id).eg) }}</span>
          </div>
          <div class="gc-flowrow" :title="'produces ' + giveInfo(n.id).kind + ' — e.g. ' + giveInfo(n.id).eg.join(', ')">
            <span class="gc-flowtag" :style="{ background: kindColor(giveInfo(n.id).kind) }">out</span>
            <span class="gc-floweg">{{ egText(giveInfo(n.id).eg) }}</span>
          </div>
        </div>
        <!-- filter box: several keep/reject conditions, ALL must pass -->
        <div v-if="!live && n.tool === 'filter'" class="gc-conds" @pointerdown.stop
             title="keep (contains) / reject (excludes) — all conditions must pass">
          <div v-for="(c, i) in condsOf(n)" :key="i" class="gc-cond">
            <button class="gc-mode" @click="toggleCondRow(n, i)">{{ c.mode === 'excludes' ? 'excludes' : 'contains' }}</button>
            <input class="gc-condv" :value="c.value" placeholder="text" @input="setCondRowVal(n, i, $event.target.value)" />
            <button class="gc-cx" title="remove condition" @click="rmCond(n, i)">✕</button>
          </div>
          <button class="gc-addc" @click="addCond(n)">+ condition</button>
        </div>
        <div v-if="!live && !isTerminal(n.tool)" class="gc-rep" @pointerdown.stop
             title="re-run this box on its own newly-discovered URLs until nothing new is found (bounded)">
          <button class="gc-mode" :class="{ on: repeatOf(n) }" @click="toggleRepeat(n)">
            ↻ repeat{{ repeatOf(n) ? ' until stable' : '' }}</button>
          <input v-if="repeatOf(n)" class="gc-repmax" type="number" min="1" max="10" :value="repeatOf(n).max"
                 title="max rounds" @input="setRepeatMax(n, $event.target.value)" />
        </div>
        <input v-if="!live && n.tool !== 'filter'" class="gc-args" :value="n.args"
               :placeholder="n.tool === 'limit' ? 'max items (e.g. 100)' : 'tool args (e.g. --timeout 60)'"
               @pointerdown.stop @input="setArgs(n, $event.target.value)" />
        <div v-if="!live && argIssues(n).length" class="gc-argwarn" @pointerdown.stop>
          ⚠ {{ n.tool }} doesn't accept {{ argIssues(n).join(', ') }} — put tool-native flags in
          <b>opt-args</b> below</div>
        <input v-if="!live && optArgsSupported(n.tool)" class="gc-args gc-optargs" :value="n.optargs"
               placeholder="opt-args → passed to the tool verbatim (e.g. -severity critical,high)"
               title="Forwarded verbatim to the underlying scanner binary — put its native flags here"
               @pointerdown.stop @input="setOptArgs(n, $event.target.value)" />
      </div>

      </div>
      <div v-if="!nodes.length" class="gc-empty">Add a tool box to start — the ➕ palette, or right-click here.</div>
    </div>

    <teleport to="body">
      <div v-if="ctx.open" class="gc-ctxbackdrop" @click="closeCtx" @contextmenu.prevent="closeCtx"></div>
      <div v-if="ctx.open" class="gc-ctxmenu" :style="ctxMenuStyle" @contextmenu.prevent>
        <!-- STEP 1: pick a group -->
        <template v-if="!activeGroup">
          <div class="gc-ctxhint">Add a box — pick a group</div>
          <button v-for="g in grouped" :key="g.group" class="gc-ctxgrow" @click="ctx.group = g.group">
            <span class="gc-dot" :style="{ background: GROUP_COLOR[g.group] || '#8f9099' }"></span>
            <span class="gc-ctxgname">{{ g.group }}</span>
            <span class="gc-ctxcount">{{ g.tools.length }}</span>
            <span class="gc-ctxchev">▸</span>
          </button>
        </template>
        <!-- STEP 2: pick a box in that group -->
        <template v-else>
          <button class="gc-ctxback" @click="ctx.group = ''">‹ groups</button>
          <div class="gc-ctxhint"><span class="gc-dot" :style="{ background: GROUP_COLOR[activeGroup.group] || '#8f9099' }"></span>{{ activeGroup.group }}</div>
          <button v-for="t in activeGroup.tools" :key="t.name" class="gc-ctxtool" @click="ctxAdd(t.name)">
            <span class="gc-ctxthead"><span class="gc-ctxtname">{{ t.name }}</span>
              <span class="gc-chipk">out: {{ t.produces || t.kind }}</span></span>
            <span class="gc-ctxtdesc">{{ t.description || 'no description' }}</span>
            <span v-if="t.accepts" class="gc-ctxtneeds">needs: {{ t.accepts }}</span>
          </button>
        </template>
      </div>
    </teleport>
  </div>
</template>

<style scoped>
.gc {
  display: flex; flex-direction: column; gap: 8px;
  /* this canvas was authored against a --panel/--text/--line/--accent palette the app doesn't define, so it
     fell back to white boxes + near-black text on a dark UI (unreadable). Alias those names to the REAL theme
     tokens here, once, so every box, input and edge below is legible in the app's dark theme. */
  --panel: var(--sc, #1e1f23);
  --panel-2: var(--sc-low, #1a1b1f);
  --text: var(--on-surface, #e4e2e6);
  --muted: var(--on-surface-variant, #c5c6cf);
  --muted-strong: var(--outline, #8f9099);
  --line: var(--outline-variant, #43474e);
  --accent: var(--primary, #8ab4f8);
}
.gc-bar { display: flex; align-items: center; gap: 12px; }
.gc-addbtn { font-size: 13px; font-weight: 600; padding: 5px 12px; border: 1px solid var(--line);
  border-radius: 8px; background: var(--primary, #8ab4f8); color: var(--on-primary, #06264d); cursor: pointer; }
.gc-palette { display: flex; flex-wrap: wrap; gap: 14px; padding: 10px; border: 1px solid var(--line);
  border-radius: 10px; background: var(--panel-2); max-height: 220px; overflow: auto; }
.gc-pcol { display: flex; flex-direction: column; gap: 5px; min-width: 230px; max-width: 260px; }
.gc-pgroup { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
.gc-chip { display: flex; flex-direction: column; gap: 2px; font-size: 12px; padding: 5px 8px;
  border: 1px solid var(--line); border-radius: 6px; background: var(--panel); color: var(--text);
  cursor: pointer; text-align: left; }
.gc-chip:hover { border-color: var(--primary, #8ab4f8); }
.gc-chiphead { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.gc-chipn { font-weight: 600; }
.gc-chipk { font-size: 10px; color: var(--muted); white-space: nowrap; }
.gc-chipd { font-size: 11px; line-height: 1.35; color: var(--muted);
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.gc-zoom { margin-left: auto; display: flex; gap: 4px; align-items: center; }
.gc-tidy { font-weight: 600; margin-right: 6px; }
.gc-zbtn { font-size: 12px; padding: 2px 9px; border: 1px solid var(--line, #ccc); border-radius: 6px;
  background: var(--panel-2, #f3f4f6); color: var(--text, #16181d); cursor: pointer; }
.gc-zbtn.on { background: var(--primary, #8ab4f8); color: var(--on-primary, #06264d); border-color: var(--primary, #8ab4f8); }
.gc-zlabel { min-width: 46px; }
.gc-world { position: absolute; inset: 0; }
.gc-canvas {
  /* near full-screen working area (leaves room for the toolbar/legend above and a little page chrome) */
  position: relative; height: calc(100vh - 210px); min-height: 480px;
  border: 1px solid var(--line, var(--border, #ddd)); border-radius: 10px;
  background: var(--panel-2, var(--panel)); overflow: hidden;
  background-image: radial-gradient(var(--line, #e3e3e3) 1px, transparent 1px); background-size: 20px 20px;
}
.gc-canvas { cursor: grab; }                 /* empty canvas is pannable — drag to move everything */
.gc-canvas.panning { cursor: grabbing; }
.gc-canvas.wiring { cursor: crosshair; }
.gc-edges { position: absolute; inset: 0; width: 100%; height: 100%; pointer-events: none; overflow: visible; }
.gc-edge { fill: none; stroke: var(--accent, #5865f2); stroke-width: 2; }
.gc-edge.gc-temp { stroke-dasharray: 5 4; opacity: .7; }
.gc-edge.gc-edge-split { stroke: var(--primary, #8ab4f8); stroke-width: 2.5; stroke-dasharray: 7 4; }
.gc-edge-hit { fill: none; stroke: transparent; stroke-width: 12; pointer-events: stroke; cursor: pointer; }
/* per-wire fan-out / filter control, placed at the wire's midpoint in world (zoomed) coords */
.gc-elabel { position: absolute; transform: translate(-50%, -50%); display: flex; align-items: center; gap: 4px; z-index: 4; }
.gc-split { font-size: 10.5px; padding: 1px 8px; border-radius: 999px; border: 1px solid var(--line);
  background: var(--panel-2); color: var(--muted); cursor: pointer; white-space: nowrap; line-height: 1.6; }
.gc-split.on { background: var(--primary, #8ab4f8); color: var(--on-primary, #06264d);
  border-color: var(--primary, #8ab4f8); font-weight: 600; }
.gc-hub { font-size: 10px; font-weight: 600; padding: 1px 8px; border-radius: 999px; white-space: nowrap;
  background: var(--primary, #8ab4f8); color: var(--on-primary, #06264d); border: 1px solid var(--primary, #8ab4f8); }
.gc-efilter { font-size: 10.5px; padding: 1px 3px; border-radius: 6px; border: 1px solid var(--line);
  background: var(--panel-2); color: var(--text); }
.gc-warn { font-size: 12px; padding: 7px 11px; border: 1px solid var(--bad, #ed4245); border-radius: 8px;
  background: var(--panel-2); color: var(--bad, #ed4245); }
.gc-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
.gc-node {
  position: absolute; border: 1px solid var(--line, #ccc); border-radius: 8px; background: var(--panel, #fff);
  color: var(--text, #16181d); box-shadow: 0 1px 3px rgba(0,0,0,.12); user-select: none; cursor: default;
}
/* ---- live/read-only monitor: colour boxes by run state (red=running, green=done, grey=waiting) ---- */
.gc-live, .gc-live .gc-node-head { cursor: pointer; }
.gc-st-running { border-color: var(--bad, #ed4245);
  box-shadow: 0 0 0 2px var(--bad, #ed4245), 0 0 14px rgba(237, 66, 69, .5); animation: gcpulse 1.1s ease-in-out infinite; }
.gc-st-done { border-color: var(--good, #3ba55d); box-shadow: 0 0 0 1px var(--good, #3ba55d); }
.gc-st-failed { border-color: var(--bad, #ed4245); box-shadow: 0 0 0 1px var(--bad, #ed4245); border-style: dashed; }
.gc-st-pending { opacity: .85; }
.gc-sel { outline: 2px solid var(--primary, #8ab4f8); outline-offset: 2px; }
@keyframes gcpulse {
  0%, 100% { box-shadow: 0 0 0 2px var(--bad, #ed4245), 0 0 6px rgba(237, 66, 69, .35); }
  50% { box-shadow: 0 0 0 2px var(--bad, #ed4245), 0 0 18px rgba(237, 66, 69, .7); }
}
.gc-statepill { font-size: 10px; font-weight: 700; padding: 0 7px; border-radius: 999px;
  text-transform: uppercase; letter-spacing: .03em; }
.gc-sp-running { background: var(--bad, #ed4245); color: #fff; }
.gc-sp-done { background: var(--good, #3ba55d); color: #fff; }
.gc-sp-pending { background: var(--outline, #8f9099); color: #fff; }
.gc-sp-failed { background: var(--bad, #ed4245); color: #fff; }
.gc-livecounts { display: flex; flex-wrap: wrap; gap: 8px; padding: 0 10px 8px; font-size: 10.5px; align-items: center; }
.gc-lc-run { color: var(--bad, #ed4245); font-weight: 600; }
.gc-lc-find { color: var(--bad, #ed4245); }
.gc-lc-item { color: var(--on-surface-variant, #c5c6cf); }
.gc-node-head { display: flex; align-items: center; gap: 6px; padding: 8px 10px; cursor: grab; }
.gc-node-head:active { cursor: grabbing; }
.gc-tool { font-weight: 700; font-size: 13px; color: var(--text, #16181d); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.gc-kind { font-size: 11px; line-height: 1.5; padding: 0 7px; border-radius: 999px; background: var(--accent, #5865f2); color: #fff; }
.gc-kind.terminal { background: var(--muted-strong, #6b7280); }
.gc-io { padding: 0 10px 6px; font-size: 11px; color: var(--muted, #5a6172); }
.gc-needs { color: var(--on-surface-variant, #8f9099); }
.gc-ctxtneeds { font-size: 10.5px; color: var(--on-surface-variant, #c5c6cf); }
.gc-x { margin-left: auto; }
/* inputs need an explicit dark background + border, or light theme text sits on the browser's default white */
.gc-args, .gc-condv, .gc-repmax {
  background: var(--panel-2); color: var(--text); border: 1px solid var(--line);
  border-radius: 6px; padding: 3px 6px; font-size: 12px;
}
.gc-args::placeholder, .gc-condv::placeholder { color: var(--muted); }
.gc-args { margin: 0 8px 8px; width: calc(100% - 16px); }
.gc-optargs { border-style: dashed; }        /* opt-args reads distinct from the recognized tool args */
.gc-argwarn { margin: -2px 8px 8px; font-size: 10.5px; line-height: 1.35; color: var(--bad, #ed4245); }
.gc-argwarn code { font-size: 10px; }
.gc-cond, .gc-rep { display: flex; gap: 4px; margin: 0 8px 6px; align-items: center; }
.gc-mode { font-size: 11px; padding: 2px 8px; border: 1px solid var(--line); border-radius: 6px;
  background: var(--panel-2); color: var(--text); cursor: pointer; white-space: nowrap; }
.gc-mode.on { background: var(--primary, #8ab4f8); color: var(--on-primary, #06264d); border-color: var(--primary, #8ab4f8); }
.gc-condv { flex: 1; min-width: 0; }
.gc-repmax { width: 52px; }
.gc-conds { display: flex; flex-direction: column; gap: 4px; margin: 0 8px 6px; }
.gc-cx { font-size: 10px; padding: 0 5px; border: 1px solid var(--line); border-radius: 6px;
  background: var(--panel-2); color: var(--muted); cursor: pointer; }
.gc-addc { align-self: flex-start; font-size: 11px; padding: 1px 8px; border: 1px dashed var(--line);
  border-radius: 6px; background: transparent; color: var(--muted); cursor: pointer; }
.gc-in, .gc-out {
  position: absolute; top: 18px; width: 14px; height: 14px; border-radius: 50%;
  background: var(--panel, #fff); border: 2px solid var(--accent, #5865f2);
}
.gc-in { left: -8px; }
.gc-out { right: -8px; cursor: crosshair; background: var(--accent, #5865f2); }
/* #10: port SHAPE encodes the data type (colour is set inline from kindColor) */
.gc-port-circle { border-radius: 50%; }
.gc-port-square { border-radius: 3px; }
.gc-port-diamond { border-radius: 2px; transform: rotate(45deg); }
.gc-port-pill { border-radius: 7px; }
/* #9: the tool's description on the box */
.gc-desc { padding: 0 10px 8px; font-size: 10.5px; line-height: 1.35; color: var(--muted);
  display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
/* data-flow emulation: example in/out values on the box */
.gc-flow { margin: 0 8px 8px; display: flex; flex-direction: column; gap: 3px;
  border-top: 1px dashed var(--line); padding-top: 6px; }
.gc-flowrow { display: flex; align-items: center; gap: 6px; min-width: 0; }
.gc-flowtag { flex: none; font-size: 8.5px; font-weight: 700; line-height: 1.6; padding: 0 5px; border-radius: 4px;
  color: #fff; text-transform: uppercase; letter-spacing: .03em; }
.gc-floweg { font-size: 10px; color: var(--muted); font-family: ui-monospace, Menlo, Consolas, monospace;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
/* #10: the port-type legend under the toolbar */
.gc-legend { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.gc-leg { display: inline-flex; align-items: center; gap: 4px; font-size: 11px; color: var(--muted); }
.gc-legdot { display: inline-block; width: 11px; height: 11px; border: 2px solid; box-sizing: border-box; }
.gc-empty { position: absolute; inset: 0; display: grid; place-items: center; color: var(--muted); font-size: 13px; }
/* right-click context menu — teleported to <body>, so it uses the REAL theme tokens (the .gc aliases don't reach it) */
.gc-ctxbackdrop { position: fixed; inset: 0; z-index: 70; }
/* two-STEP drill-in menu: step 1 = groups, click a group -> step 2 = its boxes (with a back button) */
.gc-ctxmenu { position: fixed; z-index: 71; min-width: 230px; max-width: 320px; max-height: 72vh; overflow: auto;
  padding: 6px; background: var(--sc, #1e1f23); color: var(--on-surface, #e4e2e6);
  border: 1px solid var(--outline-variant, #43474e); border-radius: 8px; box-shadow: 0 8px 30px rgba(0, 0, 0, .5); }
.gc-ctxhint { display: flex; align-items: center; font-size: 11px; color: var(--on-surface-variant, #c5c6cf); padding: 2px 8px 6px; }
.gc-ctxback { width: 100%; text-align: left; font-size: 11.5px; padding: 3px 8px; margin-bottom: 2px; border: 0;
  border-radius: 5px; background: transparent; color: var(--on-surface-variant, #c5c6cf); cursor: pointer; }
.gc-ctxback:hover { background: var(--sc-high, #282a2e); color: var(--on-surface, #e4e2e6); }
.gc-ctxgrow { display: flex; align-items: center; gap: 8px; width: 100%; text-align: left; font-size: 12.5px;
  padding: 5px 8px; border: 0; border-radius: 5px; background: transparent; color: var(--on-surface, #e4e2e6);
  cursor: pointer; }
.gc-ctxgrow:hover, .gc-ctxgrow.active { background: var(--sc-high, #282a2e); }
.gc-ctxgname { flex: 1; }
.gc-ctxcount { font-size: 10.5px; color: var(--on-surface-variant, #c5c6cf);
  background: var(--sc-low, #1a1b1f); border-radius: 999px; padding: 0 7px; }
.gc-ctxchev { color: var(--on-surface-variant, #c5c6cf); font-size: 11px; }
.gc-ctxtool { display: flex; flex-direction: column; gap: 2px; width: 100%; text-align: left;
  padding: 5px 8px; border: 0; border-radius: 5px; background: transparent; color: var(--on-surface, #e4e2e6);
  cursor: pointer; }
.gc-ctxtool:hover { background: var(--sc-high, #282a2e); }
.gc-ctxthead { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.gc-ctxtname { font-weight: 600; font-size: 12.5px; }
.gc-ctxtdesc { font-size: 11px; line-height: 1.35; color: var(--on-surface-variant, #c5c6cf);
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
</style>
