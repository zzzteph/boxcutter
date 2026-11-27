// Convert between the server's stage list and the graph the WorkflowGraph component draws, and the wiring rules
// the builder checks while you drag a wire (the server checks the same rules in pipeline.check_plan).
//   stage: {template_id, from: [-1 | stageIndex...], input, args, label}
//   graph: {nodes: [{key, templateId, title, kind, category, produces, accepts, takes, gives, input, args, x, y}],
//           edges: [{from: '@targets' | key, to: key}]}
export const TARGETS = '@targets'

// what each "takes" filter hands to a step
const URL_INPUTS = new Set(['urls', 'param-urls', 'js-urls', 'writes', 'sql-leads'])
export const KIND_WORD = { host: 'hostnames', url: 'URLs' }

function takesOf(accepts, kind) {
  if (accepts === 'domain' || accepts === 'network') return ['host']
  if (!accepts || accepts === 'host' || accepts === 'any') return ['host', 'url']
  if (accepts === 'spec') return kind === 'tool' ? ['url'] : ['host', 'url']
  return ['url']
}
function givesOf(produces) { return { hosts: 'host', urls: 'url', items: 'url' }[produces] || '' }

function nodeFromTemplate(key, t, extra = {}) {
  return { key, templateId: t ? t.id : null, title: t ? t.title : '(deleted template)', kind: t ? t.kind : 'tool',
    category: t ? (t.builtin ? t.category : 'Custom') : 'Custom', produces: t ? t.produces : 'findings',
    accepts: t ? t.accepts : 'any', steps: t ? t.steps : 0, description: t ? t.description : '',
    engine: t ? t.engine : '', takes: t ? (t.takes || takesOf(t.accepts, t.kind)) : ['host', 'url'],
    gives: t ? (t.gives ?? givesOf(t.produces)) : '', unverified: !!(t && t.unverified),
    verifier: !!(t && t.verifier), leads: !!(t && t.leads), ...extra }
}

// a saved workflow (raw stages that point at templates) -> graph
export function graphFromStages(stages, templates, layout = []) {
  const byId = Object.fromEntries(templates.map(t => [t.id, t]))
  const nodes = (stages || []).map((s, i) => nodeFromTemplate('n' + i, byId[s.template_id], {
    input: s.input || 'all', args: s.args || '', label: s.label || '',
    x: layout && layout[i] ? layout[i].x : undefined, y: layout && layout[i] ? layout[i].y : undefined }))
  const edges = []
  ;(stages || []).forEach((s, i) => {
    for (const f of (s.from || [])) edges.push({ from: f < 0 ? TARGETS : 'n' + f, to: 'n' + i })
  })
  return { nodes, edges }
}

// an expanded plan (what actually runs: scan.stages or a template's `plan`) -> graph
export function graphFromPlan(plan) {
  const nodes = (plan || []).map((s, i) => ({
    key: 'n' + (s.index ?? i), templateId: s.template_id, title: s.title || s.template, kind: s.kind,
    category: s.category || 'Tools', produces: s.produces, accepts: s.accepts, input: s.input || 'all',
    args: s.args || '', description: s.description || '', gives: s.gives ?? givesOf(s.produces),
    takes: takesOf(s.accepts, s.kind), engine: s.engine || s.template }))
  const edges = []
  ;(plan || []).forEach((s, i) => {
    for (const f of (s.from || [])) edges.push({ from: f < 0 ? TARGETS : 'n' + f, to: 'n' + (s.index ?? i) })
  })
  return { nodes, edges }
}

// graph -> {stages, layout} in dependency order, or {error}
export function stagesFromGraph(graph) {
  const nodes = graph.nodes || [], edges = graph.edges || []
  if (!nodes.length) return { error: 'add at least one step' }
  for (const n of nodes) {
    if (!n.templateId) return { error: `pick what “${n.title || 'a step'}” runs` }
    if (!edges.some(e => e.to === n.key)) return { error: `“${n.label || n.title}” isn't connected — wire something into it` }
  }
  // Kahn's algorithm, ties broken left-to-right then top-to-bottom so indexes follow the picture
  const indeg = Object.fromEntries(nodes.map(n => [n.key, edges.filter(e => e.to === n.key && e.from !== TARGETS).length]))
  const order = []
  const pick = () => nodes.filter(n => indeg[n.key] === 0 && !order.includes(n.key))
    .sort((a, b) => (a.x ?? 0) - (b.x ?? 0) || (a.y ?? 0) - (b.y ?? 0))[0]
  for (let n = pick(); n; n = pick()) {
    order.push(n.key)
    for (const e of edges) if (e.from === n.key) indeg[e.to]--
  }
  if (order.length !== nodes.length) return { error: 'the wires make a loop — data must flow one way' }
  const idx = Object.fromEntries(order.map((k, i) => [k, i]))
  const byKey = Object.fromEntries(nodes.map(n => [n.key, n]))
  const stages = order.map(k => {
    const n = byKey[k]
    return { template_id: n.templateId, input: n.input || 'all', args: n.args || '', label: n.label || '',
      from: edges.filter(e => e.to === k).map(e => (e.from === TARGETS ? -1 : idx[e.from])).sort((a, b) => a - b) }
  })
  const layout = order.map(k => ({ x: byKey[k].x ?? 0, y: byKey[k].y ?? 0 }))
  return { stages, layout }
}

export const DEFAULT_INPUT = { domain: 'hosts', host: 'all', network: 'hosts', url: 'urls', spec: 'urls', graphql: 'urls',
  endpoint: 'param-urls', js: 'js-urls', any: 'all' }

export function newNode(t, key) {
  return nodeFromTemplate(key, t, { input: DEFAULT_INPUT[t.accepts] || 'all', args: '' })
}

// ---- wiring rules ------------------------------------------------------------------------------------------
// What every node passes on ('host' | 'url' | ''), whether its hostnames still need dnsx, and whether a merge
// carries SQL-injection leads. Merges take on the kind of what flows into them.
export function flowInfo(graph) {
  const nodes = graph.nodes || [], edges = graph.edges || []
  const byKey = Object.fromEntries(nodes.map(n => [n.key, n]))
  const memo = {}
  const visit = (k, depth = 0) => {
    if (k === TARGETS) return { gives: 'any', unverified: false, leads: false }
    if (memo[k]) return memo[k]
    const n = byKey[k]
    if (!n || depth > nodes.length) return { gives: '', unverified: false, leads: false }
    let r
    if (n.kind === 'merge') {
      const ins = edges.filter(e => e.to === k).map(e => visit(e.from, depth + 1))
      let kinds = new Set(ins.map(i => i.gives).filter(g => g && g !== 'any'))
      if (n.input === 'hosts') kinds = new Set(['host'])
      else if (URL_INPUTS.has(n.input)) kinds = new Set(['url'])
      r = { gives: kinds.size === 1 ? [...kinds][0] : (kinds.size ? 'mixed' : 'url'),
        unverified: ins.some(i => i.unverified), leads: n.input === 'sql-leads' }
    } else {
      r = { gives: n.gives ?? givesOf(n.produces), unverified: !!n.unverified, leads: !!n.leads }
    }
    memo[k] = r
    return r
  }
  for (const n of nodes) visit(n.key)
  return memo
}

function nm(n) { return n ? (n.label || n.title) : 'Scan targets' }

// Can `from` feed `to` when `to` takes `input`? Returns '' when it can, else the reason (user-facing).
export function wireError(graph, from, to, input) {
  const byKey = Object.fromEntries((graph.nodes || []).map(n => [n.key, n]))
  const dst = byKey[to]
  if (!dst || from === TARGETS) return ''
  const src = byKey[from]
  const info = flowInfo(graph)[from] || { gives: '' }
  const want = dst.kind === 'merge' ? ['host', 'url'] : (dst.takes || takesOf(dst.accepts, dst.kind))
  if (input === 'sql-leads') {
    return (src && (src.leads || (src.kind === 'merge' && info.leads))) ? ''
      : `“${nm(dst)}” takes SQL-injection leads — those come from a fuzz step, not from “${nm(src)}”`
  }
  if (!info.gives) return `“${nm(src)}” only produces findings — nothing to pass on`
  if (info.gives === 'mixed') return `“${nm(src)}” mixes hostnames and URLs — merge one kind of result`
  if (info.unverified && !dst.verifier && dst.kind !== 'merge') {
    return `“${nm(src)}” ${src && src.kind === 'merge' ? 'carries' : 'finds'} hostnames that may not exist — wire it into dnsx first so they are verified`
  }
  if (info.gives === 'host') {
    if (URL_INPUTS.has(input) || !want.includes('host')) {
      return `“${nm(src)}” gives hostnames and “${nm(dst)}” needs URLs — put httpx in between to find the web services`
    }
  } else if (input === 'hosts') {
    if (!want.includes('host')) return `“${nm(dst)}” needs URLs — it can't take hostnames`
  } else if (!want.includes('url')) {
    return `“${nm(dst)}” takes hostnames — set what it takes to “Hostnames”`
  }
  return ''
}

// Every problem with the wires into `to` if it took `input` (used to offer only workable "takes" choices).
export function nodeErrors(graph, to, input) {
  return (graph.edges || []).filter(e => e.to === to).map(e => wireError(graph, e.from, to, input)).filter(Boolean)
}

// The best "takes" for a new wire from `from` into `to`: its current one if that works for all its wires,
// else the first one that does. Returns {input} or {error}.
export function pickInput(graph, from, to, inputs) {
  const dst = (graph.nodes || []).find(n => n.key === to)
  const g = { nodes: graph.nodes, edges: [...graph.edges, { from, to }] }
  const ok = (inp) => !nodeErrors(g, to, inp).length
  if (ok(dst.input || 'all')) return { input: dst.input || 'all' }
  const alt = inputs.find(ok)
  if (alt) return { input: alt }
  return { error: wireError(g, from, to, dst.input || 'all') || 'these two steps can’t be wired' }
}

// A workflow template's steps as new nodes (fresh keys), entry steps wired from `attach`, laid out as columns to
// the right of `origin`. Lets the builder add a whole workflow as visible boxes instead of one nested box.
export function inlineWorkflow(stages, layout, templates, attach, origin, keyFn) {
  const byId = Object.fromEntries(templates.map(t => [t.id, t]))
  const keys = stages.map(() => keyFn())
  const depth = []
  stages.forEach((s, i) => {
    const ps = (s.from || []).filter(f => f >= 0)
    depth[i] = ps.length ? Math.max(...ps.map(p => depth[p])) + 1 : 0
  })
  const rows = {}
  const nodes = stages.map((s, i) => {
    const r = rows[depth[i]] = (rows[depth[i]] ?? -1) + 1
    return nodeFromTemplate(keys[i], byId[s.template_id], { input: s.input || 'all', args: s.args || '', label: s.label || '',
      x: origin.x + depth[i] * 300, y: origin.y + r * 90 })
  })
  const edges = []
  stages.forEach((s, i) => {
    for (const f of (s.from || [])) edges.push({ from: f < 0 ? attach : keys[f], to: keys[i] })
  })
  return { nodes, edges }
}
