// Convert between the server's stage list and the graph the WorkflowGraph component draws.
//   stage: {template_id, from: [-1 | stageIndex...], input, args}
//   graph: {nodes: [{key, templateId, title, kind, category, produces, accepts, input, args, steps, x, y}],
//           edges: [{from: '@targets' | key, to: key}]}
export const TARGETS = '@targets'

function nodeFromTemplate(key, t, extra = {}) {
  return { key, templateId: t ? t.id : null, title: t ? t.title : '(deleted template)', kind: t ? t.kind : 'tool',
    category: t ? (t.builtin ? t.category : 'Custom') : 'Custom', produces: t ? t.produces : 'findings',
    accepts: t ? t.accepts : 'any', steps: t ? t.steps : 0, description: t ? t.description : '', ...extra }
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
    args: s.args || '', description: s.description || '' }))
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
    if (!edges.some(e => e.to === n.key)) return { error: `“${n.title}” isn't connected — wire something into it` }
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
