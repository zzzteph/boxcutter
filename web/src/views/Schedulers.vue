<script setup>
// Schedulers: recurring scans on a cron schedule. Create one from New scan ("On a schedule"); here you see them
// all, pause or resume, run one now, and edit its name / schedule / targets / what it runs.
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'
import ScanTypePicker from '../components/ScanTypePicker.vue'
import CronInput from '../components/CronInput.vue'
import WindowInput from '../components/WindowInput.vue'
import { timeAgo, timeUntil, detectTargets, targetLines } from '../util'

const router = useRouter()
const rows = ref([])
const templates = ref([])
const loading = ref(true)
const editing = ref(null)
const cronOk = ref(true)
const err = ref('')
let timer = null

async function load() {
  try { rows.value = await api.get('/schedulers') } catch (e) { /* transient */ } finally { loading.value = false }
}
async function toggle(r) {
  try { await api.patch('/schedulers/' + r.id, { enabled: !r.enabled }); await load() } catch (e) { alert(e.message) }
}
async function runNow(r) {
  try { const x = await api.post(`/schedulers/${r.id}/run`); router.push('/scans/' + x.scan_id) } catch (e) { alert(e.message) }
}
async function remove(r) {
  if (!confirm(`Delete scheduler "${r.name}"? Its scan and past results stay under Scans.`)) return
  try { await api.del('/schedulers/' + r.id); await load() } catch (e) { alert(e.message) }
}
const isTwin = (t) => !!t && String(t.variant_of || '').endsWith('-distributed')
function edit(r) {
  const t = templates.value.find(x => x.id === r.template_id)
  const b = isTwin(t) ? templates.value.find(x => x.name === t.variant_of) : null
  editing.value = { id: r.id, name: r.name, targets: r.targets.join('\n'), enabled: r.enabled, cron: r.cron,
    timezone: r.timezone, templateId: b ? b.id : r.template_id, external: !!b, window: r.window }
  err.value = ''
}
const editTwin = computed(() => {
  const b = editing.value && templates.value.find(t => t.id === editing.value.templateId)
  return b ? templates.value.find(t => t.variant_of === b.name) || null : null
})
const editKind = computed(() => editing.value ? detectTargets(targetLines(editing.value.targets)).kind : '')
async function save() {
  const e = editing.value
  err.value = ''
  try {
    await api.patch('/schedulers/' + e.id, { name: e.name, enabled: e.enabled, targets: targetLines(e.targets),
      template_id: e.external && editTwin.value ? editTwin.value.id : e.templateId, cron: e.cron, timezone: e.timezone,
      window: e.window, set_window: true })
    editing.value = null
    await load()
  } catch (x) { err.value = x.message }
}

onMounted(async () => {
  templates.value = await api.get('/templates').catch(() => [])
  await load()
  timer = setInterval(load, 10000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center">
    <div>
      <h1 style="margin:0">Schedulers</h1>
      <div class="muted">Scans that run on a cron schedule. Each run is compared with the last one: new, still open, fixed.</div>
    </div>
    <router-link to="/scans/new?repeat=1" class="btn primary">+ New scheduler</router-link>
  </div>

  <div class="card tablecard" style="margin-top:16px">
    <table class="reflow rows">
      <thead><tr><th>Name</th><th>Runs</th><th>Targets</th><th>Schedule</th><th>Next run</th><th>Last run</th><th></th></tr></thead>
      <tbody>
        <tr v-for="r in rows" :key="r.id" :class="{ off: !r.enabled }">
          <td data-label="Name"><b>{{ r.name }}</b></td>
          <td data-label="Runs">{{ r.template }}<div v-if="r.template_kind === 'pipeline'" class="muted small">workflow</div></td>
          <td data-label="Targets"><span :title="r.targets.slice(0, 20).join('\n')">{{ r.targets_count }}</span></td>
          <td data-label="Schedule">{{ r.schedule }}<div class="muted small"><code>{{ r.cron }}</code> · {{ r.timezone }}</div>
            <div v-if="r.window" class="small win" :title="r.window_open ? 'inside its scan window now' : 'outside its scan window now'">
              🕘 only {{ r.window_text }}</div></td>
          <td data-label="Next run">
            <span v-if="!r.enabled" class="muted">paused</span>
            <span v-else-if="['running', 'paused'].includes(r.scan_status)" class="st-running">running now</span>
            <span v-else :title="r.next_run_at">{{ timeUntil(r.next_run_at) }}</span>
          </td>
          <td data-label="Last run">
            <router-link v-if="r.scan_id" :to="'/scans/' + r.scan_id">#{{ r.run_no }}
              <span class="state" :class="'st-' + r.scan_status">{{ r.scan_status }}</span></router-link>
            <span v-else class="muted">never</span>
            <div v-if="r.last_run_at" class="muted small">{{ timeAgo(r.last_run_at) }}</div>
          </td>
          <td>
            <div class="row" style="gap:4px;flex-wrap:nowrap;justify-content:flex-end">
              <button class="sm ghost" :disabled="['running', 'paused'].includes(r.scan_status)" @click="runNow(r)">Run now</button>
              <button class="sm ghost" @click="toggle(r)">{{ r.enabled ? 'Pause' : 'Resume' }}</button>
              <button class="sm ghost" @click="edit(r)">Edit</button>
              <button class="sm ghost danger" @click="remove(r)">✕</button>
            </div>
          </td>
        </tr>
        <tr v-if="!loading && !rows.length">
          <td colspan="7" class="empty">
            <b>No schedulers yet.</b>
            <div class="muted">Set one up to scan your perimeter every night or every week and get alerted about anything new.</div>
            <router-link to="/scans/new?repeat=1" class="btn primary" style="margin-top:10px">Create a scheduler</router-link>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <div v-if="editing" class="modal" @click.self="editing = null">
    <div class="modal-inner card">
      <div class="row" style="justify-content:space-between"><h2 style="margin:0">Edit scheduler</h2>
        <button class="ghost sm" @click="editing = null">✕</button></div>
      <label>Name</label><input v-model="editing.name" />
      <label>Schedule</label>
      <CronInput v-model:cron="editing.cron" v-model:timezone="editing.timezone" @valid="v => cronOk = v" />
      <label>Targets (one per line)</label>
      <textarea v-model="editing.targets" rows="4"></textarea>
      <div class="muted small">A change of targets takes effect on the next run.</div>
      <label>Scan window — when its jobs may run</label>
      <WindowInput v-model="editing.window" />
      <div class="muted small">Applies right away, also to a run in progress.</div>
      <label>What it runs</label>
      <ScanTypePicker :templates="templates" :kind="editKind" v-model="editing.templateId" />
      <label v-if="editTwin" class="chk" style="margin-top:8px"><input type="checkbox" v-model="editing.external" />
        🌐 only what is reachable from the internet (liveless check)</label>
      <label class="chk"><input type="checkbox" v-model="editing.enabled" /> enabled</label>
      <div v-if="err" class="err">{{ err }}</div>
      <div class="row" style="justify-content:flex-end;margin-top:12px">
        <button class="ghost" @click="editing = null">Cancel</button>
        <button class="primary" :disabled="!cronOk" @click="save">Save</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
tr.off td { opacity: .6; }
td.empty { text-align: center; padding: 34px 12px !important; }
.small { font-size: 12px; }
.win { color: var(--accent-ink); margin-top: 2px; }
.modal { position: fixed; inset: 0; background: var(--scrim); display: flex; align-items: flex-start; justify-content: center;
  z-index: 50; padding: 40px 16px; overflow: auto; }
.modal-inner { width: min(980px, 100%); }
.chk { display: inline-flex; gap: 8px; align-items: center; cursor: pointer; }
.chk input { width: auto; }
</style>
