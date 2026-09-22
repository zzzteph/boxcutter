<script setup>
// An in-browser terminal that authorizes Claude Code INSIDE the server container: it bridges xterm.js to a PTY
// running `claude` (server/app/routers/console.py), so an admin can run `/login` at the Docker level without
// `docker exec`. The login persists on /data, so every claude-code run then rides it (no API key).
import { ref, onBeforeUnmount, nextTick } from 'vue'
import { Terminal } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import 'xterm/css/xterm.css'
import { apiBase, token } from '../api'

const emit = defineEmits(['closed'])
const open = ref(false)
const termEl = ref(null)
let term = null, fit = null, ws = null, ro = null

function wsUrl() {
  // same origin in prod (apiBase() is ''), or the dev API host; ws://ws-secure derived from the scheme.
  const base = apiBase()
  const origin = base ? base.replace(/^http/, 'ws')
    : (location.protocol === 'https:' ? 'wss' : 'ws') + '://' + location.host
  return origin.replace(/\/$/, '') + '/console/claude/ws?token=' + encodeURIComponent(token())
}

function sendResize() {
  if (ws && ws.readyState === 1 && term) ws.send('\x00resize:' + term.cols + ',' + term.rows)
}

async function start() {
  open.value = true
  await nextTick()
  term = new Terminal({ cursorBlink: true, fontSize: 13, scrollback: 4000,
    theme: { background: '#0b0e14', foreground: '#d7dde8' } })
  fit = new FitAddon()
  term.loadAddon(fit)
  term.open(termEl.value)
  try { fit.fit() } catch { /* pre-layout */ }
  ws = new WebSocket(wsUrl())
  ws.onopen = () => { term.focus(); sendResize() }
  ws.onmessage = (e) => term.write(e.data)
  ws.onerror = () => term.write('\r\n[connection error]\r\n')
  ws.onclose = () => term.write('\r\n[disconnected]\r\n')
  term.onData((d) => { if (ws && ws.readyState === 1) ws.send(d) })
  ro = new ResizeObserver(() => { try { fit.fit(); sendResize() } catch { /* mid-teardown */ } })
  ro.observe(termEl.value)
}

function stop() {
  try { ws && ws.close() } catch { /* already closed */ }
  try { ro && ro.disconnect() } catch { /* n/a */ }
  try { term && term.dispose() } catch { /* n/a */ }
  ws = term = fit = ro = null
  if (open.value) { open.value = false; emit('closed') }
}
onBeforeUnmount(stop)
</script>

<template>
  <button class="tonal sm" @click="start">⌨ Authorize in a console</button>
  <teleport to="body">
    <div v-if="open" class="ovl" @click.self="stop">
      <div class="tmodal">
        <div class="thead">
          <b>Claude Code login</b>
          <span class="muted thint">Type <code>/login</code> and follow the prompts (open the URL it prints, paste
            the code back). The login persists on <code>/data</code>; every claude-code run then uses it.</span>
          <button class="ghost sm" @click="stop">Close ✕</button>
        </div>
        <div ref="termEl" class="tbody"></div>
      </div>
    </div>
  </teleport>
</template>

<style scoped>
.ovl { position: fixed; inset: 0; background: rgba(0, 0, 0, .55); display: grid; place-items: center; z-index: 60; }
.tmodal { width: min(940px, 94vw); background: #0b0e14; border-radius: 10px; overflow: hidden;
  border: 1px solid var(--line); box-shadow: 0 20px 60px rgba(0, 0, 0, .5); }
.thead { display: flex; align-items: center; gap: 10px; padding: 8px 12px; background: var(--panel);
  border-bottom: 1px solid var(--line); }
.thead .ghost { margin-left: auto; }
.thint { font-size: 12px; }
.tbody { height: 62vh; padding: 8px; }
</style>
