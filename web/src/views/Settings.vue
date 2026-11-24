<script setup>
import { ref, reactive, onMounted } from 'vue'
import { api } from '../api'
import { timeAgo } from '../util'

const account = ref(null)
const pw = reactive({ current: '', next: '', again: '', msg: '', err: '' })
const n = ref(null)
const form = reactive({ tgEnabled: false, tgToken: '', tgChat: '', slEnabled: false, slHook: '', sevs: [], scanDone: true })
const nMsg = reactive({ saved: '', telegram: '', slack: '' })

async function loadAccount() { account.value = await api.get('/settings/account') }
async function changePw() {
  pw.msg = ''; pw.err = ''
  if (pw.next !== pw.again) { pw.err = "The new passwords don't match"; return }
  try {
    await api.post('/settings/password', { current_password: pw.current, new_password: pw.next })
    pw.msg = 'Password changed. Your browser will ask you to sign in again with the new one.'
    pw.current = pw.next = pw.again = ''
    setTimeout(() => location.reload(), 1500)
  } catch (e) { pw.err = e.message }
}

function fill(r) {
  n.value = r
  form.tgEnabled = r.telegram.enabled; form.tgChat = r.telegram.chat_id; form.tgToken = ''
  form.slEnabled = r.slack.enabled; form.slHook = ''
  form.sevs = [...r.severities]; form.scanDone = r.scan_done
}
async function loadNotify() { fill(await api.get('/settings/notifications')) }
async function saveNotify() {
  nMsg.saved = ''
  try {
    fill(await api.post('/settings/notifications', {
      telegram_enabled: form.tgEnabled, telegram_chat_id: form.tgChat, telegram_token: form.tgToken || null,
      slack_enabled: form.slEnabled, slack_webhook: form.slHook || null, severities: form.sevs, scan_done: form.scanDone }))
    nMsg.saved = '✓ saved'
  } catch (e) { nMsg.saved = e.message }
}
async function test(ch) {
  nMsg[ch] = 'sending…'
  await saveNotify()
  try { const r = await api.post('/settings/notifications/test/' + ch); nMsg[ch] = r.ok ? '✓ sent — check the channel' : r.error }
  catch (e) { nMsg[ch] = e.message }
}
function toggleSev(s) { form.sevs = form.sevs.includes(s) ? form.sevs.filter(x => x !== s) : [...form.sevs, s] }

onMounted(() => { loadAccount(); loadNotify() })
</script>

<template>
  <h1>Settings</h1>

  <div class="card" style="margin-top:12px">
    <h2 style="margin-top:0">Sign-in</h2>
    <div class="muted">boxcutter uses one account with HTTP basic auth. Username <code>{{ account?.username || 'admin' }}</code>.
      <span v-if="account && account.password_changed_at"> Password last changed {{ timeAgo(account.password_changed_at) }}.</span></div>
    <div v-if="account && account.default_password" class="warnbox">You are using the default password <code>admin</code> — change it now.</div>
    <div class="formgrid" style="max-width:780px">
      <div><label>Current password</label><input v-model="pw.current" type="password" autocomplete="current-password" /></div>
      <div><label>New password</label><input v-model="pw.next" type="password" autocomplete="new-password" placeholder="at least 8 characters" /></div>
      <div><label>Repeat new password</label><input v-model="pw.again" type="password" autocomplete="new-password" @keyup.enter="changePw" /></div>
    </div>
    <div class="row" style="margin-top:10px">
      <button class="primary" :disabled="!pw.current || !pw.next" @click="changePw">Change password</button>
      <span v-if="pw.msg" class="okc">{{ pw.msg }}</span><span v-if="pw.err" class="err">{{ pw.err }}</span>
    </div>
  </div>

  <div v-if="n" class="card" style="margin-top:16px">
    <h2 style="margin-top:0">Notifications</h2>
    <div class="muted">Get a message for new findings of the severities you pick, and when a scan finishes.</div>

    <label>Notify about new findings that are</label>
    <div class="row" style="gap:6px">
      <button v-for="s in n.all_severities" :key="s" type="button" class="sevchip" :class="{ on: form.sevs.includes(s) }"
              @click="toggleSev(s)"><span class="badge" :class="'sev-' + s">{{ s }}</span></button>
    </div>
    <label class="chk"><input type="checkbox" v-model="form.scanDone" /> also send a summary when a scan finishes</label>

    <div class="channels">
      <div class="chan">
        <label class="chk head"><input type="checkbox" v-model="form.tgEnabled" /> <b>Telegram</b></label>
        <label>Bot token <span class="muted">{{ n.telegram.has_token ? '(saved — leave empty to keep)' : '' }}</span></label>
        <input v-model="form.tgToken" type="password" placeholder="123456:ABC-DEF…  (from @BotFather)" />
        <label>Chat ID</label>
        <input v-model="form.tgChat" placeholder="e.g. -1001234567890" />
        <div class="row" style="margin-top:10px">
          <button class="sm" @click="test('telegram')">Send test</button><span class="muted">{{ nMsg.telegram }}</span>
        </div>
      </div>
      <div class="chan">
        <label class="chk head"><input type="checkbox" v-model="form.slEnabled" /> <b>Slack</b></label>
        <label>Incoming webhook URL <span class="muted">{{ n.slack.has_webhook ? '(saved — leave empty to keep)' : '' }}</span></label>
        <input v-model="form.slHook" type="password" placeholder="https://hooks.slack.com/services/…" />
        <div class="muted" style="font-size:12px;margin-top:6px">Slack → Apps → Incoming Webhooks → Add to a channel.</div>
        <div class="row" style="margin-top:10px">
          <button class="sm" @click="test('slack')">Send test</button><span class="muted">{{ nMsg.slack }}</span>
        </div>
      </div>
    </div>
    <div class="row" style="margin-top:14px">
      <button class="primary" @click="saveNotify">Save notifications</button><span class="muted">{{ nMsg.saved }}</span>
    </div>
  </div>
</template>

<style scoped>
.warnbox { margin-top: 10px; padding: 8px 12px; border-radius: var(--radius-s); background: var(--tertiary-container);
  color: var(--on-tertiary-container); }
.okc { color: var(--ok); }
.chk { display: inline-flex; gap: 8px; align-items: center; cursor: pointer; margin-top: 12px; }
.chk input { width: auto; }
.chk.head { margin-top: 0; font-size: 14px; color: var(--on-surface); }
.channels { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); margin-top: 16px; }
.chan { background: var(--sc); border-radius: var(--radius-s); padding: 14px 16px; }
.sevchip { height: 34px; padding: 0 6px; border-color: var(--outline-variant); opacity: .45; }
.sevchip.on { opacity: 1; border-color: var(--accent); }
.sevchip:hover { background: transparent; box-shadow: none; opacity: .8; }
</style>
