<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { api, setToken, setUser } from '../api'

const router = useRouter()
const username = ref('root')
const password = ref('')
const err = ref('')
const busy = ref(false)
const mustChange = ref(false)
const cur = ref('')
const nw = ref('')
const nw2 = ref('')
const code = ref('')
const needCode = ref(false)

const canLogin = computed(() => username.value.trim() && password.value && (!needCode.value || code.value) && !busy.value)
const canChange = computed(() => nw.value.length >= 8 && nw.value === nw2.value && !busy.value)

function friendly(e) {
  const m = (e?.message || '').toLowerCase()
  if (m.includes('credential') || m.includes('401') || m.includes('unauthor')) return 'Incorrect username or password.'
  if (m.includes('failed to fetch') || m.includes('network')) return 'Can’t reach the server — is it running?'
  return e?.message || 'Something went wrong. Please try again.'
}

async function submit() {
  if (!canLogin.value) return
  err.value = ''; busy.value = true
  try {
    const res = await api.login(username.value.trim(), password.value, needCode.value ? code.value.trim() : undefined)
    setToken(res.token); setUser(res.user)
    if (res.user.must_change_password) { mustChange.value = true; cur.value = password.value; err.value = '' }
    else router.push('/dashboard')
  } catch (e) {
    const m = ((e && e.message) || '').toLowerCase()
    if (m.includes('2fa_required')) { needCode.value = true; err.value = '' }        // password ok — ask for the code
    else if (m.includes('2fa')) err.value = 'Invalid authentication code — try again.'
    else err.value = friendly(e)
  } finally { busy.value = false }
}
async function change() {
  if (!canChange.value) return
  err.value = ''; busy.value = true
  try {
    await api.changePassword(cur.value, nw.value)
    setUser(await api.me())          // refresh cached user (clears must_change_password)
    router.push('/dashboard')
  } catch (e) { err.value = e?.message || 'Could not update the password.' } finally { busy.value = false }
}
</script>

<template>
  <div class="login">
    <div class="card">
      <div class="brand" style="font-size:22px">boxcutter</div>

      <template v-if="!mustChange">
        <p class="muted" style="margin:2px 0 16px">Sign in to continue.</p>
        <label>Username</label>
        <input v-model="username" autocomplete="username" autofocus @keyup.enter="submit" />
        <label>Password</label>
        <input v-model="password" type="password" autocomplete="current-password" @keyup.enter="submit" />
        <template v-if="needCode">
          <label>Authentication code</label>
          <input v-model="code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" @keyup.enter="submit" />
          <p class="muted" style="font-size:12px;margin-top:4px">Enter the 6-digit code from your authenticator app.</p>
        </template>
        <p v-if="err" class="err" role="alert">{{ err }}</p>
        <button class="primary" style="margin-top:16px;width:100%" :disabled="!canLogin" @click="submit">
          {{ busy ? 'Signing in…' : 'Log in' }}
        </button>
      </template>

      <template v-else>
        <p class="muted" style="margin:2px 0 16px">Welcome. Set a password to finish setting up your account.</p>
        <label>New password</label>
        <input v-model="nw" type="password" autocomplete="new-password" autofocus @keyup.enter="change" />
        <label>Confirm new password</label>
        <input v-model="nw2" type="password" autocomplete="new-password" @keyup.enter="change" />
        <p class="muted" style="font-size:12px;margin-top:6px">At least 8 characters.</p>
        <p v-if="nw && nw2 && nw !== nw2" class="err">Passwords don’t match.</p>
        <p v-if="err" class="err" role="alert">{{ err }}</p>
        <button class="primary" style="margin-top:12px;width:100%" :disabled="!canChange" @click="change">
          {{ busy ? 'Saving…' : 'Save password' }}
        </button>
      </template>
    </div>
  </div>
</template>

<style scoped>
.login { min-height: calc(100vh - 48px); display: grid; place-items: center; padding: 24px; }
.login .card { width: 100%; max-width: 360px; }
</style>
