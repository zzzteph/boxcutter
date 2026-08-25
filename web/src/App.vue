<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, token, setToken, setUser, getUser, isAdmin, getActivitySeen } from './api'
const docsUrl = '/docs'   // same origin/port as the app (Vite proxies it in dev; the API serves it in prod)
const route = useRoute()
const router = useRouter()
const open = ref(false)
const acctOpen = ref(false)
const acctEl = ref(null)
const unseen = ref(0)
let timer = null

const initial = computed(() => (getUser()?.username || '?').charAt(0))
function logout() { setToken(''); setUser(''); open.value = false; acctOpen.value = false; router.push('/login') }
function go() { open.value = false; acctOpen.value = false }
function onDoc(e) { if (acctEl.value && !acctEl.value.contains(e.target)) acctOpen.value = false }
watch(() => route.path, () => { acctOpen.value = false })
async function pollActivity() {
  if (!token()) { unseen.value = 0; return }
  try {
    const r = await api.get('/activity?limit=50')
    const seen = getActivitySeen()
    unseen.value = r.items.filter(a => a.id > seen).length
  } catch (e) { /* transient */ }
}
onMounted(() => { pollActivity(); timer = setInterval(pollActivity, 5000); document.addEventListener('click', onDoc) })
onUnmounted(() => { clearInterval(timer); document.removeEventListener('click', onDoc) })
</script>

<template>
  <nav v-if="route.path !== '/login'" class="nav">
    <span class="brand">boxcutter</span>
    <button class="navtoggle" @click="open = !open" aria-label="Toggle menu">☰</button>
    <div class="navlinks" :class="{ open }">
      <router-link to="/dashboard" @click="go">Overview</router-link>
      <router-link to="/scans" @click="go">Scans</router-link>
      <router-link to="/findings" @click="go">Findings</router-link>
      <router-link to="/templates" @click="go">Templates</router-link>
      <router-link to="/scanners" @click="go">Scanners</router-link>
      <router-link to="/activity" @click="go">Activity<span v-if="unseen" class="navbadge">{{ unseen > 99 ? '99+' : unseen }}</span></router-link>
      <router-link v-if="isAdmin()" to="/llm-profiles" @click="go">LLM Profiles</router-link>
      <a :href="docsUrl" target="_blank" rel="noopener" @click="go">API ↗</a>
      <span class="spacer" />
      <div v-if="token()" class="acct" ref="acctEl">
        <button class="avatar" @click.stop="acctOpen = !acctOpen" :title="getUser()?.username" aria-label="Account">{{ initial }}</button>
        <div v-if="acctOpen" class="menu-panel right">
          <div class="menu-head">
            <span class="avatar">{{ initial }}</span>
            <div><div class="who">{{ getUser()?.username }}</div><div class="role">{{ getUser()?.role }}</div></div>
          </div>
          <router-link to="/settings" class="menu-item" @click="go">Settings</router-link>
          <button class="menu-item danger" @click="logout">Log out</button>
        </div>
      </div>
    </div>
  </nav>
  <main class="container">
    <router-view />
  </main>
</template>
