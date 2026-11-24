<script setup>
import { ref, watch, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { api, getActivitySeen } from './api'

const route = useRoute()
const open = ref(false)
const unseen = ref(0)
const defaultPw = ref(false)
let timer = null

watch(() => route.path, () => { open.value = false })
async function pollActivity() {
  try {
    const r = await api.get('/activity?limit=50')
    const seen = getActivitySeen()
    unseen.value = r.items.filter(a => a.id > seen).length
  } catch (e) { /* transient */ }
}
async function checkAccount() {
  try { defaultPw.value = (await api.get('/settings/account')).default_password } catch (e) { /* ignore */ }
}
onMounted(() => { pollActivity(); checkAccount(); timer = setInterval(pollActivity, 8000) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <nav class="nav">
    <router-link to="/dashboard" class="brand">boxcutter</router-link>
    <button class="navtoggle" @click="open = !open" aria-label="Toggle menu">☰</button>
    <div class="navlinks" :class="{ open }">
      <router-link to="/dashboard">Overview</router-link>
      <router-link to="/scans" :class="{ 'router-link-active': route.path.startsWith('/scans/') && route.path !== '/scans/new' }">Scans</router-link>
      <router-link to="/schedulers">Schedulers</router-link>
      <router-link to="/pipelines">Pipelines</router-link>
      <router-link to="/findings">Findings</router-link>
      <router-link to="/scanners">Scanners</router-link>
      <router-link to="/activity">Activity<span v-if="unseen" class="navbadge">{{ unseen > 99 ? '99+' : unseen }}</span></router-link>
      <span class="spacer" />
      <router-link to="/scans/new" class="btn primary newscan">+ New scan</router-link>
      <router-link to="/settings" class="gear" title="Settings" aria-label="Settings">⚙</router-link>
    </div>
  </nav>
  <div v-if="defaultPw && route.path !== '/settings'" class="banner">
    You are still using the default password <code>admin</code>.
    <router-link to="/settings">Change it in Settings</router-link>.
  </div>
  <main class="container">
    <router-view :key="route.fullPath.startsWith('/scans/new') ? route.fullPath : route.path" />
  </main>
</template>

<style scoped>
.newscan { height: 36px; color: var(--on-primary) !important; padding: 0 16px !important; }
.newscan:hover { text-decoration: none; }
.gear { font-size: 18px; padding: 6px 10px !important; }
.brand:hover { text-decoration: none; }
.banner { background: var(--tertiary-container); color: var(--on-tertiary-container); padding: 8px 28px; font-size: 13px; }
</style>
