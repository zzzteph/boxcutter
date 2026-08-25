import { createRouter, createWebHashHistory } from 'vue-router'
import { token } from './api'

const routes = [
  { path: '/login', component: () => import('./views/Login.vue') },
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', component: () => import('./views/Dashboard.vue') },
  { path: '/findings', component: () => import('./views/Findings.vue') },
  { path: '/scans', component: () => import('./views/Scans.vue') },
  { path: '/scans/new', component: () => import('./views/NewScan.vue') },
  { path: '/scans/:id', component: () => import('./views/ScanDetail.vue') },
  { path: '/templates', component: () => import('./views/Templates.vue') },
  { path: '/llm-profiles', component: () => import('./views/LLMProfiles.vue') },
  { path: '/activity', component: () => import('./views/Activity.vue') },
  { path: '/scanners', component: () => import('./views/Fleet.vue') },
  { path: '/scanners/:id', component: () => import('./views/RunnerDetail.vue') },
  { path: '/fleet', redirect: '/scanners' },
  { path: '/settings', component: () => import('./views/Settings.vue') },
]

const router = createRouter({ history: createWebHashHistory(), routes })
router.beforeEach((to) => {
  if (to.path !== '/login' && !token()) return '/login'
})
export default router
