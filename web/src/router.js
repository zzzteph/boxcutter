import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', component: () => import('./views/Dashboard.vue') },
  { path: '/scans', component: () => import('./views/Scans.vue') },
  { path: '/scans/new', component: () => import('./views/NewScan.vue') },
  { path: '/scans/:id', component: () => import('./views/ScanDetail.vue') },
  { path: '/schedulers', component: () => import('./views/Schedulers.vue') },
  { path: '/workflows', component: () => import('./views/Workflows.vue') },
  { path: '/workflows/new', component: () => import('./views/WorkflowBuilder.vue') },
  { path: '/workflows/:id', component: () => import('./views/WorkflowBuilder.vue') },
  { path: '/findings', component: () => import('./views/Findings.vue') },
  { path: '/scanners', component: () => import('./views/Fleet.vue') },
  { path: '/scanners/:id', component: () => import('./views/RunnerDetail.vue') },
  { path: '/activity', component: () => import('./views/Activity.vue') },
  { path: '/settings', component: () => import('./views/Settings.vue') },
  // old paths
  { path: '/monitoring', redirect: '/schedulers' },
  { path: '/templates', redirect: '/workflows' },
  { path: '/pipelines', redirect: '/workflows' },
  { path: '/fleet', redirect: '/scanners' },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
]

export default createRouter({ history: createWebHashHistory(), routes })
