import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import './style.css'

// Material ripple: on press, spawn a ripple span inside the button (CSS animates + removes it).
document.addEventListener('pointerdown', (e) => {
  const btn = e.target.closest('button, .btn')
  if (!btn || btn.disabled) return
  const r = btn.getBoundingClientRect()
  const size = Math.max(r.width, r.height)
  const el = document.createElement('span')
  el.className = 'ripple'
  el.style.width = el.style.height = size + 'px'
  el.style.left = (e.clientX - r.left - size / 2) + 'px'
  el.style.top = (e.clientY - r.top - size / 2) + 'px'
  btn.appendChild(el)
  el.addEventListener('animationend', () => el.remove())
})

createApp(App).use(router).mount('#app')
