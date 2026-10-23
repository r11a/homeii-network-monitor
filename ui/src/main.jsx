import React from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/heebo'
import App from './App'
import ZabbixWorkspace from './ZabbixWorkspace'
import './styles.css'
import './accessibility.css'
import './operations.css'
import './aura.css'

if ('serviceWorker' in navigator) {
  addEventListener('load', () => navigator.serviceWorker.register('./sw.js').catch(() => {}))
}

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    {new URLSearchParams(location.search).has('legacy') ? <App /> : <ZabbixWorkspace />}
  </React.StrictMode>,
)
