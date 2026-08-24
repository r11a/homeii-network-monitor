import React from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/heebo'
import App from './App'
import './styles.css'
import './accessibility.css'

if ('serviceWorker' in navigator) {
  addEventListener('load', () => navigator.serviceWorker.register('./sw.js').catch(() => {}))
}

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
