import React from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/assistant'
import '@fontsource-variable/space-grotesk'
import App from './App'
import './styles.css'

if ('serviceWorker' in navigator) {
  addEventListener('load', () => navigator.serviceWorker.register('./sw.js').catch(() => {}))
}

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
