import { render } from 'solid-js/web'

// Bundled variable fonts (offline, no FOUC): Space Grotesk for UI, JetBrains Mono
// for code — a clean, consistent look on every OS instead of the platform default.
import '@fontsource-variable/space-grotesk'
import '@fontsource-variable/jetbrains-mono'
import './theme.css'
import App from './App'
import { applyTheme, theme } from './store'

// Apply the saved theme before the first paint so there is no light/dark flash.
applyTheme(theme())

const root = document.getElementById('root')
if (root) render(() => <App />, root)
