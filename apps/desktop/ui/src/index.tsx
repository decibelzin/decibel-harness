import { render } from 'solid-js/web'

// Bundled fonts (offline, no FOUC): the unified "Space" family — Space Grotesk for
// UI, Space Mono for code/terminal/numbers — a consistent look on every OS instead
// of the platform default. Space Mono ships 400/700; 600-weight labels map to 700.
import '@fontsource-variable/space-grotesk'
import '@fontsource/space-mono/400.css'
import '@fontsource/space-mono/700.css'
import './theme.css'
import App from './App'
import { applyTheme, theme } from './store'

// Apply the saved theme before the first paint so there is no light/dark flash.
applyTheme(theme())

const root = document.getElementById('root')
if (root) render(() => <App />, root)
