import { render } from 'solid-js/web'

import './theme.css'
import App from './App'
import { applyTheme, theme } from './store'

// Apply the saved theme before the first paint so there is no light/dark flash.
applyTheme(theme())

const root = document.getElementById('root')
if (root) render(() => <App />, root)
