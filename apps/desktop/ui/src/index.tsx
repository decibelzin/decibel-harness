import { render } from 'solid-js/web'

import './theme.css'
import App from './App'

const root = document.getElementById('root')
if (root) render(() => <App />, root)
