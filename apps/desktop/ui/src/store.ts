import { createSignal } from 'solid-js'
import { createStore, produce } from 'solid-js/store'

import { fetchModels, runPrompt, type ModelInfo } from './api'

// ── model catalog ───────────────────────────────────────────────────────────
export const [models, setModels] = createSignal<ModelInfo[]>([])
export const [modelsError, setModelsError] = createSignal<string | undefined>()
export const [loadingModels, setLoadingModels] = createSignal(false)
export const [selectedModel, setSelectedModel] = createSignal<string>('')
export const [search, setSearch] = createSignal('')

export async function loadModels(): Promise<void> {
  setLoadingModels(true)
  setModelsError(undefined)
  try {
    const list = await fetchModels()
    list.sort((a, b) => b.context_length - a.context_length)
    setModels(list)
    if (!selectedModel()) {
      // Default to the cheapest tool-capable DeepSeek model, else the first.
      const best = list.find((m) => m.id === 'deepseek-v4-flash') ?? list.find((m) => m.supports_tools) ?? list[0]
      if (best) setSelectedModel(best.id)
    }
  } catch (e) {
    setModelsError(e instanceof Error ? e.message : String(e))
  } finally {
    setLoadingModels(false)
  }
}

/** The catalog after the search filter, context desc. */
export function visibleModels(): ModelInfo[] {
  const q = search().trim().toLowerCase()
  if (!q) return models()
  return models().filter(
    (m) => m.id.toLowerCase().includes(q) || m.name.toLowerCase().includes(q),
  )
}

export function modelById(id: string): ModelInfo | undefined {
  return models().find((m) => m.id === id)
}

// ── preferences (persisted to localStorage) ──────────────────────────────────
export type Theme = 'system' | 'dark' | 'light'

function readPref<T extends string>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key)
    return (v as T) ?? fallback
  } catch {
    return fallback
  }
}
function writePref(key: string, value: string): void {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* private mode / storage disabled — preference just won't persist */
  }
}

const [theme, setThemeSignal] = createSignal<Theme>(readPref<Theme>('decibel.theme', 'dark'))
export { theme }

/** Apply a theme to the document root and persist it. `system` defers to the
 * OS via `prefers-color-scheme` (no explicit attribute). */
export function applyTheme(t: Theme): void {
  setThemeSignal(t)
  writePref('decibel.theme', t)
  const root = document.documentElement
  if (t === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', t)
}

// ── conversation ─────────────────────────────────────────────────────────────
export interface TextBlock {
  kind: 'text'
  text: string
}
export interface ToolBlock {
  kind: 'tool'
  name: string
  args: string
  state: 'running' | 'ok' | 'error'
  /** The tool's rendered model-facing output text, once it settles. */
  output?: string
  /** The tool's canonical JSON value, for a structured card (nmap, http, …). */
  value?: unknown
}
/** A run-level system note shown inline (e.g. an automatic model fallback). */
export interface NoticeBlock {
  kind: 'notice'
  text: string
}
export type Block = TextBlock | ToolBlock | NoticeBlock
export interface Msg {
  role: 'user' | 'assistant'
  blocks: Block[]
}

export const [conversation, setConversation] = createStore<{ list: Msg[] }>({ list: [] })
export const [running, setRunning] = createSignal(false)
export const [settingsOpen, setSettingsOpen] = createSignal(false)
let controller: AbortController | undefined
// Each run gets a monotonic id; only the active run's events are applied, so a
// cancelled or superseded run can never write into the transcript or clobber
// running-state (its backend is also cancelled via the AbortSignal → cancel_run).
let nextRunId = 1
let activeRunId = 0

export function newSession(): void {
  cancel()
  setConversation('list', [])
}

export async function send(text: string): Promise<void> {
  const prompt = text.trim()
  if (!prompt || running()) return
  const model = selectedModel()
  if (!model) return

  setConversation('list', (l) => [...l, { role: 'user', blocks: [{ kind: 'text', text: prompt }] }])
  setConversation('list', (l) => [...l, { role: 'assistant', blocks: [] }])
  const idx = conversation.list.length - 1

  const runId = nextRunId++
  activeRunId = runId
  setRunning(true)
  controller = new AbortController()
  try {
    await runPrompt(prompt, model, runId, (e) => applyEvent(idx, runId, e), controller.signal)
  } finally {
    // Backstop: if runPrompt rejects (e.g. an IPC failure) rather than ending
    // with a done/error event, don't leave the spinner stuck — but only touch
    // state if this run is still the active one (never clobber a newer run).
    if (runId === activeRunId) setRunning(false)
  }
}

export function cancel(): void {
  // Drop the active run first so any late events from it are ignored, then abort
  // (which reaches the backend via the api's cancel_run bridge).
  activeRunId = 0
  controller?.abort()
  controller = undefined
  setRunning(false)
}

function applyEvent(idx: number, runId: number, e: import('./api').RunEvent): void {
  // Ignore events from a run that was cancelled or superseded by a newer one.
  if (runId !== activeRunId) return
  setConversation(
    'list',
    idx,
    'blocks',
    produce((blocks: Block[]) => {
      switch (e.type) {
        case 'token': {
          const last = blocks[blocks.length - 1]
          if (last && last.kind === 'text') last.text += e.text
          else blocks.push({ kind: 'text', text: e.text })
          break
        }
        case 'tool_call':
          blocks.push({ kind: 'tool', name: e.name, args: e.args, state: 'running' })
          break
        case 'tool_result': {
          for (let i = blocks.length - 1; i >= 0; i--) {
            const b = blocks[i]
            if (b.kind === 'tool' && b.name === e.name && b.state === 'running') {
              b.state = e.ok ? 'ok' : 'error'
              b.output = e.output
              b.value = e.value
              break
            }
          }
          break
        }
        case 'error':
          blocks.push({ kind: 'text', text: `\n\n⚠ ${e.message}` })
          break
        case 'step':
        case 'done':
          break
      }
    }),
  )
  if (e.type === 'done' || e.type === 'error') setRunning(false)
}
