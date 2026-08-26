import { createSignal } from 'solid-js'
import { createStore, produce } from 'solid-js/store'

import { fetchModels, runPrompt, type ModelInfo } from './api'

// ── model catalog ───────────────────────────────────────────────────────────
export const [models, setModels] = createSignal<ModelInfo[]>([])
export const [modelsError, setModelsError] = createSignal<string | undefined>()
export const [loadingModels, setLoadingModels] = createSignal(false)
export const [selectedModel, setSelectedModel] = createSignal<string>('')
export const [freeOnly, setFreeOnly] = createSignal(true)
export const [toolsOnly, setToolsOnly] = createSignal(true)
export const [search, setSearch] = createSignal('')

export async function loadModels(): Promise<void> {
  setLoadingModels(true)
  setModelsError(undefined)
  try {
    const list = await fetchModels()
    list.sort((a, b) => b.context_length - a.context_length)
    setModels(list)
    if (!selectedModel()) {
      const best = list.find((m) => m.is_free && m.supports_tools) ?? list[0]
      if (best) setSelectedModel(best.id)
    }
  } catch (e) {
    setModelsError(e instanceof Error ? e.message : String(e))
  } finally {
    setLoadingModels(false)
  }
}

/** The catalog after the active free/tools/search filters, context desc. */
export function visibleModels(): ModelInfo[] {
  const q = search().trim().toLowerCase()
  return models().filter((m) => {
    if (freeOnly() && !m.is_free) return false
    if (toolsOnly() && !m.supports_tools) return false
    if (q && !m.id.toLowerCase().includes(q) && !m.name.toLowerCase().includes(q)) return false
    return true
  })
}

export function modelById(id: string): ModelInfo | undefined {
  return models().find((m) => m.id === id)
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
}
export type Block = TextBlock | ToolBlock
export interface Msg {
  role: 'user' | 'assistant'
  blocks: Block[]
}

export const [conversation, setConversation] = createStore<{ list: Msg[] }>({ list: [] })
export const [running, setRunning] = createSignal(false)
let controller: AbortController | undefined

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

  setRunning(true)
  controller = new AbortController()
  await runPrompt(prompt, model, (e) => applyEvent(idx, e), controller.signal)
}

export function cancel(): void {
  controller?.abort()
  controller = undefined
  setRunning(false)
}

function applyEvent(idx: number, e: import('./api').RunEvent): void {
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
