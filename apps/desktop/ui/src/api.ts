// Data layer. In the real Tauri app these call Rust commands; in dev / browser
// preview they hit the proxied public OpenRouter catalog and mock the agent run,
// so the whole UI is demonstrable without the backend or an API key.

import { Channel, invoke } from '@tauri-apps/api/core'

export interface ModelInfo {
  id: string
  name: string
  context_length: number
  is_free: boolean
  supports_tools: boolean
  input_modalities: string[]
}

/** A streamed event from a running turn. Matches the Rust `RunEvt`. */
export type RunEvent =
  | { type: 'step'; n: number }
  | { type: 'token'; text: string }
  | { type: 'tool_call'; name: string; args: string }
  | { type: 'tool_result'; name: string; ok: boolean }
  | { type: 'done' }
  | { type: 'error'; message: string }

export function isTauri(): boolean {
  return typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined'
}

function parseModel(entry: any): ModelInfo {
  const prompt = String(entry?.pricing?.prompt ?? '0')
  const completion = String(entry?.pricing?.completion ?? '0')
  const isFree = Number(prompt) === 0 && Number(completion) === 0
  const params: string[] = entry?.supported_parameters ?? []
  return {
    id: entry.id,
    name: entry.name ?? entry.id,
    context_length: entry.context_length ?? entry?.top_provider?.context_length ?? 0,
    is_free: isFree,
    supports_tools: params.includes('tools') || params.includes('tool_choice'),
    input_modalities: entry?.architecture?.input_modalities ?? ['text'],
  }
}

/** Fetch the live model catalog. */
export async function fetchModels(): Promise<ModelInfo[]> {
  if (isTauri()) return await invoke<ModelInfo[]>('list_models')
  const res = await fetch('/or/api/v1/models')
  if (!res.ok) throw new Error(`catalog HTTP ${res.status}`)
  const json = await res.json()
  return (json.data ?? []).map(parseModel)
}

// ── API key (keyring in Tauri; no-op in browser preview) ─────────────────────
export async function hasApiKey(): Promise<boolean> {
  if (isTauri()) return await invoke<boolean>('has_api_key')
  return false
}
export async function saveApiKey(key: string): Promise<void> {
  if (isTauri()) await invoke('save_api_key', { key })
}
export async function deleteApiKey(): Promise<void> {
  if (isTauri()) await invoke('delete_api_key')
}

/** Run one prompt, streaming events. Real in Tauri, mocked in browser preview. */
export async function runPrompt(
  prompt: string,
  model: string,
  onEvent: (e: RunEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  if (isTauri()) {
    const channel = new Channel<RunEvent>()
    channel.onmessage = onEvent
    await invoke('run_prompt', { prompt, model, onEvent: channel })
    return
  }
  await mockRun(prompt, model, onEvent, signal)
}

/** A believable mock so the conversation UI is demonstrable without a key. */
async function mockRun(
  prompt: string,
  _model: string,
  onEvent: (e: RunEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
  const emitText = async (text: string) => {
    for (const word of text.split(/(\s+)/)) {
      if (signal?.aborted) return
      onEvent({ type: 'token', text: word })
      await sleep(18)
    }
  }

  onEvent({ type: 'step', n: 1 })
  await emitText("Starting recon on the target. I'll enumerate open ports first.")
  if (signal?.aborted) return
  onEvent({ type: 'tool_call', name: 'nmap', args: '{"target":"127.0.0.1","service_version":true}' })
  await sleep(700)
  onEvent({ type: 'tool_result', name: 'nmap', ok: true })

  onEvent({ type: 'step', n: 2 })
  await emitText('\n\nFound SSH (22) and HTTP (80) open. Probing the web service.')
  if (signal?.aborted) return
  onEvent({ type: 'tool_call', name: 'http', args: '{"url":"http://127.0.0.1/","method":"GET"}' })
  await sleep(500)
  onEvent({ type: 'tool_result', name: 'http', ok: true })

  onEvent({ type: 'step', n: 3 })
  await emitText(
    '\n\n**Summary:** 127.0.0.1 exposes SSH (OpenSSH) and HTTP (nginx). ' +
      'Next I would fingerprint the web app and test for common misconfigurations. ' +
      '(This is a mocked run — the Tauri build drives the real agent.)',
  )
  onEvent({ type: 'done' })
}
