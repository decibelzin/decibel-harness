// Data layer. In the real Tauri app these call Rust commands; in dev / browser
// preview the catalog is a fixed DeepSeek list and the agent run is mocked, so
// the whole UI is demonstrable without the backend or an API key.

import { Channel, invoke } from '@tauri-apps/api/core'

export interface ModelInfo {
  id: string
  name: string
  /** Backend that serves this model: 'deepseek' (paid API) or 'openrouter' (free). */
  provider: string
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
  // `output` is the tool's rendered model-facing text; `value` is its canonical
  // JSON (present on success) — the source for structured cards (nmap, http, …).
  | { type: 'tool_result'; name: string; ok: boolean; output: string; value: unknown }
  // Nested specialist events (orchestrate mode): a live sub-agent timeline under
  // the `delegate` card. `delegation` correlates the events to one specialist lane.
  | { type: 'specialist_start'; delegation: number; specialist: string; task: string }
  | { type: 'specialist_step'; delegation: number; specialist: string; n: number }
  | { type: 'specialist_token'; delegation: number; specialist: string; text: string }
  | { type: 'specialist_tool_call'; delegation: number; specialist: string; name: string; args: string }
  | { type: 'specialist_tool_result'; delegation: number; specialist: string; name: string; ok: boolean; output: string; value: unknown }
  | { type: 'specialist_end'; delegation: number; specialist: string; ok: boolean; stop: string; steps: number; findings_added: number; summary: string }
  | { type: 'done' }
  | { type: 'error'; message: string }

export function isTauri(): boolean {
  const w = window as unknown as { __TAURI_INTERNALS__?: unknown; __TAURI__?: unknown }
  return typeof w.__TAURI_INTERNALS__ !== 'undefined' || typeof w.__TAURI__ !== 'undefined'
}

/** The catalog for the browser preview (the desktop app gets the live list from
 * the Rust `list_models`): the paid DeepSeek API models plus a representative set
 * of the free, tool-capable OpenRouter models. The real app fetches OpenRouter's
 * free list live, so its ids/flags are authoritative — OpenRouter has no free
 * DeepSeek models, so the free tier here is other providers. */
const PREVIEW_MODELS: ModelInfo[] = [
  { id: 'deepseek-v4-flash', name: 'DeepSeek V4 Flash', provider: 'deepseek', context_length: 1_000_000, is_free: false, supports_tools: true, input_modalities: ['text'] },
  { id: 'deepseek-v4-pro', name: 'DeepSeek V4 Pro', provider: 'deepseek', context_length: 1_000_000, is_free: false, supports_tools: true, input_modalities: ['text'] },
  { id: 'deepseek-v4-flash-vision-exp', name: 'DeepSeek V4 Flash Vision (exp)', provider: 'deepseek', context_length: 1_000_000, is_free: false, supports_tools: true, input_modalities: ['text', 'image'] },
  { id: 'minimax/minimax-m3:free', name: 'MiniMax M3 (free)', provider: 'openrouter', context_length: 1_048_576, is_free: true, supports_tools: true, input_modalities: ['text'] },
  { id: 'z-ai/glm-5.2:free', name: 'GLM 5.2 (free)', provider: 'openrouter', context_length: 256_000, is_free: true, supports_tools: true, input_modalities: ['text'] },
  { id: 'google/gemma-4-31b-it:free', name: 'Gemma 4 31B (free)', provider: 'openrouter', context_length: 262_144, is_free: true, supports_tools: true, input_modalities: ['text'] },
]

/** The model catalog. From the Rust backend in the app; the fixed list above in
 * the browser preview. */
export async function fetchModels(): Promise<ModelInfo[]> {
  if (isTauri()) return await invoke<ModelInfo[]>('list_models')
  return PREVIEW_MODELS
}

// ── API keys (per provider; keyring in Tauri, no-op in browser preview) ───────
export async function hasApiKey(provider: string): Promise<boolean> {
  if (isTauri()) return await invoke<boolean>('has_api_key', { provider })
  return false
}
export async function saveApiKey(provider: string, key: string): Promise<void> {
  if (isTauri()) await invoke('save_api_key', { provider, key })
}
export async function deleteApiKey(provider: string): Promise<void> {
  if (isTauri()) await invoke('delete_api_key', { provider })
}

/** Run one prompt, streaming events. Real in Tauri, mocked in browser preview.
 * `runId` tags this run so a Stop/New-session can cancel exactly it on the
 * backend and stale events can be filtered out on the frontend. */
export async function runPrompt(
  prompt: string,
  model: string,
  provider: string,
  workspace: string,
  mode: string,
  access: string,
  scope: string,
  image: string,
  sessionId: string,
  runId: number,
  onEvent: (e: RunEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  if (isTauri()) {
    const channel = new Channel<RunEvent>()
    channel.onmessage = onEvent
    // Bridge the AbortSignal to a real backend cancel — invoke() itself is not
    // abortable, so abort must reach the Rust turn through a command.
    signal?.addEventListener('abort', () => void invoke('cancel_run', { runId }).catch(() => {}), {
      once: true,
    })
    // `image` = a data: URL for a vision model ('' = none). `scope` = the RoE
    // authorized-target text ('' = no restriction).
    await invoke('run_prompt', {
      prompt,
      model,
      provider,
      workspace: workspace || null,
      mode,
      access,
      scope: scope || null,
      image: image || null,
      sessionId,
      runId,
      onEvent: channel,
    })
    return
  }
  await mockRun(prompt, model, mode, onEvent, signal)
}

// ── MCP servers (Tauri; no-op in browser preview) ────────────────────────────
export interface McpServerConfigDto {
  name: string
  command: string
  args: string[]
  env?: [string, string][]
}
export interface McpProbeResult {
  name: string
  ok: boolean
  tools: string[]
  error?: string
}
/** (Re)configure + connect the MCP servers; returns each server's discovered
 * tools or its connection error. No-op-ish in the browser preview (no backend). */
export async function setMcpServers(servers: McpServerConfigDto[]): Promise<McpProbeResult[]> {
  if (isTauri()) return await invoke<McpProbeResult[]>('set_mcp_servers', { servers })
  return servers.map((s) => ({ name: s.name, ok: false, tools: [], error: 'MCP needs the desktop app' }))
}
/** The MCP servers currently configured in the backend. Empty in browser preview. */
export async function listMcpServers(): Promise<McpServerConfigDto[]> {
  if (isTauri()) return await invoke<McpServerConfigDto[]>('list_mcp_servers')
  return []
}

/** Whether `path` is an existing directory (validates a chosen workspace). */
export async function pathIsDir(path: string): Promise<boolean> {
  if (isTauri()) return await invoke<boolean>('path_is_dir', { path })
  return path.trim().length > 0 // preview: accept any non-empty path
}

/** Open the native OS folder picker (desktop app only). Returns the chosen
 * directory, or null if cancelled / not in the app. */
export async function pickFolder(): Promise<string | null> {
  if (!isTauri()) return null
  try {
    const { open } = await import('@tauri-apps/plugin-dialog')
    const dir = await open({ directory: true, title: 'Choose workspace folder' })
    return typeof dir === 'string' ? dir : null
  } catch {
    return null
  }
}

// ── session / slash-command commands (Tauri; no-ops or estimates in preview) ──
export interface ContextInfo {
  messages: number
  estimated_tokens: number
  last_input_tokens: number | null
  last_output_tokens: number | null
}

/** Drop a conversation's backend session (multi-turn memory) — for /clear. */
export async function clearSession(sessionId: string): Promise<void> {
  if (isTauri()) await invoke('clear_session', { sessionId })
}

/** The conversation's context usage — for /context. Null in browser preview. */
export async function sessionContext(sessionId: string): Promise<ContextInfo | null> {
  if (isTauri()) return await invoke<ContextInfo>('session_context', { sessionId })
  return null
}

/** Summarize + replace the conversation's history — for /compact. Returns the
 * summary (empty if nothing to compact). Browser preview has no backend session. */
export async function compactSession(sessionId: string, model: string, provider: string): Promise<string> {
  if (isTauri()) return await invoke<string>('compact_session', { sessionId, model, provider })
  return ''
}

// ── saved sessions (sidebar; disk-backed in Tauri, empty in preview) ──────────
export interface SessionMeta {
  id: string
  title: string
  updated_ms: number
}
/** One block of a reconstructed transcript (from `load_session`). */
export interface DisplayBlock {
  kind: string
  text?: string
  name?: string
  args?: string
  state?: string
  output?: string
}
export interface DisplayMsg {
  role: string
  blocks: DisplayBlock[]
}

export async function listSessions(): Promise<SessionMeta[]> {
  if (isTauri()) return await invoke<SessionMeta[]>('list_sessions')
  return []
}
export async function loadSession(id: string): Promise<DisplayMsg[]> {
  if (isTauri()) return await invoke<DisplayMsg[]>('load_session', { id })
  return []
}
export async function deleteSession(id: string): Promise<void> {
  if (isTauri()) await invoke('delete_session', { id })
}
export async function renameSession(id: string, title: string): Promise<void> {
  if (isTauri()) await invoke('rename_session', { id, title })
}

/** A believable mock so the conversation UI is demonstrable without a key. It
 * exercises every rich tool card (nmap, shell, http, finding) and markdown. */
async function mockRun(
  prompt: string,
  _model: string,
  mode: string,
  onEvent: (e: RunEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
  const emitText = async (text: string) => {
    for (const word of text.split(/(\s+)/)) {
      if (signal?.aborted) return
      onEvent({ type: 'token', text: word })
      await sleep(14)
    }
  }

  // Orchestrate mode: demonstrate the nested specialist timeline — the
  // orchestrator delegates to a specialist whose live steps/tools/narration
  // stream INSIDE the `delegate` card.
  if (mode === 'orchestrate') {
    await mockOrchestrate(emitText, sleep, onEvent, signal)
    return
  }

  onEvent({ type: 'step', n: 1 })
  await emitText("Starting recon on the target. I'll enumerate open ports with a structured nmap scan first.")
  if (signal?.aborted) return
  onEvent({ type: 'tool_call', name: 'nmap', args: '{"target":"127.0.0.1","service_version":true}' })
  await sleep(700)
  onEvent({
    type: 'tool_result',
    name: 'nmap',
    ok: true,
    output: 'nmap 127.0.0.1 — 1 host(s)\n\n127.0.0.1 (localhost) [up]\n  22/tcp open ssh OpenSSH 8.9p1\n  80/tcp open http nginx 1.24.0',
    value: {
      target: '127.0.0.1',
      timed_out: false,
      hosts: [
        {
          address: '127.0.0.1',
          hostname: 'localhost',
          status: 'up',
          ports: [
            { port: 22, protocol: 'tcp', state: 'open', service: 'ssh', product: 'OpenSSH', version: '8.9p1' },
            { port: 80, protocol: 'tcp', state: 'open', service: 'http', product: 'nginx', version: '1.24.0' },
            { port: 443, protocol: 'tcp', state: 'filtered', service: 'https', product: '', version: '' },
          ],
        },
      ],
    },
  })

  onEvent({ type: 'step', n: 2 })
  await emitText('\n\nSSH (22) and HTTP (80) are open. Probing the web root for the server banner and headers.')
  if (signal?.aborted) return
  onEvent({ type: 'tool_call', name: 'http', args: '{"url":"http://127.0.0.1/","method":"GET"}' })
  await sleep(500)
  onEvent({
    type: 'tool_result',
    name: 'http',
    ok: true,
    output: 'GET http://127.0.0.1/ → 200\nserver: nginx/1.24.0\ncontent-type: text/html\n\n<!doctype html><title>Welcome</title>',
    value: {
      status: 200,
      headers: { server: 'nginx/1.24.0', 'content-type': 'text/html', 'x-powered-by': 'Express' },
      body: '<!doctype html>\n<html><head><title>Welcome</title></head>\n<body><h1>It works</h1></body></html>',
      body_truncated: false,
    },
  })

  onEvent({ type: 'step', n: 3 })
  await emitText('\n\nThe `x-powered-by: Express` header leaks the framework. Running a quick version check via shell.')
  if (signal?.aborted) return
  onEvent({ type: 'tool_call', name: 'shell', args: '{"command":"curl -sI http://127.0.0.1/ | grep -i x-powered-by"}' })
  await sleep(450)
  onEvent({
    type: 'tool_result',
    name: 'shell',
    ok: true,
    output: 'x-powered-by: Express\n[exit code: 0]',
    value: { exit_code: 0, stdout: 'x-powered-by: Express\n', stderr: '', timed_out: false },
  })

  if (signal?.aborted) return
  onEvent({ type: 'tool_call', name: 'add_finding', args: '{"title":"Framework disclosure via X-Powered-By"}' })
  await sleep(300)
  onEvent({
    type: 'tool_result',
    name: 'add_finding',
    ok: true,
    output: 'recorded finding #1: [low] Framework disclosure via X-Powered-By [T1592]',
    value: {
      recorded: true,
      index: 1,
      finding: {
        title: 'Framework disclosure via X-Powered-By',
        severity: 'low',
        description: 'The server advertises `X-Powered-By: Express`, disclosing the web framework and easing targeted attacks.',
        target: 'http://127.0.0.1/',
        mitre: 'T1592',
      },
    },
  })

  onEvent({ type: 'step', n: 4 })
  await emitText(
    "\n\n## Summary\n\n`127.0.0.1` exposes:\n\n- **SSH** (22) — OpenSSH `8.9p1`\n- **HTTP** (80) — nginx fronting an **Express** app\n\nOne low-severity finding recorded (framework disclosure). Next I'd fingerprint the Express routes and test for common misconfigurations.\n\n> This is a mocked run — the Tauri build drives the real agent.",
  )
  onEvent({ type: 'done' })
}

/** Mock the orchestrate flow: the orchestrator narrates, then delegates to a
 * `recon` specialist whose steps/tools/narration stream nested under the
 * `delegate` card, then closes the phase. Exercises the nested-timeline UI. */
async function mockOrchestrate(
  emitText: (t: string) => Promise<void>,
  sleep: (ms: number) => Promise<unknown>,
  onEvent: (e: RunEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const d = 0 // one delegation lane
  onEvent({ type: 'step', n: 1 })
  await emitText('Planning the engagement. I’ll delegate reconnaissance to the `recon` specialist first.')
  if (signal?.aborted) return

  // The orchestrator's `delegate` tool call opens the card the specialist nests in.
  onEvent({ type: 'tool_call', name: 'delegate', args: '{"specialist":"recon","task":"Enumerate open ports and services on 127.0.0.1"}' })
  onEvent({ type: 'specialist_start', delegation: d, specialist: 'recon', task: 'Enumerate open ports and services on 127.0.0.1' })
  await sleep(300)

  onEvent({ type: 'specialist_step', delegation: d, specialist: 'recon', n: 1 })
  for (const word of 'Running a structured port scan against the target.'.split(/(\s+)/)) {
    if (signal?.aborted) return
    onEvent({ type: 'specialist_token', delegation: d, specialist: 'recon', text: word })
    await sleep(14)
  }
  onEvent({ type: 'specialist_tool_call', delegation: d, specialist: 'recon', name: 'port_scan', args: '{"target":"127.0.0.1"}' })
  await sleep(600)
  onEvent({
    type: 'specialist_tool_result',
    delegation: d,
    specialist: 'recon',
    name: 'port_scan',
    ok: true,
    output: 'port_scan 127.0.0.1 — 2 open\n  22/tcp ssh\n  80/tcp http',
    value: { target: '127.0.0.1', open: [{ port: 22, service: 'ssh' }, { port: 80, service: 'http' }] },
  })

  onEvent({ type: 'specialist_tool_call', delegation: d, specialist: 'recon', name: 'record_finding', args: '{"title":"SSH exposed to the network"}' })
  await sleep(300)
  onEvent({
    type: 'specialist_tool_result',
    delegation: d,
    specialist: 'recon',
    name: 'record_finding',
    ok: true,
    output: 'recorded finding: [info] SSH exposed to the network',
    value: { recorded: true, finding: { title: 'SSH exposed to the network', severity: 'info', target: '127.0.0.1:22', mitre: 'T1046' } },
  })

  onEvent({ type: 'specialist_end', delegation: d, specialist: 'recon', ok: true, stop: 'completed', steps: 2, findings_added: 1, summary: 'Found SSH (22) and HTTP (80) open; recorded one info finding.' })
  // The `delegate` tool settles with the specialist's returned summary.
  onEvent({
    type: 'tool_result',
    name: 'delegate',
    ok: true,
    output: '[recon] completed, 2 step(s), 1 finding(s) recorded.\nFound SSH (22) and HTTP (80) open; recorded one info finding.',
    value: { specialist: 'recon', steps: 2, findings_added: 1, stop: 'completed', summary: 'Found SSH (22) and HTTP (80) open.' },
  })

  onEvent({ type: 'step', n: 2 })
  await emitText('\n\nRecon complete. Next I’d delegate exploitation of the exposed HTTP service. \n\n> Mocked orchestrate run — the Tauri build drives the real 17-specialist roster.')
  onEvent({ type: 'done' })
}
