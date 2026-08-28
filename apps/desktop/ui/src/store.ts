import { createSignal } from 'solid-js'
import { createStore, produce } from 'solid-js/store'

import {
  clearSession,
  compactSession,
  deleteSession,
  fetchModels,
  listSessions,
  loadSession,
  renameSession,
  runPrompt,
  sessionContext,
  sessionFindings,
  setMcpServers as apiSetMcpServers,
  type DisplayMsg,
  type ModelInfo,
  type SessionMeta,
} from './api'

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

// The workspace: the directory the shell/fs/search tools operate in. '' = the
// app's own directory. Persisted so it survives restarts.
const [workspace, setWorkspaceSignal] = createSignal<string>(readPref<string>('decibel.workspace', ''))
export { workspace }
export function setWorkspace(dir: string): void {
  setWorkspaceSignal(dir)
  writePref('decibel.workspace', dir)
}
/** The workspace's last path segment, for a compact chip label. */
export function workspaceName(): string {
  const w = workspace().replace(/[\\/]+$/, '')
  return w ? (w.split(/[\\/]/).pop() || w) : ''
}

// Run mode: 'act' executes tools; 'plan' proposes a plan and runs nothing;
// 'orchestrate' runs the multi-agent engagement (delegates to specialists).
export type Mode = 'act' | 'plan' | 'orchestrate'
const [mode, setModeSignal] = createSignal<Mode>(readPref<Mode>('decibel.mode', 'act'))
export { mode }
export function setMode(m: Mode): void {
  setModeSignal(m)
  writePref('decibel.mode', m)
}

// Engagement scope (Rules of Engagement): authorized targets, one per line (or
// comma-separated) — IPs, CIDRs, or domains. Empty = no RoE restriction. Threaded
// to the backend where it installs a ScopePolicy pre-gate. Persisted like the
// workspace so it survives restarts.
const [engagementScope, setScopeSignal] = createSignal<string>(readPref<string>('decibel.scope', ''))
export { engagementScope }
export function setEngagementScope(s: string): void {
  setScopeSignal(s)
  writePref('decibel.scope', s)
}

// Max steps per turn (the agent's runaway backstop). Default 40; the operator can
// raise it for long engagements or lower it to keep runs short. Clamped 1–200.
const [maxSteps, setMaxStepsSignal] = createSignal<number>(
  Math.min(200, Math.max(1, parseInt(readPref('decibel.maxSteps', '40'), 10) || 40)),
)
export { maxSteps }
export function setMaxSteps(n: number): void {
  const v = Math.min(200, Math.max(1, Math.round(n) || 40))
  setMaxStepsSignal(v)
  writePref('decibel.maxSteps', String(v))
}

// Auto-compaction: when the context window passes ~80% after a turn, summarize +
// replace the history automatically (same path as /compact). Opt-in (off by
// default) so a long conversation is never rewritten behind the operator's back
// unless they asked for it.
const [autoCompact, setAutoCompactSignal] = createSignal<boolean>(readPref<string>('decibel.autoCompact', 'off') === 'on')
export { autoCompact }
export function setAutoCompact(on: boolean): void {
  setAutoCompactSignal(on)
  writePref('decibel.autoCompact', on ? 'on' : 'off')
}

// ── MCP servers (persisted config list; also synced to the backend) ──────────
// Remote (SSH) execution config: when enabled with a host, the `shell` tool runs
// commands on the remote box. `keyPath` is a key-FILE path, not a secret, so it's
// safe to persist in localStorage.
export interface RemoteExec {
  enabled: boolean
  host: string
  port?: number
  user: string
  keyPath: string
  workspace?: string
}
function readRemote(): RemoteExec {
  const base: RemoteExec = { enabled: false, host: '', user: '', keyPath: '' }
  try {
    const raw = localStorage.getItem('decibel.remote')
    const v = raw ? JSON.parse(raw) : null
    return v && typeof v === 'object' ? { ...base, ...v } : base
  } catch {
    return base
  }
}
const [remoteExec, setRemoteExecSignal] = createSignal<RemoteExec>(readRemote())
export { remoteExec }
export function setRemoteExec(r: RemoteExec): void {
  setRemoteExecSignal(r)
  writePref('decibel.remote', JSON.stringify(r))
}

export interface McpServer {
  name: string
  command: string
  args: string[]
}
function readMcpServers(): McpServer[] {
  try {
    const raw = localStorage.getItem('decibel.mcp')
    const v = raw ? JSON.parse(raw) : []
    return Array.isArray(v) ? v : []
  } catch {
    return []
  }
}
const [mcpServers, setMcpServersSignal] = createSignal<McpServer[]>(readMcpServers())
export { mcpServers }
/** Persist the MCP server config list (localStorage). The backend is synced
 * separately via `setMcpServers` from api.ts when the user hits Connect. */
export function saveMcpServers(list: McpServer[]): void {
  setMcpServersSignal(list)
  writePref('decibel.mcp', JSON.stringify(list))
}

/** On app start, push the persisted MCP server list to the backend (connect +
 * keep warm) so `run_prompt` has the external tools without waiting for the user
 * to open Settings and hit Connect. No-op when nothing is configured. */
export async function syncMcpToBackend(): Promise<void> {
  const list = mcpServers()
  if (list.length === 0) return
  try {
    await apiSetMcpServers(list)
  } catch {
    /* a server may be offline — surfaced when the user opens Settings or runs */
  }
}

// Access preset: 'full' = every tool; 'readonly' = recon/inspection only (no
// shell / write / edit).
export type Access = 'full' | 'readonly'
const [access, setAccessSignal] = createSignal<Access>(readPref<Access>('decibel.access', 'full'))
export { access }
export function setAccess(a: Access): void {
  setAccessSignal(a)
  writePref('decibel.access', a)
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
  /** Nested sub-agent run, present only on a `delegate` card (orchestrate mode):
   * the specialist's live steps/tools/narration streamed under this tool card. */
  specialist?: SpecialistRun
}
/** A specialist subagent's run, nested inside its `delegate` tool card. Its
 * `blocks` reuse the same Block union as the top-level timeline, so a specialist's
 * tool calls render as real (nmap/http/…) cards inside the delegation. */
export interface SpecialistRun {
  /** Session-unique id (stable across turns), for the agents panel + scroll-to. */
  uid: number
  /** The orchestrator's delegation index — correlates streamed events to this lane. */
  delegation: number
  name: string
  task?: string
  state: 'running' | 'ok' | 'error'
  stop?: string
  steps?: number
  findingsAdded?: number
  tokens?: number
  /** Wall-clock timestamps (ms) stamped when the start/end events arrive, so the
   * agents panel can show each agent's live/elapsed duration. */
  startedAt?: number
  endedAt?: number
  /** The specialist's final summary text. Shown only as a fallback when the run
   * streamed no narration (some models don't stream text), since otherwise the
   * streamed tokens already contain it. */
  summary?: string
  blocks: Block[]
}
/** A run-level system note shown inline (e.g. an automatic model fallback). */
export interface NoticeBlock {
  kind: 'notice'
  text: string
}
export type Block = TextBlock | ToolBlock | NoticeBlock
export interface Msg {
  role: 'user' | 'assistant' | 'system'
  blocks: Block[]
}

export const [conversation, setConversation] = createStore<{ list: Msg[] }>({ list: [] })
export const [running, setRunning] = createSignal(false)
export const [settingsOpen, setSettingsOpen] = createSignal(false)
// Drives the Findings drawer (a live, severity-sorted view over the transcript).
export const [findingsOpen, setFindingsOpen] = createSignal(false)
// Live context-usage for the composer meter — refreshed after each turn (backend
// `session_context`); reset when the conversation changes.
export const [contextInfo, setContextInfo] = createSignal<import('./api').ContextInfo | null>(null)
// Findings persisted server-side (the KG + finding store) for this session, so the
// drawer keeps them after a reload even though the reconstructed transcript drops the
// structured tool `value`. Merged into `findings()`, deduped against the transcript.
const [persistedFindings, setPersistedFindings] = createSignal<Finding[]>([])
/** Reload the session's persisted findings (KG `record_finding` + `add_finding`). */
export async function refreshPersistedFindings(): Promise<void> {
  const list = await sessionFindings(sessionId).catch(() => [])
  setPersistedFindings(
    list.map((f) => ({
      title: String(f.title ?? 'finding'),
      severity: String(f.severity ?? 'info').toLowerCase(),
      description: f.description || undefined,
      target: f.target || undefined,
      mitre: f.mitre || undefined,
    })),
  )
}
// Drives the live Agents panel (right column). Persisted, open by default.
const [agentsPanelOpen, setAgentsPanelOpenSignal] = createSignal(readPref<string>('decibel.agentsPanel', 'open') !== 'closed')
export { agentsPanelOpen }
export function setAgentsPanelOpen(open: boolean): void {
  setAgentsPanelOpenSignal(open)
  writePref('decibel.agentsPanel', open ? 'open' : 'closed')
}
// Drives the composer's model picker so /model can open it from anywhere.
export const [modelPickerOpen, setModelPickerOpen] = createSignal(false)
// Opens the workspace-directory picker (from the composer chip or the sidebar).
export const [workspacePanelOpen, setWorkspacePanelOpen] = createSignal(false)
// The composer draft lives in the store so it survives the hero↔docked Composer
// remount at the empty/non-empty boundary (otherwise a typed draft is lost).
export const [composerDraft, setComposerDraft] = createSignal('')
// A pending image attachment (a base64 data: URL) sent with the next prompt to a
// vision model; cleared once the run starts.
export const [pendingImage, setPendingImage] = createSignal<string>('')
let controller: AbortController | undefined
// Each run gets a monotonic id; only the active run's events are applied, so a
// cancelled or superseded run can never write into the transcript or clobber
// running-state (its backend is also cancelled via the AbortSignal → cancel_run).
let nextRunId = 1
let activeRunId = 0
// Conversation identity for the backend's multi-turn memory. A new one starts a
// fresh backend session; /clear (newSession) rotates it and drops the old one.
let sessionCounter = 0
let sessionId = `sess-${Date.now()}-${++sessionCounter}`

// The active conversation id, mirrored as a signal so the sidebar can highlight
// which saved session is open.
export const [activeSessionId, setActiveSessionId] = createSignal(sessionId)
// Saved sessions listed in the sidebar (disk-backed in the desktop app).
export const [sessions, setSessions] = createSignal<SessionMeta[]>([])
// True while a session is being loaded — blocks sends so a run can't start
// against the old session and stream into the freshly-loaded one.
export const [sessionLoading, setSessionLoading] = createSignal(false)
// Monotonic counter so a slow openSession that resolves after a newer open/new
// bails instead of clobbering the newer state.
let openGen = 0

/** Reload the saved-session list (sidebar). */
export async function refreshSessions(): Promise<void> {
  try {
    setSessions(await listSessions())
  } catch {
    /* browser preview has no persistence */
  }
}

function mapDisplayMsg(d: DisplayMsg): Msg {
  const role = d.role === 'user' ? 'user' : d.role === 'assistant' ? 'assistant' : 'system'
  return {
    role,
    blocks: d.blocks.map((b) =>
      b.kind === 'tool'
        ? { kind: 'tool', name: b.name ?? '', args: b.args ?? '', state: (b.state as any) ?? 'ok', output: b.output != null ? stripUntrusted(b.output) : b.output }
        : { kind: 'text', text: b.text ?? '' },
    ),
  }
}

/** Open a saved session: reload its transcript and continue its backend memory. */
export async function openSession(id: string): Promise<void> {
  if (running()) cancel()
  const gen = ++openGen
  setSessionLoading(true)
  try {
    const display = await loadSession(id)
    if (gen !== openGen) return // superseded by a newer open / New Session
    sessionId = id
    setActiveSessionId(id)
    setConversation('list', display.map(mapDisplayMsg))
    setContextInfo(null) // meter re-estimates from the loaded transcript
    void refreshPersistedFindings() // findings the reloaded transcript can't show
    setComposerDraft('') // a draft/image prepared for the old conversation shouldn't leak
    setPendingImage('')
  } catch {
    /* ignore a missing/corrupt session */
  } finally {
    if (gen === openGen) setSessionLoading(false)
  }
}

/** Delete a saved session (and start fresh if it's the open one). */
export async function removeSession(id: string): Promise<void> {
  await deleteSession(id).catch(() => {})
  if (id === sessionId) newSession()
  else void refreshSessions()
}

/** Rename a saved session's title. */
export async function renameSessionTitle(id: string, title: string): Promise<void> {
  if (!title.trim()) return
  await renameSession(id, title).catch(() => {})
  void refreshSessions()
}

/** Append a standalone system message (slash-command output). */
function pushSystem(blocks: Block[]): void {
  setConversation('list', (l) => [...l, { role: 'system', blocks }])
}

export function newSession(): void {
  openGen++ // supersede any in-flight session load
  cancel()
  void clearSession(sessionId).catch(() => {})
  sessionId = `sess-${Date.now()}-${++sessionCounter}`
  setActiveSessionId(sessionId)
  setConversation('list', [])
  setContextInfo(null)
  setPersistedFindings([])
  setComposerDraft('')
  setPendingImage('')
  setSessionLoading(false)
  void refreshSessions()
}

export async function send(text: string): Promise<void> {
  const prompt = text.trim()
  if (running() || sessionLoading()) return
  const model = selectedModel()
  if (!model) return
  const info = modelById(model)
  // Only attach the image to a vision model; otherwise keep it (a text-only model
  // would silently drop it) so the user can switch models and still send it.
  const supportsVision = info?.input_modalities?.includes('image') ?? false
  const image = supportsVision ? pendingImage() : ''
  if (!prompt && !image) return // nothing to send
  if (image) setPendingImage('')
  setComposerDraft('') // committed — clear the draft now (not before the guards)
  const provider = info?.provider ?? 'deepseek'

  const userBlocks: Block[] = [{ kind: 'text', text: prompt || '(image)' }]
  setConversation('list', (l) => [...l, { role: 'user', blocks: userBlocks }])
  setConversation('list', (l) => [...l, { role: 'assistant', blocks: [] }])
  const idx = conversation.list.length - 1

  const runId = nextRunId++
  activeRunId = runId
  setRunning(true)
  controller = new AbortController()
  try {
    const rc = remoteExec()
    const remote = rc.enabled && rc.host.trim() ? { host: rc.host, port: rc.port, user: rc.user, keyPath: rc.keyPath, workspace: rc.workspace } : null
    await runPrompt(prompt, model, provider, workspace(), mode(), access(), engagementScope(), image, maxSteps(), remote, sessionId, runId, (e) => applyEvent(idx, runId, e), controller.signal)
  } finally {
    // Backstop: if runPrompt rejects (e.g. an IPC failure) rather than ending
    // with a done/error event, don't leave the spinner stuck — but only touch
    // state if this run is still the active one (never clobber a newer run).
    if (runId === activeRunId) setRunning(false)
  }
}

/** Mark every still-`running` tool block (and any running specialist sub-run and
 * its nested tools) as terminal. Called on cancel/done so no phantom `running`
 * agent lingers — otherwise the Agents panel's live-duration ticker never stops,
 * since the late `specialist_end` for an aborted run is dropped by the runId guard. */
function finalizeRunningBlocks(): void {
  setConversation(
    'list',
    produce((list: Msg[]) => {
      for (const msg of list) {
        for (const b of msg.blocks) {
          if (b.kind !== 'tool') continue
          if (b.state === 'running') b.state = 'error'
          const sr = b.specialist
          if (sr && sr.state === 'running') {
            sr.state = 'error'
            if (sr.endedAt == null) sr.endedAt = Date.now()
            for (const nb of sr.blocks) {
              if (nb.kind === 'tool' && nb.state === 'running') nb.state = 'error'
            }
          }
        }
      }
    }),
  )
}

export function cancel(): void {
  // Drop the active run first so any late events from it are ignored, then abort
  // (which reaches the backend via the api's cancel_run bridge).
  activeRunId = 0
  controller?.abort()
  controller = undefined
  setRunning(false)
  // Finalize whatever was mid-flight so the agents panel's ticker stops and no
  // phantom `running` agent is left behind.
  finalizeRunningBlocks()
}

// The prompt-injection shield (backend ShieldPolicy) wraps each tool result's
// model-facing text in an untrusted envelope. These mirror the Rust constants in
// crates/decibel-offsec/src/shield/mod.rs so the UI can show clean tool output
// while the model still receives the wrapped, injection-framed version.
const UNTRUSTED_OPEN_PREFIX = '<untrusted_tool_output'
const UNTRUSTED_CLOSE = '</untrusted_tool_output>'
const UNTRUSTED_SEP = '\n---\n'
/** Inverse of the backend's `tag_untrusted` for display: if `s` is a tagged
 * block, return the inner tool content; otherwise return `s` unchanged. Defensive
 * — strips only when both markers are present (the header banner is discarded). */
function stripUntrusted(s: string): string {
  const t = s.trim()
  if (t.startsWith(UNTRUSTED_OPEN_PREFIX) && t.endsWith(UNTRUSTED_CLOSE)) {
    const a = t.indexOf(UNTRUSTED_SEP)
    const b = t.lastIndexOf(UNTRUSTED_SEP)
    if (a !== -1 && b > a) return t.slice(a + UNTRUSTED_SEP.length, b)
  }
  return s
}

// Monotonic id for specialist sub-runs, so the agents panel has a stable key +
// scroll anchor even though `delegation` resets to 0 on each new orchestrate turn.
let nextAgentUid = 1

/** The nested specialist sub-run for `delegation`, found by reverse-scanning the
 * assistant blocks for its `delegate` card. Returns undefined if not yet started. */
function findSpecialist(blocks: Block[], delegation: number): SpecialistRun | undefined {
  for (let i = blocks.length - 1; i >= 0; i--) {
    const b = blocks[i]
    if (b.kind === 'tool' && b.name === 'delegate' && b.specialist?.delegation === delegation) {
      return b.specialist
    }
  }
  return undefined
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
              // Strip the shield's untrusted envelope for a clean transcript; the
              // structured `value` is untouched by the shield, so cards still render.
              b.output = stripUntrusted(e.output)
              b.value = e.value
              break
            }
          }
          break
        }
        // ── nested specialist (orchestrate) events ──────────────────────────────
        // Each attaches to a `delegate` card and mutates its `specialist` sub-run,
        // whose `blocks` mirror the top-level timeline logic (token/tool_call/…).
        case 'specialist_start': {
          // Attach to the most recent still-running delegate card without a sub-run.
          for (let i = blocks.length - 1; i >= 0; i--) {
            const b = blocks[i]
            if (b.kind === 'tool' && b.name === 'delegate' && b.state === 'running' && !b.specialist) {
              b.specialist = {
                uid: nextAgentUid++,
                delegation: e.delegation,
                name: e.specialist,
                task: e.task,
                state: 'running',
                startedAt: Date.now(),
                blocks: [],
              }
              break
            }
          }
          break
        }
        case 'specialist_token': {
          const sr = findSpecialist(blocks, e.delegation)
          if (!sr) break
          const last = sr.blocks[sr.blocks.length - 1]
          if (last && last.kind === 'text') last.text += e.text
          else sr.blocks.push({ kind: 'text', text: e.text })
          break
        }
        case 'specialist_tool_call': {
          const sr = findSpecialist(blocks, e.delegation)
          if (!sr) break
          sr.blocks.push({ kind: 'tool', name: e.name, args: e.args, state: 'running' })
          break
        }
        case 'specialist_tool_result': {
          const sr = findSpecialist(blocks, e.delegation)
          if (!sr) break
          for (let i = sr.blocks.length - 1; i >= 0; i--) {
            const t = sr.blocks[i]
            if (t.kind === 'tool' && t.name === e.name && t.state === 'running') {
              t.state = e.ok ? 'ok' : 'error'
              t.output = stripUntrusted(e.output)
              t.value = e.value
              break
            }
          }
          break
        }
        case 'specialist_step': {
          const sr = findSpecialist(blocks, e.delegation)
          if (sr) sr.steps = e.n
          break
        }
        case 'specialist_end': {
          const sr = findSpecialist(blocks, e.delegation)
          if (sr) {
            sr.state = e.ok ? 'ok' : 'error'
            sr.stop = e.stop
            sr.steps = e.steps
            sr.findingsAdded = e.findings_added
            sr.tokens = e.tokens
            sr.summary = e.summary
            sr.endedAt = Date.now()
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
  if (e.type === 'done' || e.type === 'error') {
    setRunning(false)
    // Defensively finalize any block still `running` at turn end (a specialist that
    // died without a `specialist_end`), so the agents ticker never runs forever.
    finalizeRunningBlocks()
    // Refresh the composer's context meter with this turn's real prompt size.
    void refreshContext()
    // Pick up any findings this turn recorded into the KG / finding store.
    void refreshPersistedFindings()
    // The turn was just persisted server-side; refresh the sidebar's session list.
    if (e.type === 'done') void refreshSessions()
  }
}

// ── findings (derived live from the transcript) ───────────────────────────────
export interface Finding {
  title: string
  severity: string
  description?: string
  target?: string
  mitre?: string
}
/** Severity rank for sorting (critical → info); unknown severities sort last. */
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
function sevRank(s: string): number {
  return SEV_RANK[s.toLowerCase()] ?? 5
}

/** Scan the conversation for finding tool-cards (`add_finding` / `record_finding`)
 * and return them aggregated + severity-sorted. A live derived view: reading
 * `conversation.list` makes it reactive, so the drawer updates as findings land. */
export function findings(): Finding[] {
  const out: Finding[] = []
  // Dedup key so the same exposure recorded twice (e.g. a specialist AND the
  // orchestrator consolidating) shows once. First occurrence wins.
  const seen = new Set<string>()
  // Scan a block list for finding tool-cards, descending into any nested
  // specialist sub-run so findings recorded inside a delegation surface too.
  const scan = (blocks: Block[]): void => {
    for (const b of blocks) {
      if (b.kind !== 'tool') continue
      if (b.specialist?.blocks) scan(b.specialist.blocks)
      if (b.name !== 'add_finding' && b.name !== 'record_finding') continue
      // `add_finding` nests the finding under `.finding`; `record_finding` returns
      // the finding object as its value directly — accept either shape.
      const raw = b.value as { finding?: Partial<Finding> } & Partial<Finding> | undefined
      const f = raw && typeof raw === 'object' ? raw.finding ?? raw : undefined
      if (!f) continue
      const finding: Finding = {
        title: String(f.title ?? b.output ?? 'finding'),
        severity: String(f.severity ?? 'info').toLowerCase(),
        description: f.description ? String(f.description) : undefined,
        target: f.target ? String(f.target) : undefined,
        mitre: f.mitre ? String(f.mitre) : undefined,
      }
      const key = `${finding.title.toLowerCase()}|${(finding.target ?? '').toLowerCase()}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push(finding)
    }
  }
  for (const msg of conversation.list) scan(msg.blocks)
  // Merge server-persisted findings (the KG + finding store) — this is what keeps a
  // reopened session's findings visible after the transcript dropped its structured
  // values. Transcript findings win on a dup (they carry the freshest detail).
  for (const f of persistedFindings()) {
    const key = `${f.title.toLowerCase()}|${(f.target ?? '').toLowerCase()}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(f)
  }
  // Stable severity sort (critical first); equal severities keep discovery order.
  return out
    .map((f, i) => [f, i] as const)
    .sort((a, b) => sevRank(a[0].severity) - sevRank(b[0].severity) || a[1] - b[1])
    .map(([f]) => f)
}

// ── agents (derived live from the transcript) ─────────────────────────────────
/** Every specialist sub-run in the transcript, in start order — the data behind
 * the live Agents panel (orchestrate mode). A derived view over `conversation.list`,
 * so it updates as delegations start, stream, and finish. */
export function agentRuns(): SpecialistRun[] {
  const out: SpecialistRun[] = []
  for (const msg of conversation.list) {
    for (const b of msg.blocks) {
      if (b.kind === 'tool' && b.specialist) out.push(b.specialist)
    }
  }
  return out
}

// ── context usage (composer meter) ────────────────────────────────────────────
/** Refresh the backend-reported context usage for the current session, then
 * auto-compact if enabled and the window is nearly full. */
export async function refreshContext(): Promise<void> {
  setContextInfo(await sessionContext(sessionId).catch(() => null))
  if (autoCompact() && !running()) {
    const u = contextUsage()
    if (u && u.pct >= 80) {
      pushSystem([{ kind: 'notice', text: `Context ${u.pct}% full — auto-compacting…` }])
      void runCompact()
    }
  }
}
/** Rough token estimate from the visible transcript (~4 chars/token) — the meter's
 * fallback before the first turn and in the browser preview (no backend usage). */
function estimateTokens(): number {
  const chars = conversation.list
    .flatMap((m) => m.blocks)
    .reduce((n, b) => n + (b.kind === 'text' ? b.text.length : b.kind === 'tool' ? (b.output?.length ?? 0) + b.args.length : (b as { text?: string }).text?.length ?? 0), 0)
  return Math.round(chars / 4)
}
/** The composer's context meter: how full the model's window is. Uses the provider-
 * reported prompt size when available, else the transcript estimate. Null if no
 * model / nothing yet. Reactive over `contextInfo()` and the transcript. */
export function contextUsage(): { used: number; total: number; pct: number } | null {
  const total = modelById(selectedModel())?.context_length ?? 0
  if (!total) return null
  const used = contextInfo()?.last_input_tokens ?? estimateTokens()
  if (!used) return null
  return { used, total, pct: Math.min(100, Math.round((used / total) * 100)) }
}

// ── slash commands ────────────────────────────────────────────────────────────
export interface SlashCommand {
  name: string
  desc: string
}
export const COMMANDS: SlashCommand[] = [
  { name: 'clear', desc: 'Clear the conversation and start fresh' },
  { name: 'new', desc: 'Start a new session (alias of /clear)' },
  { name: 'compact', desc: 'Summarize the conversation to free up context' },
  { name: 'context', desc: 'Show token / context usage' },
  { name: 'model', desc: 'Open the model picker' },
  { name: 'settings', desc: 'Open settings' },
  { name: 'help', desc: 'List the slash commands' },
]

/** Whether `text` is EXACTLY a slash command (no trailing args). Trailing prose
 * (`/new the server`) is deliberately NOT a command — it sends as text — so a
 * destructive command can't fire from ambiguous input. */
export function isCommand(text: string): boolean {
  const t = text.trim()
  return COMMANDS.some((c) => t === `/${c.name}`)
}

/** Execute a slash command by name. */
export async function runSlashCommand(name: string): Promise<void> {
  switch (name) {
    case 'clear':
    case 'new':
      newSession()
      break
    case 'model':
      setModelPickerOpen(true)
      break
    case 'settings':
      setSettingsOpen(true)
      break
    case 'help':
      pushSystem([{ kind: 'text', text: helpText() }])
      break
    case 'context':
      await runContext()
      break
    case 'compact':
      await runCompact()
      break
  }
}

function helpText(): string {
  return '**Slash commands**\n\n' + COMMANDS.map((c) => `- \`/${c.name}\` — ${c.desc}`).join('\n')
}

function fmtTok(n: number): string {
  return n >= 1000 ? `${(n / 1000).toFixed(n >= 100_000 ? 0 : 1)}k` : String(n)
}
function contextLine(messages: number, est: number, lastInput: number | null, ctxLen?: number): string {
  let s = `context · ${messages} message${messages === 1 ? '' : 's'} · ~${fmtTok(est)} tokens`
  if (lastInput != null) s += ` · last turn ${fmtTok(lastInput)} in`
  if (ctxLen) {
    const used = lastInput ?? est
    s += ` · ${Math.round((used / ctxLen) * 100)}% of ${fmtTok(ctxLen)}`
  }
  return s
}

async function runContext(): Promise<void> {
  const ctxLen = modelById(selectedModel())?.context_length
  const info = await sessionContext(sessionId).catch(() => null)
  if (info) {
    pushSystem([{ kind: 'notice', text: contextLine(info.messages, info.estimated_tokens, info.last_input_tokens, ctxLen) }])
    return
  }
  // No backend (browser preview): estimate from the display conversation.
  const chars = conversation.list
    .flatMap((m) => m.blocks)
    .reduce((n, b) => n + (b.kind === 'text' ? b.text.length : b.kind === 'tool' ? (b.output?.length ?? 0) + b.args.length : b.text.length), 0)
  pushSystem([{ kind: 'notice', text: contextLine(conversation.list.length, Math.round(chars / 4), null, ctxLen) + ' (estimated)' }])
}

async function runCompact(): Promise<void> {
  if (running()) return
  const model = selectedModel()
  if (!model) return
  if (conversation.list.length === 0) {
    pushSystem([{ kind: 'notice', text: 'nothing to compact yet' }])
    return
  }
  const provider = modelById(model)?.provider ?? 'deepseek'
  // Tag this like a run so Stop (cancel → activeRunId=0) or /clear (rotates
  // sessionId) makes a late-resolving compaction bail instead of clobbering a
  // newer transcript or a run started after Stop.
  const runId = nextRunId++
  activeRunId = runId
  const sid = sessionId
  setRunning(true)
  try {
    const summary = await compactSession(sid, model, provider)
    if (runId !== activeRunId || sid !== sessionId) return // stopped or cleared
    if (!summary) {
      pushSystem([{ kind: 'notice', text: 'compaction needs the desktop app and an API key' }])
      return
    }
    // Replace the transcript with a single compacted-summary message; the backend
    // session now carries just this summary as context for the next turn.
    setConversation('list', [
      { role: 'system', blocks: [{ kind: 'notice', text: 'conversation compacted' }, { kind: 'text', text: summary }] },
    ])
    // Drop the stale pre-compaction usage so the meter falls back to the (now tiny)
    // transcript estimate immediately, instead of staying pinned until the next turn.
    setContextInfo(null)
  } catch (e) {
    if (runId === activeRunId) pushSystem([{ kind: 'notice', text: `compact failed: ${e instanceof Error ? e.message : String(e)}` }])
  } finally {
    if (runId === activeRunId) setRunning(false)
  }
}
