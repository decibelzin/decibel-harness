import { createEffect, createSignal, For, Match, onCleanup, onMount, Show, Switch, type JSX } from 'solid-js'

import './App.css'
import { deleteApiKey, hasApiKey, isTauri, listMcpServers, pathIsDir, pickFolder, saveApiKey, saveExport, setMcpServers, type McpProbeResult, type ModelInfo, type SessionMeta } from './api'
import { highlightWithin, renderMarkdown } from './markdown'
import { findingsToMarkdown, findingsToSarif } from './report'
import {
  access,
  activeSessionId,
  agentRuns,
  agentsPanelOpen,
  applyTheme,
  autoCompact,
  cancel,
  COMMANDS,
  composerDraft,
  contextUsage,
  conversation,
  engagementScope,
  findings,
  findingsOpen,
  isCommand,
  maxSteps,
  mcpServers,
  mode,
  modelPickerOpen,
  openSession,
  pendingImage,
  refreshSessions,
  remoteExec,
  removeSession,
  renameSessionTitle,
  runSlashCommand,
  saveMcpServers,
  sessionLoading,
  sessions,
  setAccess,
  setAgentsPanelOpen,
  setAutoCompact,
  setEngagementScope,
  setMaxSteps,
  setRemoteExec,
  setFindingsOpen,
  setMode,
  setPendingImage,
  setComposerDraft,
  settingsOpen,
  setModelPickerOpen,
  setSettingsOpen,
  loadingModels,
  loadModels,
  modelById,
  models,
  modelsError,
  newSession,
  running,
  search,
  selectedModel,
  send,
  setSearch,
  setSelectedModel,
  setWorkspace,
  setWorkspacePanelOpen,
  syncMcpToBackend,
  theme,
  visibleModels,
  workspace,
  workspaceName,
  workspacePanelOpen,
  type Block,
  type Finding,
  type McpServer,
  type Mode,
  type SlashCommand,
  type SpecialistRun,
  type ToolBlock,
} from './store'

function fmtCtx(n: number): string {
  if (n >= 1_000_000) {
    const m = n / 1_000_000
    return Math.abs(m - Math.round(m)) < 0.05 ? `${Math.round(m)}M` : `${m.toFixed(1)}M`
  }
  if (n >= 1000) return `${Math.round(n / 1000)}K`
  return String(n)
}

/** Parse a tool's raw argument JSON; never throws (partial/invalid → {}). */
function parseArgs(raw: string): Record<string, unknown> {
  try {
    const v = JSON.parse(raw)
    return v && typeof v === 'object' ? v : {}
  } catch {
    return {}
  }
}

// ── icons (inline, currentColor) ─────────────────────────────────────────────
const svg = (children: JSX.Element, size = 18, stroke = 1.9): JSX.Element => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width={stroke} stroke-linecap="round" stroke-linejoin="round">
    {children}
  </svg>
)
// The brand mark: the user's logo.png when present (drop it in ui/public/),
// otherwise an inline SVG that approximates it — decibel bars + a `D` chevron.
function InlineMark(p: { size?: number }): JSX.Element {
  const s = p.size ?? 20
  return (
    <svg width={s} height={s} viewBox="0 0 32 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
      <rect x="1" y="11" width="2.6" height="2.4" rx="1.2" fill="currentColor" stroke="none" />
      <rect x="5" y="8" width="2.6" height="8" rx="1.3" fill="currentColor" stroke="none" />
      <rect x="9" y="4.5" width="2.6" height="15" rx="1.3" fill="currentColor" stroke="none" />
      <rect x="13" y="7" width="2.6" height="10" rx="1.3" fill="currentColor" stroke="none" />
      <path d="M18 3 L28 12 L18 21" stroke-width="3" />
    </svg>
  )
}
function Logo(p: { size?: number }): JSX.Element {
  const [failed, setFailed] = createSignal(false)
  const s = p.size ?? 20
  return (
    <Show when={!failed()} fallback={<InlineMark size={s} />}>
      <img src="/logo.png" width={s} height={s} style={{ display: 'block', 'object-fit': 'contain' }} onError={() => setFailed(true)} />
    </Show>
  )
}
const IconFolder = () => svg(<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />, 16)
const IconPlusCircle = () => svg(<><circle cx="12" cy="12" r="9" /><line x1="12" y1="8" x2="12" y2="16" /><line x1="8" y1="12" x2="16" y2="12" /></>, 16)
const IconSearch = () => svg(<><circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.5" y2="16.5" /></>, 16)
const IconAdd = () => svg(<><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></>, 16)
const IconGear = () => svg(<><circle cx="12" cy="12" r="3" /><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.3 1a7 7 0 0 0-1.7-1l-.4-2.6H9.5l-.4 2.6a7 7 0 0 0-1.7 1l-2.3-1-2 3.4L5 11a7 7 0 0 0 0 2l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 1.7 1l.4 2.6h4.9l.4-2.6a7 7 0 0 0 1.7-1l2.3 1 2-3.4-2-1.5c.1-.3.1-.7.1-1z" /></>, 16)
const IconCollapse = () => svg(<><rect x="3" y="4" width="18" height="16" rx="2" /><line x1="9" y1="4" x2="9" y2="20" /></>, 17)
const IconSend = () => svg(<><line x1="12" y1="19" x2="12" y2="5" /><polyline points="6 11 12 5 18 11" /></>, 17, 2.2)
const IconMode = () => svg(<><path d="M4 12a8 8 0 0 1 14-5" /><polyline points="18 3 18 7 14 7" /><path d="M20 12a8 8 0 0 1-14 5" /><polyline points="6 21 6 17 10 17" /></>, 15)
// tool-card glyphs
const IconTerminal = () => svg(<><polyline points="5 8 9 12 5 16" /><line x1="12" y1="16" x2="18" y2="16" /></>, 15)
const IconFile = () => svg(<><path d="M6 3h8l4 4v14H6z" /><polyline points="14 3 14 7 18 7" /></>, 15)
const IconEdit = () => svg(<><path d="M4 20h4l10-10-4-4L4 16z" /><line x1="13" y1="6" x2="17" y2="10" /></>, 15)
const IconNet = () => svg(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" /></>, 15)
const IconGlobe = () => svg(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 3 2.5 15 0 18M12 3c-2.5 3-2.5 15 0 18" /></>, 15)
const IconShield = () => svg(<path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" />, 15)
const IconWrench = () => svg(<path d="M14 6a4 4 0 0 0-5 5L4 16l4 4 5-5a4 4 0 0 0 5-5l-3 3-2-2z" />, 15)
const IconSwitch = () => svg(<><path d="M4 12a8 8 0 0 1 14-5" /><polyline points="18 2 18 7 13 7" /><path d="M20 12a8 8 0 0 1-14 5" /><polyline points="6 22 6 17 11 17" /></>, 13)
const IconFlag = () => svg(<><line x1="5" y1="21" x2="5" y2="3" /><path d="M5 4h12l-2.5 4L17 12H5" /></>, 16)
const IconAgents = () => svg(<><circle cx="9" cy="8" r="3" /><path d="M3 20a6 6 0 0 1 12 0" /><path d="M16 6a3 3 0 0 1 0 6" /><path d="M18.5 20a6 6 0 0 0-3-5.2" /></>, 15)

// ── sidebar ──────────────────────────────────────────────────────────────────
function Sidebar() {
  const [editing, setEditing] = createSignal<string | null>(null)
  const [editVal, setEditVal] = createSignal('')
  onMount(refreshSessions)
  const startRename = (s: SessionMeta) => {
    setEditing(s.id)
    setEditVal(s.title)
  }
  const commitRename = (id: string) => {
    void renameSessionTitle(id, editVal())
    setEditing(null)
  }
  return (
    <aside class="sidebar">
      <div class="brand">
        <span class="logo"><Logo size={30} /></span>
        <span class="name">Decibel</span>
        <span class="pill">v0.1</span>
        <button class="collapse" title="Collapse"><IconCollapse /></button>
      </div>
      <button class="new-btn" onClick={newSession}>
        <IconPlusCircle /> New Session
      </button>
      <div class="ws-header">
        <span class="label">Workspace</span>
        <span class="actions">
          <button title="Set workspace" onClick={() => setWorkspacePanelOpen(true)}><IconAdd /></button>
        </span>
      </div>
      <Show
        when={workspaceName()}
        fallback={<button class="ws-empty" onClick={() => setWorkspacePanelOpen(true)}>Set a workspace…</button>}
      >
        <button class="ws-item" onClick={() => setWorkspacePanelOpen(true)} title={workspace()}>
          <span class="fico"><IconFolder /></span>
          {workspaceName()}
        </button>
      </Show>
      <div class="ws-header">
        <span class="label">Sessions</span>
        <span class="actions">
          <button title="Refresh" onClick={() => refreshSessions()}><IconSearch /></button>
        </span>
      </div>
      <div class="sess-list">
        <For each={sessions()}>
          {(s) => (
            <div class={`sess-item ${s.id === activeSessionId() ? 'active' : ''}`}>
              <Show
                when={editing() === s.id}
                fallback={
                  <>
                    <button class="sess-open" onClick={() => openSession(s.id)} title={s.title}>
                      {s.title}
                    </button>
                    <button class="sess-act" title="Rename" onClick={() => startRename(s)}><IconEdit /></button>
                    <button class="sess-del" title="Delete session" onClick={() => removeSession(s.id)}>✕</button>
                  </>
                }
              >
                <input
                  class="sess-edit"
                  value={editVal()}
                  ref={(el) => setTimeout(() => el.focus(), 0)}
                  onInput={(e) => setEditVal(e.currentTarget.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') commitRename(s.id)
                    if (e.key === 'Escape') setEditing(null)
                  }}
                  onBlur={() => setEditing(null)}
                />
              </Show>
            </div>
          )}
        </For>
        <Show when={sessions().length === 0}>
          <div class="sess-empty">No saved sessions yet — start one below.</div>
        </Show>
      </div>
      <button class="findings-btn" onClick={() => setAgentsPanelOpen(!agentsPanelOpen())}>
        <IconAgents /> Agents
        <Show when={agentRuns().some((a) => a.state === 'running')}>
          <span class="fbadge live">{agentRuns().filter((a) => a.state === 'running').length}</span>
        </Show>
        <Show when={!agentRuns().some((a) => a.state === 'running') && agentRuns().length}>
          <span class="fbadge">{agentRuns().length}</span>
        </Show>
      </button>
      <button class="findings-btn" onClick={() => setFindingsOpen(true)}>
        <IconFlag /> Findings
        <Show when={findings().length}><span class="fbadge">{findings().length}</span></Show>
      </button>
      <button class="settings" onClick={() => setSettingsOpen(true)}><IconGear /> Settings</button>
    </aside>
  )
}

// ── findings drawer (live, severity-sorted view over the transcript) ──────────
function FindingsPanel() {
  const stamp = () => new Date().toISOString().slice(0, 10)
  const exportAs = (fmt: 'md' | 'sarif') => {
    const list = findings()
    if (!list.length) return
    const contents = fmt === 'md' ? findingsToMarkdown(list) : findingsToSarif(list)
    const name = fmt === 'md' ? `findings-${stamp()}.md` : `findings-${stamp()}.sarif`
    void saveExport(name, contents)
  }
  return (
    <div class="modal-backdrop findings-back" onClick={() => setFindingsOpen(false)}>
      <div class="findings-drawer" onClick={(e) => e.stopPropagation()}>
        <div class="fp-head">
          <span class="fp-ico"><IconFlag /></span>
          <span class="fp-title">Findings</span>
          <span class="fp-count">{findings().length}</span>
          <Show when={findings().length}>
            <button class="fp-export" title="Export as Markdown" onClick={() => exportAs('md')}>.md</button>
            <button class="fp-export" title="Export as SARIF" onClick={() => exportAs('sarif')}>SARIF</button>
          </Show>
          <button class="x" onClick={() => setFindingsOpen(false)}>✕</button>
        </div>
        <div class="fp-body">
          <Show
            when={findings().length}
            fallback={
              <div class="fp-empty">
                No findings yet. As the agent records confirmed weaknesses with
                {' '}<code>add_finding</code> / <code>record_finding</code>, they appear here — sorted by severity.
              </div>
            }
          >
            <For each={findings()}>
              {(f: Finding) => (
                <div class="fp-item">
                  <div class="fp-item-head">
                    <span class={`sev ${f.severity}`}>{f.severity}</span>
                    <span class="fp-item-title">{f.title}</span>
                    <Show when={f.mitre}><span class="mitre">{f.mitre}</span></Show>
                  </div>
                  <Show when={f.target}><div class="fd-target">{f.target}</div></Show>
                  <Show when={f.description}><div class="fd-desc">{f.description}</div></Show>
                </div>
              )}
            </For>
          </Show>
        </div>
      </div>
    </div>
  )
}

// ── settings (tabbed page) ────────────────────────────────────────────────────
type SettingsTab = 'models' | 'general' | 'mcp' | 'appearance' | 'about'

interface KeyFieldProps {
  provider: string
  label: string
  placeholder: string
  help: JSX.Element
  note?: string
}
function ApiKeyField(props: KeyFieldProps) {
  const [key, setKey] = createSignal('')
  const [stored, setStored] = createSignal(false)
  const [busy, setBusy] = createSignal(false)
  const [error, setError] = createSignal<string | undefined>()
  const [saved, setSaved] = createSignal(false)
  void hasApiKey(props.provider).then(setStored).catch(() => {})
  const save = async () => {
    const k = key().trim()
    if (!k) return
    setBusy(true); setError(undefined); setSaved(false)
    try {
      await saveApiKey(props.provider, k)
      setKey('')
      setStored(await hasApiKey(props.provider))
      setSaved(true)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  const clear = async () => {
    setBusy(true); setError(undefined); setSaved(false)
    try {
      await deleteApiKey(props.provider)
      setStored(await hasApiKey(props.provider))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div class="setting">
      <div class="field-label">{props.label}</div>
      <div class="field-help">{props.help}</div>
      <Show when={!isTauri()}>
        <div class="key-status" style={{ color: 'var(--warning)' }}>
          <span class="kd" style={{ background: 'var(--warning)' }} />
          Browser preview — the keyring only works in the desktop app (npm run app).
        </div>
      </Show>
      <div class="field-row">
        <input
          type="password"
          placeholder={props.placeholder}
          value={key()}
          onInput={(e) => setKey(e.currentTarget.value)}
          onKeyDown={(e) => e.key === 'Enter' && save()}
        />
        <button class="btn primary" disabled={busy() || !key().trim()} onClick={save}>
          {busy() ? 'Saving…' : 'Save'}
        </button>
        <Show when={stored()}>
          <button class="btn danger" disabled={busy()} onClick={clear}>Clear</button>
        </Show>
      </div>
      <Show when={error()}>
        {(e) => (
          <div class="key-status" style={{ color: 'var(--danger)' }}>
            <span class="kd" style={{ background: 'var(--danger)' }} />Failed: {e()}
          </div>
        )}
      </Show>
      <Show when={saved() && !error()}>
        <div class="key-status set"><span class="kd" />Key saved to the keyring.</div>
      </Show>
      <div class={`key-status ${stored() ? 'set' : ''}`}>
        <span class="kd" />
        {stored() ? 'A key is stored in the keyring.' : (props.note ?? 'No key set.')}
      </div>
    </div>
  )
}

function ModelsTab() {
  return (
    <>
      <ApiKeyField
        provider="deepseek"
        label="DeepSeek API key"
        placeholder="sk-…"
        note="No key set — the paid DeepSeek models can't run until you add one."
        help={
          <>
            For the paid DeepSeek models. Stored in your OS keyring. Create a key at{' '}
            <a href="https://platform.deepseek.com/api_keys" target="_blank" rel="noreferrer">platform.deepseek.com/api_keys</a>{' '}
            (add credit under Top Up).
          </>
        }
      />
      <ApiKeyField
        provider="openrouter"
        label="OpenRouter API key"
        placeholder="sk-or-v1-…"
        note="No key set — the free OpenRouter models can't run until you add one."
        help={
          <>
            For the free, tool-capable models served via OpenRouter (OpenRouter has no free DeepSeek
            models, so these are other providers). Stored in your OS keyring. Create a free key at{' '}
            <a href="https://openrouter.ai/keys" target="_blank" rel="noreferrer">openrouter.ai/keys</a>.
          </>
        }
      />
      <div class="setting">
        <div class="field-label">Default model</div>
        <div class="field-help">The model new runs start with. Paid DeepSeek models and free OpenRouter models are both listed.</div>
        <div class="filters embedded">
          <input class="search" placeholder="search models…" value={search()} onInput={(e) => setSearch(e.currentTarget.value)} />
          <button class="refresh" onClick={() => loadModels()}>{loadingModels() ? '…' : '↻'}</button>
        </div>
        <div class="model-count">
          <Show when={modelsError()} fallback={<>Showing {visibleModels().length} of {models().length} models</>}>
            {(err) => <span style={{ color: 'var(--danger)' }}>catalog error: {err()}</span>}
          </Show>
        </div>
        <div class="model-rows embedded">
          <For each={visibleModels()}>
            {(m) => (
              <div class={`model-row ${m.id === selectedModel() ? 'selected' : ''}`} onClick={() => setSelectedModel(m.id)}>
                <div class="mid">
                  <div class="name">{m.name}</div>
                  <div class="sub">{m.id}</div>
                </div>
                <ModelBadges m={m} />
              </div>
            )}
          </For>
        </div>
      </div>
    </>
  )
}

function GeneralTab() {
  const scopeTargets = () => engagementScope().split(/[\n,]/).map((t) => t.trim()).filter((t) => t !== '')
  return (
    <>
      <div class="setting">
        <div class="field-label">Providers</div>
        <div class="field-help">Decibel runs models from two sources: the paid <b>DeepSeek API</b> (deepseek-v4-*, billed to your DeepSeek account) and the <b>free tool-capable models on OpenRouter</b> (rate-limited; OpenRouter has no free DeepSeek models, so these are other providers — MiniMax, GLM, Gemma, …). Each needs its own key under Models &amp; Providers; the run routes to whichever the picked model belongs to.</div>
      </div>
      <div class="setting">
        <div class="field-label">Engagement scope (Rules of Engagement)</div>
        <div class="field-help">
          Authorized targets — IPs, CIDRs, or domains, one per line (or comma-separated). When set, the agent
          refuses any tool call or shell egress aimed outside this list. Leave empty for <b>no RoE restriction</b>
          {' '}(every target allowed).
        </div>
        <textarea
          class="scope-input"
          rows={4}
          placeholder={'10.0.0.0/24\nexample.com\n192.168.1.10'}
          value={engagementScope()}
          onInput={(e) => setEngagementScope(e.currentTarget.value)}
        />
        <div class={`key-status ${scopeTargets().length ? 'set' : ''}`}>
          <span class="kd" />
          {scopeTargets().length
            ? `RoE enforced — ${scopeTargets().length} target${scopeTargets().length === 1 ? '' : 's'} in scope.`
            : 'No scope set — no RoE restriction.'}
        </div>
      </div>
      <div class="setting row">
        <div>
          <div class="field-label">Max steps per turn</div>
          <div class="field-help">The agent's runaway backstop — how many tool steps one turn may take before it stops. Higher = deeper autonomous engagements; lower = shorter, cheaper runs. Default 40.</div>
        </div>
        <input
          class="num-input"
          type="number"
          min={1}
          max={200}
          value={maxSteps()}
          onChange={(e) => {
            setMaxSteps(parseInt(e.currentTarget.value, 10))
            // Re-sync the field to the clamped value even when the signal didn't
            // change (Solid suppresses equal writes), so it never shows a rejected number.
            e.currentTarget.value = String(maxSteps())
          }}
        />
      </div>
      <div class="setting row">
        <div>
          <div class="field-label">Auto-compact the conversation</div>
          <div class="field-help">When the model's context window passes ~80%, summarize the history and replace it automatically (same as <code>/compact</code>) so a long engagement doesn't overflow. Off by default — the transcript is only rewritten when you enable this.</div>
        </div>
        <button class={`switch ${autoCompact() ? 'on' : ''}`} role="switch" aria-checked={autoCompact()} onClick={() => setAutoCompact(!autoCompact())}>
          <span class="knob" />
        </button>
      </div>
      <div class="setting">
        <div class="setting row" style={{ 'margin-bottom': '10px' }}>
          <div>
            <div class="field-label">Remote execution (SSH)</div>
            <div class="field-help">Run the <code>shell</code> tool on a remote host (e.g. a Kali box) over SSH instead of locally — drive its arsenal without installing anything here. Other tools stay local. Auth is a private-key <b>file path</b> (no password is stored).</div>
          </div>
          <button
            class={`switch ${remoteExec().enabled ? 'on' : ''}`}
            role="switch"
            aria-checked={remoteExec().enabled}
            onClick={() => setRemoteExec({ ...remoteExec(), enabled: !remoteExec().enabled })}
          >
            <span class="knob" />
          </button>
        </div>
        <Show when={remoteExec().enabled}>
          <div class="remote-grid">
            <input class="remote-in" placeholder="host or IP" value={remoteExec().host} onInput={(e) => setRemoteExec({ ...remoteExec(), host: e.currentTarget.value })} />
            <input class="remote-in" type="number" placeholder="port 22" value={remoteExec().port ?? ''} onInput={(e) => setRemoteExec({ ...remoteExec(), port: parseInt(e.currentTarget.value, 10) || undefined })} />
            <input class="remote-in" placeholder="user" value={remoteExec().user} onInput={(e) => setRemoteExec({ ...remoteExec(), user: e.currentTarget.value })} />
            <input class="remote-in remote-wide" placeholder="private key file path (e.g. C:\\Users\\you\\.ssh\\id_ed25519)" value={remoteExec().keyPath} onInput={(e) => setRemoteExec({ ...remoteExec(), keyPath: e.currentTarget.value })} />
            <input class="remote-in remote-wide" placeholder="remote workspace dir (optional)" value={remoteExec().workspace ?? ''} onInput={(e) => setRemoteExec({ ...remoteExec(), workspace: e.currentTarget.value || undefined })} />
          </div>
          <div class="field-help" style={{ 'margin-top': '8px' }}>Uses an unencrypted key file (or one your ssh-agent holds). A connection/build error aborts the run rather than silently running locally.</div>
        </Show>
      </div>
      <div class="setting">
        <div class="field-label">Authority</div>
        <div class="field-help">Decibel runs with full shell, filesystem, and network authority by design — there is no sandbox. Only run it against systems you own or are authorized to test. Secret-looking environment variables are scrubbed from spawned processes so keys never leak into context.</div>
      </div>
    </>
  )
}

function McpTab() {
  const [list, setList] = createSignal<McpServer[]>(mcpServers().map((s) => ({ ...s, args: [...s.args] })))
  const [results, setResults] = createSignal<McpProbeResult[]>([])
  const [busy, setBusy] = createSignal(false)
  const [err, setErr] = createSignal<string | undefined>()

  // Reconcile with the backend's configured servers on open (keeps the UI list in
  // sync with what run_prompt will actually use). Falls back to the persisted list.
  onMount(async () => {
    try {
      const backend = await listMcpServers()
      if (backend.length) setList(backend.map((s) => ({ name: s.name, command: s.command, args: [...s.args] })))
    } catch {
      /* browser preview — keep the persisted list */
    }
  })

  const update = (i: number, patch: Partial<McpServer>) =>
    setList(list().map((s, j) => (j === i ? { ...s, ...patch } : s)))
  const add = () => setList([...list(), { name: '', command: '', args: [] }])
  const remove = (i: number) => setList(list().filter((_, j) => j !== i))
  const resultFor = (name: string) => results().find((r) => r.name === name)

  const connect = async () => {
    const clean = list()
      .map((s) => ({ name: s.name.trim(), command: s.command.trim(), args: s.args.filter((a) => a.trim() !== '') }))
      .filter((s) => s.name && s.command)
    saveMcpServers(clean) // persist the config list to localStorage
    setList(clean.map((s) => ({ ...s, args: [...s.args] })))
    setBusy(true)
    setErr(undefined)
    try {
      setResults(await setMcpServers(clean.map((s) => ({ name: s.name, command: s.command, args: s.args }))))
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div class="setting">
      <div class="field-label">MCP servers</div>
      <div class="field-help">
        External Model Context Protocol tool servers (HexStrike AI, Kali-MCP, …). Each is spawned over stdio and its
        tools become available to the agent (named <code>mcp_&lt;name&gt;_…</code>) on non-plan runs. Set the launch
        command, then Connect to validate it and discover its tools.
      </div>
      <Show when={!isTauri()}>
        <div class="key-status" style={{ color: 'var(--warning)' }}>
          <span class="kd" style={{ background: 'var(--warning)' }} />
          Browser preview — MCP servers only connect in the desktop app (npm run app).
        </div>
      </Show>
      <div class="mcp-list">
        <For each={list()}>
          {(s, i) => {
            const r = () => resultFor(s.name.trim())
            return (
              <div class="mcp-row">
                <div class="mcp-fields">
                  <input class="mcp-name" placeholder="name" value={s.name} onInput={(e) => update(i(), { name: e.currentTarget.value })} />
                  <input class="mcp-cmd" placeholder="command (e.g. python)" value={s.command} onInput={(e) => update(i(), { command: e.currentTarget.value })} />
                  <input
                    class="mcp-args"
                    placeholder="args (space-separated)"
                    value={s.args.join(' ')}
                    onInput={(e) => update(i(), { args: e.currentTarget.value.split(/\s+/).filter((a) => a !== '') })}
                  />
                  <button class="mcp-del" title="Remove server" onClick={() => remove(i())}>✕</button>
                </div>
                <Show when={r()}>
                  {(res) => (
                    <div class={`mcp-result ${res().ok ? 'ok' : 'bad'}`}>
                      <span class="kd" />
                      <Show
                        when={res().ok}
                        fallback={<span>failed: {res().error}</span>}
                      >
                        <span>
                          connected — {res().tools.length} tool{res().tools.length === 1 ? '' : 's'}
                          <Show when={res().tools.length}>: {res().tools.slice(0, 8).join(', ')}{res().tools.length > 8 ? ', …' : ''}</Show>
                        </span>
                      </Show>
                    </div>
                  )}
                </Show>
              </div>
            )
          }}
        </For>
        <Show when={list().length === 0}>
          <div class="mcp-empty">No MCP servers configured. Add one below.</div>
        </Show>
      </div>
      <div class="mcp-actions">
        <button class="btn" onClick={add}><span class="ico"><IconAdd /></span> Add server</button>
        <button class="btn primary" disabled={busy() || !isTauri()} onClick={connect}>{busy() ? 'Connecting…' : 'Connect / test'}</button>
      </div>
      <Show when={err()}>
        <div class="key-status" style={{ color: 'var(--danger)' }}><span class="kd" style={{ background: 'var(--danger)' }} />{err()}</div>
      </Show>
    </div>
  )
}

function AppearanceTab() {
  const opts: { id: ReturnType<typeof theme>; label: string; hint: string }[] = [
    { id: 'dark', label: 'Dark', hint: 'The default near-black surface.' },
    { id: 'light', label: 'Light', hint: 'A bright surface for daylight work.' },
    { id: 'system', label: 'System', hint: 'Follow the OS appearance setting.' },
  ]
  return (
    <div class="setting">
      <div class="field-label">Theme</div>
      <div class="field-help">Choose the app's appearance.</div>
      <div class="theme-opts">
        <For each={opts}>
          {(o) => (
            <button class={`theme-opt ${theme() === o.id ? 'selected' : ''}`} onClick={() => applyTheme(o.id)}>
              <span class={`swatch ${o.id}`} />
              <span class="to-label">{o.label}</span>
              <span class="to-hint">{o.hint}</span>
            </button>
          )}
        </For>
      </div>
    </div>
  )
}

function AboutTab() {
  return (
    <div class="setting about">
      <div class="about-head">
        <span class="logo"><Logo size={40} /></span>
        <div>
          <div class="about-name">Decibel <span class="pill">v0.1</span></div>
          <div class="field-help">Autonomous offensive-security agent</div>
        </div>
      </div>
      <p class="about-text">
        A lightweight desktop red-team / pentest agent. It drives a recon → analysis → exploitation →
        reporting loop over an offensive toolkit (shell, nmap, http, filesystem, search, findings),
        powered by the paid DeepSeek API plus the free tool-capable models on OpenRouter.
        No guardrails by design.
      </p>
      <div class="about-links">
        <a href="https://github.com/decibelzin/decibel-harness" target="_blank" rel="noreferrer">Repository</a>
        <a href="https://platform.deepseek.com/api_keys" target="_blank" rel="noreferrer">Get an API key</a>
      </div>
    </div>
  )
}

function Settings() {
  const [tab, setTab] = createSignal<SettingsTab>('models')
  const tabs: { id: SettingsTab; label: string }[] = [
    { id: 'models', label: 'Models & Providers' },
    { id: 'general', label: 'General' },
    { id: 'mcp', label: 'MCP Servers' },
    { id: 'appearance', label: 'Appearance' },
    { id: 'about', label: 'About' },
  ]
  return (
    <div class="modal-backdrop" onClick={() => setSettingsOpen(false)}>
      <div class="settings-page" onClick={(e) => e.stopPropagation()}>
        <div class="sp-head">
          Settings
          <button class="x" onClick={() => setSettingsOpen(false)}>✕</button>
        </div>
        <div class="sp-body">
          <nav class="sp-nav">
            <For each={tabs}>
              {(t) => (
                <button class={`sp-tab ${tab() === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>{t.label}</button>
              )}
            </For>
          </nav>
          <div class="sp-content">
            <Switch>
              <Match when={tab() === 'models'}><ModelsTab /></Match>
              <Match when={tab() === 'general'}><GeneralTab /></Match>
              <Match when={tab() === 'mcp'}><McpTab /></Match>
              <Match when={tab() === 'appearance'}><AppearanceTab /></Match>
              <Match when={tab() === 'about'}><AboutTab /></Match>
            </Switch>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── model badges & selector ──────────────────────────────────────────────────
function ModelBadges(props: { m: ModelInfo }) {
  return (
    <>
      <span class="badge ctx">{fmtCtx(props.m.context_length)}</span>
      <Show when={props.m.is_free}><span class="badge free">free</span></Show>
      <Show when={props.m.provider === 'openrouter'}><span class="badge prov">openrouter</span></Show>
      <span class={`badge ${props.m.supports_tools ? 'tools' : 'notools'}`}>
        {props.m.supports_tools ? 'tools' : 'no tools'}
      </span>
    </>
  )
}

function ModelPanel(props: { onClose: () => void }) {
  return (
    <>
      <div class="backdrop" onClick={props.onClose} />
      <div class="model-panel">
        <div class="filters">
          <input class="search" placeholder="search models…" value={search()} onInput={(e) => setSearch(e.currentTarget.value)} />
          <button class="refresh" onClick={() => loadModels()}>{loadingModels() ? '…' : '↻'}</button>
        </div>
        <div class="model-count">
          <Show
            when={modelsError()}
            fallback={<>Showing {visibleModels().length} of {models().length} models</>}
          >
            {(err) => <span style={{ color: 'var(--danger)' }}>catalog error: {err()}</span>}
          </Show>
        </div>
        <div class="model-rows">
          <For each={visibleModels()}>
            {(m) => (
              <div class={`model-row ${m.id === selectedModel() ? 'selected' : ''}`} onClick={() => { setSelectedModel(m.id); props.onClose() }}>
                <div class="mid">
                  <div class="name">{m.name}</div>
                  <div class="sub">{m.id}</div>
                </div>
                <ModelBadges m={m} />
              </div>
            )}
          </For>
        </div>
      </div>
    </>
  )
}

// ── chip dropdown (mode / access) ─────────────────────────────────────────────
interface ChipOption {
  value: string
  label: string
  desc?: string
}
function ChipDropdown(props: { icon?: JSX.Element; value: string; options: ChipOption[]; onSelect: (v: string) => void }) {
  const [open, setOpen] = createSignal(false)
  const current = () => props.options.find((o) => o.value === props.value)
  return (
    <div class="chip-anchor">
      <button class="chip" onClick={() => setOpen(!open())}>
        {props.icon}
        {current()?.label ?? props.value}
        <span class="caret">▾</span>
      </button>
      <Show when={open()}>
        <div class="backdrop" onClick={() => setOpen(false)} />
        <div class="chip-menu">
          <For each={props.options}>
            {(o) => (
              <button class={`chip-opt ${o.value === props.value ? 'sel' : ''}`} onClick={() => { props.onSelect(o.value); setOpen(false) }}>
                <span class="co-label">{o.label}</span>
                <Show when={o.desc}><span class="co-desc">{o.desc}</span></Show>
              </button>
            )}
          </For>
        </div>
      </Show>
    </div>
  )
}

// ── workspace picker ──────────────────────────────────────────────────────────
function WorkspacePanel() {
  const [path, setPath] = createSignal(workspace())
  const [err, setErr] = createSignal<string | undefined>()
  const [busy, setBusy] = createSignal(false)
  const close = () => setWorkspacePanelOpen(false)
  const apply = async () => {
    const p = path().trim()
    if (!p) {
      setWorkspace('')
      close()
      return
    }
    setBusy(true)
    setErr(undefined)
    const ok = await pathIsDir(p)
    setBusy(false)
    if (!ok) {
      setErr('Not a directory on this machine.')
      return
    }
    setWorkspace(p)
    close()
  }
  const browse = async () => {
    const dir = await pickFolder()
    if (dir) {
      setWorkspace(dir)
      close()
    }
  }
  return (
    <div class="modal-backdrop" onClick={close}>
      <div class="modal" onClick={(e) => e.stopPropagation()}>
        <div class="m-head">Workspace<button class="x" onClick={close}>✕</button></div>
        <div class="m-body">
          <div class="field-help">
            The folder the agent's shell / read / write / edit / glob / grep tools operate in — relative
            paths it uses resolve here. Leave empty to use the app's own directory.
          </div>
          <Show when={isTauri()}>
            <button class="btn primary ws-browse" onClick={browse}>
              <span class="ico"><IconFolder /></span>Choose folder…
            </button>
          </Show>
          <div class="ws-or">or paste a path</div>
          <div class="field-row">
            <input
              class="ws-input"
              placeholder="C:\path\to\target"
              value={path()}
              onInput={(e) => setPath(e.currentTarget.value)}
              onKeyDown={(e) => e.key === 'Enter' && apply()}
            />
            <button class="btn" disabled={busy()} onClick={apply}>{busy() ? '…' : 'Set'}</button>
            <Show when={workspace()}>
              <button class="btn danger" onClick={() => { setWorkspace(''); close() }}>Clear</button>
            </Show>
          </div>
          <Show when={err()}>
            <div class="key-status" style={{ color: 'var(--danger)' }}>
              <span class="kd" style={{ background: 'var(--danger)' }} />{err()}
            </div>
          </Show>
          <div class={`key-status ${workspace() ? 'set' : ''}`}>
            <span class="kd" />
            {workspace() ? `Working in: ${workspace()}` : 'No workspace set — using the app directory.'}
          </div>
          <Show when={!isTauri()}>
            <div class="key-status" style={{ color: 'var(--warning)' }}>
              <span class="kd" style={{ background: 'var(--warning)' }} />
              Browser preview — the native picker only works in the desktop app.
            </div>
          </Show>
        </div>
      </div>
    </div>
  )
}

// ── composer (used centered in the hero and docked in a chat) ─────────────────
function Composer() {
  // Draft lives in the store so it survives the hero↔docked remount.
  const draft = composerDraft
  const setDraft = setComposerDraft
  const [sel, setSel] = createSignal(0)
  const current = () => modelById(selectedModel())
  let taEl: HTMLTextAreaElement | undefined
  let fileInput: HTMLInputElement | undefined
  const visionOk = () => modelById(selectedModel())?.input_modalities?.includes('image') ?? false
  onMount(() => {
    taEl?.focus()
    // Restore the auto-grow height for a multi-line draft preserved across the
    // hero↔docked remount (otherwise it collapses into a one-row box).
    if (taEl && draft()) {
      taEl.style.height = 'auto'
      taEl.style.height = `${Math.min(taEl.scrollHeight, 220)}px`
    }
  })
  const onPickFile = (e: Event & { currentTarget: HTMLInputElement }) => {
    const file = e.currentTarget.files?.[0]
    e.currentTarget.value = '' // allow re-picking the same file
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => setPendingImage(String(reader.result))
    reader.readAsDataURL(file)
  }

  // Slash-command autocomplete: active while typing "/word" (no space yet).
  const slashQuery = (): string | null => {
    const t = draft()
    if (!t.startsWith('/')) return null
    const rest = t.slice(1)
    if (/\s/.test(rest)) return null
    return rest
  }
  const slashMatches = (): SlashCommand[] => {
    const q = slashQuery()
    if (q === null) return []
    const lq = q.toLowerCase()
    return COMMANDS.filter((c) => c.name.startsWith(lq))
  }
  const menuOpen = () => slashMatches().length > 0

  const exec = (name: string) => {
    setDraft('')
    setSel(0)
    void runSlashCommand(name)
  }
  const submit = () => {
    if (running()) return cancel()
    const t = draft().trim()
    if (t === '/') return // bare slash: keep the menu open, don't act
    if (isCommand(t)) return exec(t.slice(1)) // exact "/name" only
    if (t.startsWith('/') && slashQuery()) {
      const m = slashMatches()
      // A single unambiguous match runs; a longer prefix COMPLETES (so Enter on
      // "/c" fills "/clear" for review instead of auto-wiping the conversation).
      if (m.length === 1) return exec(m[0].name)
      if (m.length > 1) {
        setDraft(`/${m[Math.min(sel(), m.length - 1)].name}`)
        return
      }
    }
    // Normal prompt: send() clears the draft only once it actually commits, so a
    // missing model or an in-flight session load never destroys the typed text.
    void send(t)
  }
  return (
    <div class="composer-card">
      <Show when={menuOpen()}>
        <div class="slash-menu">
          <For each={slashMatches()}>
            {(c, i) => (
              <div
                class={`slash-item ${i() === sel() ? 'sel' : ''}`}
                onMouseEnter={() => setSel(i())}
                onMouseDown={(e) => {
                  e.preventDefault()
                  exec(c.name)
                }}
              >
                <span class="sc-name">/{c.name}</span>
                <span class="sc-desc">{c.desc}</span>
              </div>
            )}
          </For>
        </div>
      </Show>
      <div class="chips-top">
        <button class="chip" onClick={() => setWorkspacePanelOpen(true)} title={workspace() || 'Set the working directory'}>
          <span class="ico"><IconFolder /></span>{workspaceName() || 'workspace'}<span class="caret">▾</span>
        </button>
        <ChipDropdown
          icon={<span class="ico"><IconMode /></span>}
          value={mode()}
          onSelect={(v) => setMode(v as Mode)}
          options={[
            { value: 'act', label: 'Act mode', desc: 'Run tools and act on the target' },
            { value: 'plan', label: 'Plan mode', desc: 'Propose a plan; execute nothing' },
            { value: 'orchestrate', label: 'Orchestrate', desc: 'Multi-agent: delegates to specialists' },
          ]}
        />
      </div>
      <Show when={pendingImage()}>
        <div class="attach-preview">
          <img src={pendingImage()} alt="attachment" />
          <button class="attach-remove" title="Remove image" onClick={() => setPendingImage('')}>✕</button>
        </div>
        <Show when={!visionOk()}>
          <div class="attach-warn">⚠ The selected model has no vision — switch to a vision model (e.g. deepseek-v4-flash-vision-exp) to send this image.</div>
        </Show>
      </Show>
      <textarea
        ref={taEl}
        rows={1}
        placeholder="Describe the engagement — or type / for commands"
        value={draft()}
        onInput={(e) => {
          setDraft(e.currentTarget.value)
          setSel(0)
          e.currentTarget.style.height = 'auto'
          e.currentTarget.style.height = `${Math.min(e.currentTarget.scrollHeight, 220)}px`
        }}
        onKeyDown={(e) => {
          if (menuOpen()) {
            const items = slashMatches()
            if (e.key === 'ArrowDown') {
              e.preventDefault()
              setSel((sel() + 1) % items.length)
              return
            }
            if (e.key === 'ArrowUp') {
              e.preventDefault()
              setSel((sel() - 1 + items.length) % items.length)
              return
            }
            if (e.key === 'Escape') {
              e.preventDefault()
              setDraft('')
              return
            }
            if (e.key === 'Tab') {
              // Tab COMPLETES the highlighted command (does not execute), so a
              // destructive command never fires from a stray Tab.
              e.preventDefault()
              const m = items[Math.min(sel(), items.length - 1)]
              if (m) setDraft(`/${m.name}`)
              return
            }
          }
          if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault()
            submit()
          }
        }}
      />
      <div class="composer-bottom">
        <button class="plus-btn" title="Attach an image (needs a vision model)" onClick={() => fileInput?.click()}><IconAdd /></button>
        <input ref={fileInput} type="file" accept="image/*" style={{ display: 'none' }} onChange={onPickFile} />
        <ChipDropdown
          value={access()}
          onSelect={(v) => setAccess(v as 'full' | 'readonly')}
          options={[
            { value: 'full', label: 'Full access', desc: 'All tools — shell, write, edit, …' },
            { value: 'readonly', label: 'Read-only', desc: 'Recon only — no shell / write / edit' },
          ]}
        />
        <span class="spacer" />
        <Show when={contextUsage()}>
          {(u) => (
            <div
              class={`ctx-meter ${u().pct >= 85 ? 'hot' : u().pct >= 65 ? 'warm' : ''}`}
              title={`Context: ${fmtTokens(u().used)} / ${fmtTokens(u().total)} tokens (${u().pct}%)`}
            >
              <span class="ctx-bar"><span class="ctx-fill" style={{ width: `${u().pct}%` }} /></span>
              <span class="ctx-pct">{u().pct}%</span>
            </div>
          )}
        </Show>
        <div class="model-anchor">
          <button class="model-chip" onClick={() => setModelPickerOpen(!modelPickerOpen())}>
            <Show when={current()} fallback={<span>select model</span>}>
              {(m) => (
                <>
                  <span>{m().id}</span>
                  <span class="badge-mini">{fmtCtx(m().context_length)}{m().is_free ? ' · free' : ''}</span>
                </>
              )}
            </Show>
            <span class="caret">▾</span>
          </button>
          <Show when={modelPickerOpen()}><ModelPanel onClose={() => setModelPickerOpen(false)} /></Show>
        </div>
        <button
          class={`send ${running() ? 'stop' : ''}`}
          disabled={!running() && (sessionLoading() || (!draft().trim() && !(pendingImage() && visionOk())) || !selectedModel())}
          onClick={submit}
          title={running() ? 'Stop' : 'Run'}
        >
          <Show when={!running()} fallback={<span style={{ 'font-size': '13px' }}>■</span>}><IconSend /></Show>
        </button>
      </div>
    </div>
  )
}

// ── markdown ──────────────────────────────────────────────────────────────────
function Markdown(props: { text: string }) {
  let el: HTMLDivElement | undefined
  createEffect(() => {
    const src = props.text
    if (!el) return
    el.innerHTML = renderMarkdown(src)
    highlightWithin(el)
  })
  // Keep link clicks from navigating the webview away from the app.
  const onClick = (e: MouseEvent) => {
    const a = (e.target as HTMLElement)?.closest('a') as HTMLAnchorElement | null
    if (a?.href) {
      e.preventDefault()
      try {
        window.open(a.href, '_blank', 'noopener,noreferrer')
      } catch {
        /* opener unavailable — swallow so the app never navigates away */
      }
    }
  }
  return <div class="md" ref={el} onClick={onClick} />
}

// ── tool cards ────────────────────────────────────────────────────────────────
interface ToolMeta {
  label: string
  icon: () => JSX.Element
}
function toolMeta(name: string): ToolMeta {
  switch (name) {
    case 'shell': return { label: 'shell', icon: IconTerminal }
    case 'nmap': return { label: 'nmap', icon: IconNet }
    case 'http': return { label: 'http', icon: IconGlobe }
    case 'read_file': return { label: 'read_file', icon: IconFile }
    case 'write_file': return { label: 'write_file', icon: IconFile }
    case 'str_replace': return { label: 'str_replace', icon: IconEdit }
    case 'glob': return { label: 'glob', icon: IconSearch }
    case 'grep': return { label: 'grep', icon: IconSearch }
    case 'add_finding': return { label: 'add_finding', icon: IconShield }
    case 'delegate': return { label: 'delegate', icon: IconAgents }
    default: return { label: name, icon: IconWrench }
  }
}

/** One-line context shown in the card header (the salient argument). */
function argSummary(block: ToolBlock): string {
  const a = parseArgs(block.args)
  const s = (v: unknown) => (typeof v === 'string' ? v : v == null ? '' : String(v))
  switch (block.name) {
    case 'shell': return s(a.command)
    case 'nmap': return s(a.target)
    case 'http': return `${s(a.method || 'GET').toUpperCase()} ${s(a.url)}`.trim()
    case 'read_file':
    case 'write_file':
    case 'str_replace': return s(a.path)
    case 'glob':
    case 'grep': return s(a.pattern)
    case 'add_finding': return s(a.title)
    case 'delegate': {
      const spec = s(a.specialist)
      const task = s(a.task)
      return spec && task ? `${spec} — ${task}` : spec || task
    }
    default: {
      const first = Object.values(a).find((v) => typeof v === 'string')
      return s(first)
    }
  }
}

function ShellBody(props: { block: ToolBlock }) {
  const v = () => (props.block.value as any) ?? {}
  return (
    <>
      <pre class="term">{props.block.output || '(no output)'}</pre>
      <Show when={v().exit_code != null || v().timed_out}>
        <div class="tc-foot">
          <Show when={v().timed_out} fallback={<span class={`chip-sm ${v().exit_code === 0 ? 'ok' : 'bad'}`}>exit {String(v().exit_code)}</span>}>
            <span class="chip-sm bad">timed out</span>
          </Show>
        </div>
      </Show>
    </>
  )
}

function ReadBody(props: { block: ToolBlock }) {
  const v = () => (props.block.value as any) ?? {}
  const lines = () => String(v().content ?? props.block.output ?? '').split('\n')
  const start = () => Number(v().offset ?? 1)
  return (
    <>
      <div class="code-read">
        <For each={lines()}>
          {(ln, i) => (
            <div class="cl">
              <span class="ln">{start() + i()}</span>
              <span class="lt">{ln || ' '}</span>
            </div>
          )}
        </For>
      </div>
      <Show when={v().truncated}><div class="tc-foot"><span class="chip-sm">truncated</span></div></Show>
    </>
  )
}

function EditBody(props: { block: ToolBlock }) {
  const a = () => parseArgs(props.block.args)
  const isReplace = () => props.block.name === 'str_replace'
  return (
    <>
      <div class="tc-note">{props.block.output}</div>
      <Show when={isReplace() && (a().old_str || a().new_str)}>
        <div class="diff">
          <Show when={a().old_str}><pre class="dl del">- {String(a().old_str)}</pre></Show>
          <Show when={a().new_str}><pre class="dl add">+ {String(a().new_str)}</pre></Show>
        </div>
      </Show>
      <Show when={props.block.name === 'write_file' && typeof a().content === 'string'}>
        <pre class="term small">{String(a().content).split('\n').slice(0, 12).join('\n')}</pre>
      </Show>
    </>
  )
}

function SearchBody(props: { block: ToolBlock }) {
  const v = () => (props.block.value as any) ?? {}
  return (
    <Switch fallback={<pre class="term">{props.block.output || '(no matches)'}</pre>}>
      <Match when={props.block.name === 'grep' && Array.isArray(v().files)}>
        <div class="search-out">
          <For each={v().files as any[]}>
            {(f) => (
              <div class="sf">
                <div class="sf-path">{String(f.path)}</div>
                <For each={(f.matches as any[]) ?? []}>
                  {(m) => (<div class="sm"><span class="ln">{String(m.line)}</span><span class="lt">{String(m.text)}</span></div>)}
                </For>
              </div>
            )}
          </For>
          <Show when={v().truncated}><div class="tc-foot"><span class="chip-sm">results capped</span></div></Show>
        </div>
      </Match>
      <Match when={props.block.name === 'glob' && Array.isArray(v().paths)}>
        <div class="search-out">
          <For each={v().paths as string[]}>{(p) => <div class="gp">{p}</div>}</For>
          <Show when={(v().paths as string[]).length === 0}><div class="tc-note">(no matches)</div></Show>
        </div>
      </Match>
    </Switch>
  )
}

function httpStatusClass(status: number): string {
  if (status >= 200 && status < 300) return 'ok'
  if (status >= 300 && status < 400) return 'redir'
  if (status >= 400 && status < 500) return 'warn'
  return 'bad'
}
function HttpBody(props: { block: ToolBlock }) {
  const v = () => (props.block.value as any) ?? {}
  const a = () => parseArgs(props.block.args)
  const headers = () => Object.entries((v().headers as Record<string, string>) ?? {})
  return (
    <>
      <div class="http-line">
        <span class={`chip-sm ${httpStatusClass(Number(v().status))}`}>{String(v().status ?? '—')}</span>
        <span class="http-url">{String(a().method || 'GET').toUpperCase()} {String(a().url ?? '')}</span>
      </div>
      <Show when={headers().length}>
        <div class="http-headers">
          <For each={headers()}>
            {([k, val]) => (<div class="hh"><span class="hk">{k}</span><span class="hv">{String(val)}</span></div>)}
          </For>
        </div>
      </Show>
      <Show when={v().body}>
        <pre class="term small">{String(v().body)}</pre>
      </Show>
      <Show when={v().body_truncated}><div class="tc-foot"><span class="chip-sm">body truncated</span></div></Show>
    </>
  )
}

function NmapBody(props: { block: ToolBlock }) {
  const v = () => (props.block.value as any) ?? {}
  const hosts = () => (Array.isArray(v().hosts) ? (v().hosts as any[]) : [])
  return (
    <Show when={hosts().length} fallback={<pre class="term">{props.block.output || (v().timed_out ? 'scan timed out' : 'no hosts up')}</pre>}>
      <div class="nmap">
        <For each={hosts()}>
          {(h) => (
            <div class="nmap-host">
              <div class="nh-head">
                <span class="nh-addr">{String(h.address)}</span>
                <Show when={h.hostname}><span class="nh-name">{String(h.hostname)}</span></Show>
                <span class={`chip-sm ${h.status === 'up' ? 'ok' : ''}`}>{String(h.status)}</span>
              </div>
              <div class="ports">
                <For each={(h.ports as any[]) ?? []}>
                  {(p) => {
                    const svc = [p.service, p.product, p.version].filter((x: unknown) => x).join(' ')
                    return (
                      <div class={`port ${p.state === 'open' ? 'open' : ''}`}>
                        <span class="pp">{String(p.port)}/{String(p.protocol)}</span>
                        <span class={`pstate ${p.state}`}>{String(p.state)}</span>
                        <span class="psvc">{svc || '—'}</span>
                      </div>
                    )
                  }}
                </For>
              </div>
            </div>
          )}
        </For>
      </div>
    </Show>
  )
}

function FindingBody(props: { block: ToolBlock }) {
  const f = () => ((props.block.value as any)?.finding as any) ?? {}
  const sev = () => String(f().severity ?? 'info').toLowerCase()
  return (
    <div class="finding">
      <div class="fd-head">
        <span class={`sev ${sev()}`}>{sev()}</span>
        <span class="fd-title">{String(f().title ?? props.block.output)}</span>
        <Show when={f().mitre}><span class="mitre">{String(f().mitre)}</span></Show>
      </div>
      <Show when={f().target}><div class="fd-target">{String(f().target)}</div></Show>
      <Show when={f().description}><div class="fd-desc">{String(f().description)}</div></Show>
      <Show when={f().evidence}><pre class="term small">{String(f().evidence)}</pre></Show>
    </div>
  )
}

function GenericBody(props: { block: ToolBlock }) {
  return (
    <Show when={props.block.output} fallback={<pre class="term small">{props.block.args}</pre>}>
      <pre class="term">{props.block.output}</pre>
    </Show>
  )
}

function ToolBody(props: { block: ToolBlock }) {
  return (
    <Show when={props.block.state !== 'running'} fallback={<div class="tc-running"><span class="rdot" />working…</div>}>
      <Switch fallback={<GenericBody block={props.block} />}>
        <Match when={props.block.state === 'error'}><pre class="term err">{props.block.output || 'error'}</pre></Match>
        <Match when={props.block.name === 'shell'}><ShellBody block={props.block} /></Match>
        <Match when={props.block.name === 'nmap'}><NmapBody block={props.block} /></Match>
        <Match when={props.block.name === 'http'}><HttpBody block={props.block} /></Match>
        <Match when={props.block.name === 'read_file'}><ReadBody block={props.block} /></Match>
        <Match when={props.block.name === 'write_file' || props.block.name === 'str_replace'}><EditBody block={props.block} /></Match>
        <Match when={props.block.name === 'glob' || props.block.name === 'grep'}><SearchBody block={props.block} /></Match>
        <Match when={props.block.name === 'add_finding'}><FindingBody block={props.block} /></Match>
      </Switch>
    </Show>
  )
}

/** The nested sub-agent timeline shown inside a `delegate` card: a specialist's
 * live steps, tool cards, and narration, streamed as the delegation runs. */
function SpecialistTimeline(props: { run: SpecialistRun }) {
  const status = () =>
    props.run.state === 'running' ? 'running' : props.run.stop || props.run.state
  // The streamed tokens already carry the specialist's narration; show the
  // end-summary only when nothing streamed (some models emit no text deltas).
  const streamedText = () => props.run.blocks.some((b) => b.kind === 'text' && (b as any).text?.trim())
  return (
    <div class={`subagent ${props.run.state}`}>
      <div class="sa-head">
        <span class="sa-ico"><IconAgents /></span>
        <span class="sa-name">{props.run.name}</span>
        <Show when={props.run.task}><span class="sa-task">{props.run.task}</span></Show>
        <span class={`state ${props.run.state}`}><span class="sd" />{status()}</span>
      </div>
      <div class="sa-body">
        <For each={props.run.blocks}>{(b) => <BlockView block={b} />}</For>
        <Show when={props.run.state === 'running'}><span class="cursor" /></Show>
        <Show when={props.run.state !== 'running' && !streamedText() && props.run.summary?.trim()}>
          <div class="sa-summary"><Markdown text={props.run.summary!} /></div>
        </Show>
      </div>
      <Show when={props.run.state !== 'running'}>
        <div class="sa-foot">
          {props.run.steps ?? 0} step(s)
          <Show when={props.run.findingsAdded}>{`, ${props.run.findingsAdded} finding(s) recorded`}</Show>
        </div>
      </Show>
    </div>
  )
}

function ToolCardView(props: { block: ToolBlock }) {
  // Start collapsed so the transcript stays a tidy log — the header still shows the
  // tool, its arg summary, and status at a glance; expand for the full body. In
  // orchestrate mode the live view is the Agents panel, so nothing is hidden.
  const [open, setOpen] = createSignal(false)
  const meta = () => toolMeta(props.block.name)
  const label = () => (props.block.state === 'running' ? 'running' : props.block.state === 'ok' ? 'done' : 'error')
  return (
    <div class={`toolcard ${props.block.state}`} id={props.block.specialist ? `agent-${props.block.specialist.uid}` : undefined}>
      <button class="tc-head" onClick={() => setOpen(!open())}>
        <span class="tc-ico">{meta().icon()}</span>
        <span class="tc-name">{meta().label}</span>
        <Show when={argSummary(props.block)}><span class="tc-summary">{argSummary(props.block)}</span></Show>
        <span class={`state ${props.block.state}`}><span class="sd" />{label()}</span>
        <span class="tc-caret">{open() ? '▾' : '▸'}</span>
      </button>
      <Show when={open()}>
        <div class="tc-body">
          {/* A delegation renders its specialist's nested timeline in place of the
              opaque summary; every other tool renders its normal body. */}
          <Show when={props.block.specialist} fallback={<ToolBody block={props.block} />}>
            <SpecialistTimeline run={props.block.specialist!} />
          </Show>
        </div>
      </Show>
    </div>
  )
}

// ── conversation ──────────────────────────────────────────────────────────────
function BlockView(props: { block: Block }) {
  return (
    <Switch>
      <Match when={props.block.kind === 'text'}><Markdown text={(props.block as any).text} /></Match>
      <Match when={props.block.kind === 'tool'}><ToolCardView block={props.block as ToolBlock} /></Match>
      <Match when={props.block.kind === 'notice'}>
        <div class="notice"><span class="ni"><IconSwitch /></span>{(props.block as any).text}</div>
      </Match>
    </Switch>
  )
}

function Conversation() {
  let el: HTMLDivElement | undefined
  const scrollDown = () => el && (el.scrollTop = el.scrollHeight)
  return (
    <div class="conversation" ref={el}>
      <div class="conv-inner">
        <For each={conversation.list}>
          {(msg) => {
            queueMicrotask(scrollDown)
            return (
              <div class={`msg ${msg.role}`}>
                <Switch>
                  <Match when={msg.role === 'user'}>
                    <div class="bubble">{(msg.blocks[0] as any)?.text}</div>
                  </Match>
                  <Match when={msg.role === 'assistant'}>
                    <div class="role">assistant</div>
                    <div>
                      <For each={msg.blocks}>{(b) => <BlockView block={b} />}</For>
                      <Show when={running() && msg === conversation.list[conversation.list.length - 1]}><span class="cursor" /></Show>
                    </div>
                  </Match>
                  <Match when={msg.role === 'system'}>
                    <div class="sys"><For each={msg.blocks}>{(b) => <BlockView block={b} />}</For></div>
                  </Match>
                </Switch>
              </div>
            )
          }}
        </For>
      </div>
    </div>
  )
}

// ── agents panel (live, orchestrate mode) ─────────────────────────────────────
function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  return `${m}:${String(s % 60).padStart(2, '0')}`
}
function fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return String(n)
}

/** The live Agents panel (right column): one row per delegated specialist, with
 * status, live duration, steps, findings, and tokens — the multi-agent cockpit. */
function AgentsPanel() {
  // Tick once a second while any agent is running, so live durations advance.
  const [nowMs, setNowMs] = createSignal(Date.now())
  createEffect(() => {
    if (!agentRuns().some((a) => a.state === 'running')) return
    setNowMs(Date.now())
    const id = setInterval(() => setNowMs(Date.now()), 1000)
    onCleanup(() => clearInterval(id))
  })
  const dur = (a: SpecialistRun) => (a.startedAt == null ? 0 : (a.endedAt ?? nowMs()) - a.startedAt)
  const done = () => agentRuns().filter((a) => a.state !== 'running').length
  const total = () => agentRuns().reduce((sum, a) => sum + dur(a), 0)
  const jumpTo = (uid: number) =>
    document.getElementById(`agent-${uid}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  return (
    <aside class="agents">
      <div class="ag-head">
        <span class="ag-ico"><IconAgents /></span>
        <span class="ag-title">Agents</span>
        <Show when={agentRuns().length}><span class="ag-count">{done()}/{agentRuns().length}</span></Show>
        <button class="ag-x" title="Hide agents panel" onClick={() => setAgentsPanelOpen(false)}>›</button>
      </div>
      <Show
        when={agentRuns().length}
        fallback={
          <div class="ag-empty">
            No agents yet. In <b>orchestrate</b> mode the orchestrator delegates each kill-chain phase
            to a specialist — they appear here live, with timing and cost.
          </div>
        }
      >
        <div class="ag-sub">{fmtDuration(total())} total</div>
        <div class="ag-list">
          <For each={agentRuns()}>
            {(a) => (
              <button class={`ag-row ${a.state}`} onClick={() => jumpTo(a.uid)}>
                <span class="ag-row-top">
                  <span class={`ag-dot ${a.state}`} />
                  <span class="ag-name">{a.name}</span>
                  <span class="ag-time">{fmtDuration(dur(a))}</span>
                </span>
                <Show when={a.task}><span class="ag-task">{a.task}</span></Show>
                <span class="ag-meta">
                  <span class={`ag-state ${a.state}`}>{a.state === 'running' ? 'running' : a.stop || a.state}</span>
                  <Show when={a.steps != null}><span>{a.steps} step{a.steps === 1 ? '' : 's'}</span></Show>
                  <Show when={a.findingsAdded}><span>{a.findingsAdded} finding{a.findingsAdded === 1 ? '' : 's'}</span></Show>
                  <Show when={a.tokens}><span>{fmtTokens(a.tokens!)} tok</span></Show>
                </span>
              </button>
            )}
          </For>
        </div>
      </Show>
    </aside>
  )
}

export default function App() {
  onMount(() => {
    loadModels()
    void syncMcpToBackend()
  })
  const empty = () => conversation.list.length === 0
  return (
    <div class={`app${agentsPanelOpen() ? ' agents-open' : ''}`}>
      <Sidebar />
      <div class="main">
        <Show
          when={empty()}
          fallback={
            <>
              <Conversation />
              <div class="composer docked"><Composer /></div>
            </>
          }
        >
          <div class="hero-wrap">
            <div class="glow" />
            <div class="hero">
              <span class="logo"><Logo size={52} /></span>
              <span class="title">Into the Breach</span>
              <span class="preview">Preview</span>
            </div>
            <div class="composer"><Composer /></div>
          </div>
        </Show>
      </div>
      <Show when={agentsPanelOpen()}><AgentsPanel /></Show>
      <Show when={settingsOpen()}><Settings /></Show>
      <Show when={workspacePanelOpen()}><WorkspacePanel /></Show>
      <Show when={findingsOpen()}><FindingsPanel /></Show>
    </div>
  )
}
