import { createSignal, For, onMount, Show, type JSX } from 'solid-js'

import './App.css'
import { deleteApiKey, hasApiKey, saveApiKey, type ModelInfo } from './api'
import {
  cancel,
  conversation,
  settingsOpen,
  setSettingsOpen,
  freeOnly,
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
  setFreeOnly,
  setSearch,
  setSelectedModel,
  setToolsOnly,
  toolsOnly,
  visibleModels,
  type Block,
} from './store'

function fmtCtx(n: number): string {
  if (n >= 1_000_000) {
    const m = n / 1_000_000
    return Math.abs(m - Math.round(m)) < 0.05 ? `${Math.round(m)}M` : `${m.toFixed(1)}M`
  }
  if (n >= 1000) return `${Math.round(n / 1000)}K`
  return String(n)
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
const IconSliders = () => svg(<><line x1="4" y1="8" x2="20" y2="8" /><line x1="4" y1="16" x2="20" y2="16" /><circle cx="9" cy="8" r="2" /><circle cx="15" cy="16" r="2" /></>, 16)
const IconAdd = () => svg(<><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></>, 16)
const IconGear = () => svg(<><circle cx="12" cy="12" r="3" /><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.3 1a7 7 0 0 0-1.7-1l-.4-2.6H9.5l-.4 2.6a7 7 0 0 0-1.7 1l-2.3-1-2 3.4L5 11a7 7 0 0 0 0 2l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 1.7 1l.4 2.6h4.9l.4-2.6a7 7 0 0 0 1.7-1l2.3 1 2-3.4-2-1.5c.1-.3.1-.7.1-1z" /></>, 16)
const IconCollapse = () => svg(<><rect x="3" y="4" width="18" height="16" rx="2" /><line x1="9" y1="4" x2="9" y2="20" /></>, 17)
const IconSend = () => svg(<><line x1="12" y1="19" x2="12" y2="5" /><polyline points="6 11 12 5 18 11" /></>, 17, 2.2)
const IconMode = () => svg(<><path d="M4 12a8 8 0 0 1 14-5" /><polyline points="18 3 18 7 14 7" /><path d="M20 12a8 8 0 0 1-14 5" /><polyline points="6 21 6 17 10 17" /></>, 15)

// ── sidebar ──────────────────────────────────────────────────────────────────
function Sidebar() {
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
        <span class="label">Workspaces</span>
        <span class="actions">
          <button title="Search"><IconSearch /></button>
          <button title="Filter"><IconSliders /></button>
          <button title="Add workspace"><IconAdd /></button>
        </span>
      </div>
      <div class="ws-list">
        <div class="ws-item">
          <span class="fico"><IconFolder /></span>
          fullbreachtoolkit
        </div>
        <div class="ws-session active">New Session</div>
      </div>
      <button class="settings" onClick={() => setSettingsOpen(true)}><IconGear /> Settings</button>
    </aside>
  )
}

function Settings() {
  const [key, setKey] = createSignal('')
  const [stored, setStored] = createSignal(false)
  const [busy, setBusy] = createSignal(false)
  hasApiKey().then(setStored)
  const save = async () => {
    if (!key().trim()) return
    setBusy(true)
    try {
      await saveApiKey(key().trim())
      setKey('')
      setStored(await hasApiKey())
    } finally {
      setBusy(false)
    }
  }
  const clear = async () => {
    setBusy(true)
    try {
      await deleteApiKey()
      setStored(await hasApiKey())
    } finally {
      setBusy(false)
    }
  }
  return (
    <div class="modal-backdrop" onClick={() => setSettingsOpen(false)}>
      <div class="modal" onClick={(e) => e.stopPropagation()}>
        <div class="m-head">
          Settings
          <button class="x" onClick={() => setSettingsOpen(false)}>✕</button>
        </div>
        <div class="m-body">
          <div class="field-label">OpenRouter API key</div>
          <div class="field-help">
            Stored in your OS keyring, never in a file. Get a free key at{' '}
            <a href="https://openrouter.ai/keys" target="_blank" rel="noreferrer">openrouter.ai/keys</a>.
          </div>
          <div class="field-row">
            <input
              type="password"
              placeholder="sk-or-v1-…"
              value={key()}
              onInput={(e) => setKey(e.currentTarget.value)}
              onKeyDown={(e) => e.key === 'Enter' && save()}
            />
            <button class="btn primary" disabled={busy() || !key().trim()} onClick={save}>Save</button>
            <Show when={stored()}>
              <button class="btn danger" disabled={busy()} onClick={clear}>Clear</button>
            </Show>
          </div>
          <div class={`key-status ${stored() ? 'set' : ''}`}>
            <span class="kd" />
            {stored() ? 'A key is stored in the keyring.' : 'No key set — the agent cannot run until you add one.'}
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
          <label class="toggle"><input type="checkbox" checked={freeOnly()} onChange={(e) => setFreeOnly(e.currentTarget.checked)} />free</label>
          <label class="toggle"><input type="checkbox" checked={toolsOnly()} onChange={(e) => setToolsOnly(e.currentTarget.checked)} />tools</label>
          <button class="refresh" onClick={() => loadModels()}>{loadingModels() ? '…' : '↻'}</button>
        </div>
        <div class="model-count">
          <Show
            when={modelsError()}
            fallback={
              <>
                Showing {visibleModels().length} of {models().length} models
                <Show when={freeOnly() || toolsOnly()}>
                  <span style={{ color: 'var(--text-faint)' }}>
                    {' · uncheck '}
                    {freeOnly() && toolsOnly() ? 'free / tools' : freeOnly() ? 'free' : 'tools'}
                    {' for more'}
                    {freeOnly() ? ' (paid models need credit)' : ''}
                  </span>
                </Show>
              </>
            }
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

// ── composer (used centered in the hero and docked in a chat) ─────────────────
function Composer() {
  const [text, setText] = createSignal('')
  const [panel, setPanel] = createSignal(false)
  const current = () => modelById(selectedModel())
  const submit = () => {
    if (running()) return cancel()
    const t = text()
    setText('')
    void send(t)
  }
  return (
    <div class="composer-card">
      <div class="chips-top">
        <button class="chip"><span class="ico"><IconFolder /></span>workspace<span class="caret">▾</span></button>
        <button class="chip"><span class="ico"><IconMode /></span>Standard mode<span class="caret">▾</span></button>
      </div>
      <textarea
        rows={1}
        placeholder="Describe the engagement — e.g. recon 127.0.0.1 and report findings"
        value={text()}
        onInput={(e) => {
          setText(e.currentTarget.value)
          e.currentTarget.style.height = 'auto'
          e.currentTarget.style.height = `${Math.min(e.currentTarget.scrollHeight, 220)}px`
        }}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault()
            submit()
          }
        }}
      />
      <div class="composer-bottom">
        <button class="plus-btn" title="Attach"><IconAdd /></button>
        <button class="chip">Full access<span class="caret">▾</span></button>
        <span class="spacer" />
        <div class="model-anchor">
          <button class="model-chip" onClick={() => setPanel(!panel())}>
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
          <Show when={panel()}><ModelPanel onClose={() => setPanel(false)} /></Show>
        </div>
        <button
          class={`send ${running() ? 'stop' : ''}`}
          disabled={!running() && (!text().trim() || !selectedModel())}
          onClick={submit}
          title={running() ? 'Stop' : 'Run'}
        >
          <Show when={!running()} fallback={<span style={{ 'font-size': '13px' }}>■</span>}><IconSend /></Show>
        </button>
      </div>
    </div>
  )
}

// ── conversation ──────────────────────────────────────────────────────────────
function ToolCardView(props: { block: Extract<Block, { kind: 'tool' }> }) {
  const label = () => (props.block.state === 'running' ? 'running' : props.block.state === 'ok' ? 'done' : 'error')
  return (
    <div class="toolcard">
      <div class="head">
        <span class="tname">{props.block.name}</span>
        <span class={`state ${props.block.state}`}><span class="sd" />{label()}</span>
      </div>
      <div class="args">{props.block.args}</div>
    </div>
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
                <Show when={msg.role === 'user'} fallback={<div class="role">assistant</div>}>
                  <div class="bubble">{(msg.blocks[0] as any)?.text}</div>
                </Show>
                <Show when={msg.role === 'assistant'}>
                  <div>
                    <For each={msg.blocks}>
                      {(b) => (b.kind === 'text' ? <div class="text">{b.text}</div> : <ToolCardView block={b} />)}
                    </For>
                    <Show when={running() && msg === conversation.list[conversation.list.length - 1]}><span class="cursor" /></Show>
                  </div>
                </Show>
              </div>
            )
          }}
        </For>
      </div>
    </div>
  )
}

export default function App() {
  onMount(loadModels)
  const empty = () => conversation.list.length === 0
  return (
    <div class="app">
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
      <Show when={settingsOpen()}><Settings /></Show>
    </div>
  )
}
