import { createSignal, For, onMount, Show } from 'solid-js'

import './App.css'
import type { ModelInfo } from './api'
import {
  cancel,
  conversation,
  freeOnly,
  loadingModels,
  loadModels,
  modelById,
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

function Sidebar() {
  return (
    <aside class="sidebar">
      <div class="brand">
        <span class="brand-dot" />
        <span>decibel</span>
        <small>red-team</small>
      </div>
      <button class="new-btn" onClick={newSession}>
        + New engagement
      </button>
      <div class="session-list">
        <div class="session-item active">Current session</div>
        <div class="session-item">recon 127.0.0.1</div>
        <div class="session-item">web app assessment</div>
      </div>
      <div class="sidebar-foot">OpenRouter · free models · local</div>
    </aside>
  )
}

function ModelBadges(props: { m: ModelInfo }) {
  return (
    <>
      <span class="badge ctx">{fmtCtx(props.m.context_length)}</span>
      <Show when={props.m.is_free}>
        <span class="badge free">free</span>
      </Show>
      <span class={`badge ${props.m.supports_tools ? 'tools' : 'notools'}`}>
        {props.m.supports_tools ? 'tools' : 'no tools'}
      </span>
    </>
  )
}

function ModelSelector() {
  const [open, setOpen] = createSignal(false)
  const current = () => modelById(selectedModel())
  return (
    <div style={{ position: 'relative' }}>
      <button class="model-btn" onClick={() => setOpen(!open())}>
        <span class="id">{selectedModel() || 'select a model'}</span>
        <Show when={current()}>{(m) => <ModelBadges m={m()} />}</Show>
        <span class="caret">▾</span>
      </button>
      <Show when={open()}>
        <div class="backdrop" onClick={() => setOpen(false)} />
        <div class="model-panel">
          <div class="filters">
            <input
              class="search"
              placeholder="search models…"
              value={search()}
              onInput={(e) => setSearch(e.currentTarget.value)}
            />
            <label class="toggle">
              <input type="checkbox" checked={freeOnly()} onChange={(e) => setFreeOnly(e.currentTarget.checked)} />
              free
            </label>
            <label class="toggle">
              <input type="checkbox" checked={toolsOnly()} onChange={(e) => setToolsOnly(e.currentTarget.checked)} />
              tools
            </label>
            <button class="refresh" onClick={() => loadModels()}>
              {loadingModels() ? '…' : '↻'}
            </button>
          </div>
          <div class="model-count">
            <Show when={modelsError()} fallback={`${visibleModels().length} model(s)`}>
              {(err) => <span style={{ color: 'var(--danger)' }}>catalog error: {err()}</span>}
            </Show>
          </div>
          <div class="model-rows">
            <For each={visibleModels()}>
              {(m) => (
                <div
                  class={`model-row ${m.id === selectedModel() ? 'selected' : ''}`}
                  onClick={() => {
                    setSelectedModel(m.id)
                    setOpen(false)
                  }}
                >
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
      </Show>
    </div>
  )
}

function ToolCardView(props: { block: Extract<Block, { kind: 'tool' }> }) {
  const label = () =>
    props.block.state === 'running' ? 'running' : props.block.state === 'ok' ? 'done' : 'error'
  return (
    <div class="toolcard">
      <div class="head">
        <span class="tname">{props.block.name}</span>
        <span class={`state ${props.block.state}`}>
          <span class="sd" />
          {label()}
        </span>
      </div>
      <div class="args">{props.block.args}</div>
    </div>
  )
}

function Conversation() {
  let el: HTMLDivElement | undefined
  // Keep the view pinned to the newest content while a turn streams.
  const scrollDown = () => el && (el.scrollTop = el.scrollHeight)
  return (
    <div class="conversation" ref={el}>
      <div class="conv-inner">
        <Show
          when={conversation.list.length > 0}
          fallback={
            <div class="empty">
              <h2>Decibel red-team agent</h2>
              <div>Pick a target and describe the engagement below.</div>
            </div>
          }
        >
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
                        {(b) =>
                          b.kind === 'text' ? (
                            <div class="text">{b.text}</div>
                          ) : (
                            <ToolCardView block={b} />
                          )
                        }
                      </For>
                      <Show when={running() && msg === conversation.list[conversation.list.length - 1]}>
                        <span class="cursor" />
                      </Show>
                    </div>
                  </Show>
                </div>
              )
            }}
          </For>
        </Show>
      </div>
    </div>
  )
}

function Composer() {
  const [text, setText] = createSignal('')
  const submit = () => {
    if (running()) {
      cancel()
      return
    }
    const t = text()
    setText('')
    void send(t)
  }
  return (
    <div class="composer">
      <div class="composer-inner">
        <textarea
          rows={1}
          placeholder="Describe the engagement — e.g. recon 127.0.0.1 and report findings"
          value={text()}
          onInput={(e) => {
            setText(e.currentTarget.value)
            e.currentTarget.style.height = 'auto'
            e.currentTarget.style.height = `${Math.min(e.currentTarget.scrollHeight, 180)}px`
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              submit()
            }
          }}
        />
        <button
          class={`send-btn ${running() ? 'stop' : ''}`}
          disabled={!running() && (!text().trim() || !selectedModel())}
          onClick={submit}
        >
          {running() ? 'Stop' : 'Run'}
        </button>
      </div>
      <div class="hint">
        Authorized targets only · Enter to run, Shift+Enter for newline
      </div>
    </div>
  )
}

export default function App() {
  onMount(loadModels)
  return (
    <div class="app">
      <Sidebar />
      <div class="main">
        <div class="topbar">
          <ModelSelector />
          <div class="spacer" />
          <div class={`status-pill ${running() ? 'live' : ''}`}>
            <span class="dot" />
            {running() ? 'running' : 'idle'}
          </div>
        </div>
        <Conversation />
        <Composer />
      </div>
    </div>
  )
}
