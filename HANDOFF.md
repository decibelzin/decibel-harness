# Decibel Harness — Handoff

A living handoff so a fresh Claude Code session (after `/clear`) can pick up
without losing context. Pair it with the memory file at
`C:\Users\vi\.claude\projects\C--Users-vi-Desktop-ds-harness\memory\decibel-harness.md`.

---

## What this is

**Decibel** — a lightweight **desktop autonomous red-team / pentest agent**, built
from scratch, inspired by the architecture of **DeepSeek Harness** (`dsh`, at
`C:\Users\vi\Desktop\ds-harness\deepseek-harness`, MIT — OK to port ideas) plus
**Decepticon**'s multi-agent kill-chain (Apache-2.0). **No guardrails by design**
(full shell/fs/network authority; the only withholding is scrubbing secret env
vars from spawned processes). LLM = **OpenRouter, free models** with a live
model catalog. Repo: `C:\Users\vi\Desktop\decibel-harness` (git remote
`decibelzin/decibel-harness`, branch `main`). User speaks **Portuguese**.

**Status: the native desktop app WORKS end-to-end.** Confirmed live: API key
saved to the Windows keyring, real agent streaming a full response in the native
window (minimax/minimax-m3:free). ~25 commits, ~61 Rust tests green, audited
twice by adversarial multi-agent review (bugs found + fixed).

---

## How to run it

Native desktop app (the real thing):
```
cd C:\Users\vi\Desktop\decibel-harness\apps\desktop\ui
npm install        # first time
npm run app        # tauri dev — opens the native window
```
Then **Settings → paste OpenRouter key → Save** (stored in Windows Credential
Manager). Pick a model in the composer's model chip. Free key at
https://openrouter.ai/keys.

Browser-only UI preview (no backend, agent is mocked, catalog is real):
```
npm run dev        # http://localhost:5178
```
Rust core tests: `cd C:\Users\vi\Desktop\decibel-harness && cargo test --workspace`

CLI demos (no UI): `cargo run -p decibel-offsec --example redteam "recon 127.0.0.1"`
and `cargo run -p decibel-orchestrator --example redteam_team "engage 127.0.0.1"`.

---

## Gotchas (read before building)

- **Rebuilding the backend while the app is open fails** (`os error 5`,
  `decibel-desktop.exe` locked). Close the Decibel window, then `npm run app`
  again. In dev mode the frontend hot-reloads (vite HMR) but Rust changes need a
  relaunch.
- **OpenRouter free quota is PER ACCOUNT, not per key** — a new key on the same
  account hits the same `free-models-per-day`. Fix: wait for ~00:00 UTC reset or
  add ~$10 credit (→1000/day; `:free` models still cost $0/request).
- **Some free models are gated** (`thinkingmachines/*` → AUTH "only available on
  agentic harnesses"). The default pick now skips them; auto-fallback across
  models on gated/rate-limit is NOT yet built (planned).
- **Tauri layout:** `src-tauri` lives at `apps/desktop/src-tauri` (sibling of
  `ui`). The npm `app` script does `cd .. && node ui/node_modules/.../tauri.js
  dev` so tauri finds the config. `src-tauri` is its OWN cargo workspace (keeps
  the heavy Tauri tree out of `cargo test --workspace`).
- **keyring** needs a backend feature or it silently has no store — we enabled
  `windows-native`. Add mac/linux features when targeting those.

---

## Architecture (Rust crates + app)

```
crates/
  decibel-llm       leaf vocabulary: Message, ContentBlock, StreamChunk, ToolSchema,
                    LlmAdapter trait, BlockAssembler
  decibel-core      event-sourced Session log + surface projection + JSONL persist
  decibel-openrouter  streaming SSE adapter + live /api/v1/models catalog
  decibel-tools     Tool trait (canonical value + pure render) + registry + pipeline
  decibel-agent     run_turn / run_turn_observed (live Progress), AgentConfig, TurnSignal
  decibel-offsec    9 tools: shell, nmap(structured), http, read/write/edit,
                    glob/grep, add_finding(MITRE); shared proc module (tree-kill +
                    secret-env scrub); register_all / register_named + FindingStore
  decibel-orchestrator  multi-agent: SubagentTool delegates to recon/exploit/report
                    specialists (isolated context, shared FindingStore)
apps/desktop/
  src-tauri/        Tauri v2 shell. Commands: list_models, run_prompt (streams RunEvt
                    over a Channel), has/save/delete_api_key (keyring), cancel_run.
  ui/               SolidJS + Vite. api.ts (invoke + Channel, browser mock fallback),
                    store.ts (conversation, models, run-generation guard), App.tsx
                    (sidebar, hero+composer, model picker, Settings modal, tool cards),
                    App.css + theme.css (dark bluish, DeepSeek-blue accent).
```

Core ideas ported from dsh: **model-visible ⟺ logged** (history derived from an
append-only event log via an ordered surface; compaction shadows nodes); the
**loop is a thin driver over swappable seams**; **canonical value + pure render**
per tool (drives model, UI card, and a future Code Mode from the same fact).

Two adversarial reviews already run (offsec: 5 real bugs fixed; orchestrator +
tauri: 1 real bug — Stop didn't cancel the backend — fixed). Review workflow
scripts are under the session's `workflows/scripts/`.

---

## Done (checklist)

- [x] Event-sourced session core + JSONL (tested)
- [x] OpenRouter streaming adapter + live catalog (context/free/tools)
- [x] Tool registry + pipeline (value/render)
- [x] Agent loop turn/step with live Progress; cooperative cancel
- [x] Offensive toolkit (9 tools) incl. structured nmap; secret-env scrub; tree-kill
- [x] Multi-agent orchestrator (recon/exploit/report) — Rust only, not in UI yet
- [x] Tauri native app: commands, keyring, streaming, cancel_run, app icon (logo)
- [x] UI: sidebar, hero+composer, live model picker (centered popover), tool cards,
      Settings modal (API key), streaming, Stop
- [x] Confirmed working live in the native window

---

## Backlog — what's left (the user wants ALL of this)

The app has the core loop but is well short of dsh's feature surface. The user
explicitly wants the full set, and flagged that **the current Settings is bad —
rebuild it into a REAL settings page** (tabbed: General, Models/Providers,
Appearance/Theme, Plugins, About) like dsh, not a bare key modal.

**A. Essential polish (high visual impact, do early)**
- **Markdown + syntax highlight** in assistant messages (today `**bold**` shows
  raw; code blocks unformatted). Pick a small markdown renderer + a highlighter.
- **Auto model-fallback** on gated/AUTH/rate-limit/timeout — cycle to the next
  free tool-capable model like the CLI demos do, so the user never sees those
  errors. (Frontend retry loop, or a backend command that takes a candidate list.)
- **Better tool cards** — terminal / diff / read (line-numbered) / search views
  like dsh, instead of the generic args card. The Rust tools already return
  render intents; port the card shapes.

**B. Real Settings page** (user called the current one "uma bosta")
- Left-nav or tabs: **General**, **Models/Providers** (key + default model +
  browse/filter catalog + maybe per-provider), **Appearance** (theme light/dark),
  **About/Version**. Move the API-key field there. Keyring commands exist.

**C. Session persistence**
- Save / list / reopen / delete sessions in the sidebar (today in-memory only).
  Core JSONL exists; add Tauri commands (`list_sessions`, `load_session`,
  autosave on each event) + wire the sidebar. Auto session titles (LLM or first
  prompt).

**D. Red-team differentiators**
- **Findings panel** — show the engagement's MITRE-tagged findings (the shared
  FindingStore) in the UI; export a report. run_prompt should also stream/return
  findings.
- **Multi-agent mode** — expose the orchestrator in the UI (a mode toggle);
  render nested specialist activity.

**E. Agent robustness**
- **Context compaction** — summarize/prune so long pentest sessions don't blow
  the model context (dsh has compaction-basic + tool-result pruner). Not in our
  loop yet — token growth is unbounded.
- **Slash commands** — /new, /clear, /model, /compact, etc.
- **Turn/step budget** UI, token/usage meter (usage is now logged).

**F. Larger parity (later)**
- Workspaces (real, not the decorative chip): pick a working directory per
  session; the shell/fs tools honor it.
- Plan mode + permission presets (the "Standard mode" / "Full access" chips are
  decorative today; we have no sandbox by design, but a plan/act mode is useful).
- Goals (same-session objective), background jobs list.
- Skills catalog, MCP client (external tool servers), Code Mode (run_code + SDK),
  image attachments, message feedback, trajectory views.

---

## Suggested next-session order

1. Markdown/highlight + better tool cards + auto model-fallback (A) — quick, very
   visible, removes the friction the user just hit.
2. Real Settings page (B) — user explicitly unhappy with the current one.
3. Session persistence (C) — makes it a real tool.
4. Findings panel + multi-agent UI (D) — the red-team differentiator.
5. Compaction + slash commands (E), then parity (F).

Live agent needs OpenRouter quota. Rebuild = close app + `npm run app`. Keep
committing per feature; run an adversarial review workflow after risky changes
(it has found real bugs twice).
