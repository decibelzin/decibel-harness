# Decibel Harness — Handoff

A living handoff so a fresh Claude Code session (after `/clear`) can pick up
without losing context. Pair it with the memory file at
`C:\Users\vi\.claude\projects\C--Users-vi-Desktop-ds-harness\memory\decibel-harness.md`.

---

## What this is

**Decibel** — a lightweight **desktop autonomous red-team / pentest agent**, built
from scratch, inspired by **DeepSeek Harness** (`dsh`, at
`C:\Users\vi\Desktop\ds-harness\deepseek-harness`, MIT — OK to port ideas) plus
**Decepticon**'s multi-agent kill-chain (Apache-2.0). **No guardrails by design**
(full shell/fs/network authority; the only withholding is scrubbing secret env
vars from spawned processes). LLM = the **paid DeepSeek API** (OpenAI-compatible)
— models `deepseek-v4-flash` (default, cheapest), `deepseek-v4-pro`, and
`deepseek-v4-flash-vision-exp` (all 1M context, all support tool calls). Repo:
`C:\Users\vi\Desktop\decibel-harness` (git remote `decibelzin/decibel-harness`,
branch `main`). User speaks **Portuguese**.

> **Provider note (2026-08-26):** pivoted from OpenRouter free models to the paid
> DeepSeek API only ("por enquanto"). The free-model auto-fallback and the
> free/tools catalog filters were removed. The adapter crate is still **named**
> `decibel-openrouter` (an internal label) but now targets DeepSeek — could be
> renamed to `decibel-deepseek` later.

**Status: the native desktop app WORKS end-to-end.** Confirmed live earlier (on
the previous OpenRouter setup): key in the Windows keyring, real agent streaming
in the native window. The UI has markdown, rich tool cards, and a real tabbed
settings page. Now wired to the **paid DeepSeek API** — the first live DeepSeek
run needs the user's key + credit (not yet exercised end-to-end on DeepSeek here).

---

## How to run it

Native desktop app (the real thing):
```
cd C:\Users\vi\Desktop\decibel-harness\apps\desktop\ui
npm install        # first time
npm run app        # tauri dev — opens the native window
```
Then **Settings → Models & Providers → paste DeepSeek key → Save** (stored in
Windows Credential Manager). Pick a model in the composer's model chip. Create a
key + add credit at https://platform.deepseek.com/api_keys (Top Up). Dev override:
`DEEPSEEK_API_KEY` env var (or a gitignored workspace-root `.env`).

Browser-only UI preview (no backend, agent is mocked, catalog is real):
```
npm run dev        # http://localhost:5178  — the mock exercises every tool card
```
Rust core tests: `cd C:\Users\vi\Desktop\decibel-harness && cargo test --workspace`
(61 pass). Tauri crate is its OWN workspace: `cd apps/desktop/src-tauri && cargo check`.
CLI demos: `cargo run -p decibel-offsec --example redteam "recon 127.0.0.1"` and
`cargo run -p decibel-orchestrator --example redteam_team "engage 127.0.0.1"`.

---

## Gotchas (read before building)

- **Rebuilding the backend while the app is open fails** (`os error 5`,
  `decibel-desktop.exe` locked). Close the Decibel window, then `npm run app`.
  Frontend hot-reloads (vite HMR); Rust changes need a relaunch.
- **DeepSeek is billed** — every run spends real credit. A run that fails with
  HTTP 402 / `Insufficient Balance` surfaces an actionable "add credit at
  platform.deepseek.com/top_up" error. DeepSeek has off-peak vs peak pricing
  (off-peak ~50% cheaper) and a cache-hit discount on repeated prompt prefixes.
- **Tauri layout:** `src-tauri` at `apps/desktop/src-tauri` (sibling of `ui`). The
  npm `app` script does `cd .. && node ui/node_modules/.../tauri.js dev`. `src-tauri`
  is its OWN cargo workspace (keeps the heavy Tauri tree out of `cargo test --workspace`).
- **keyring** needs a backend feature (we enabled `windows-native`).

---

## Architecture (Rust crates + app)

```
crates/
  decibel-llm       Message, ContentBlock, StreamChunk, ToolSchema, LlmAdapter, BlockAssembler
  decibel-core      event-sourced Session log + surface projection + JSONL persist
  decibel-openrouter  streaming SSE chat adapter (OpenAI-compatible) → DeepSeek;
                    fixed DeepSeek model catalog (deepseek_models()). [name is legacy]
  decibel-tools     Tool trait (canonical value + pure render) + registry + pipeline
  decibel-agent     run_turn / run_turn_observed (live Progress), AgentConfig, TurnSignal
  decibel-offsec    9 tools: shell, nmap(structured), http, read/write/edit, glob/grep,
                    add_finding(MITRE); shared proc (tree-kill + secret-env scrub); FindingStore
  decibel-orchestrator  multi-agent: SubagentTool delegates to recon/exploit/report specialists
apps/desktop/
  src-tauri/src/main.rs   Tauri v2. Commands: list_models (DeepSeek), run_prompt
                    (single DeepSeek model; streams RunEvt over a Channel),
                    has/save/delete_api_key (keyring account "deepseek"), cancel_run.
  ui/src/           SolidJS + Vite:
    api.ts          invoke + Channel + browser mock; RunEvent union
    store.ts        conversation, models, prefs (theme/autoFallback in localStorage),
                    activeModel (effective model during a fallback), run-generation guard
    markdown.ts     marked + DOMPurify + highlight.js (curated langs), theme-var token colors
    App.tsx         sidebar, hero+composer, model picker, tabbed Settings, tool cards, Markdown
    App.css/theme.css  dark + light + system themes; tool-card + markdown + settings styles
```

`Progress::ToolResult` now carries the tool's rendered `output` **and** canonical
JSON `value`; `RunEvt::ToolResult` streams both so the UI builds rich cards from
the same fact the model saw (canonical value + pure render, per dsh).

---

## Done (checklist)

- [x] Event-sourced session core + JSONL (tested)
- [x] DeepSeek streaming adapter (OpenAI-compatible) + fixed DeepSeek model catalog
- [x] Tool registry + pipeline (value/render); agent loop with live Progress + cancel
- [x] Offensive toolkit (9 tools) incl. structured nmap; secret-env scrub; tree-kill
- [x] Multi-agent orchestrator (recon/exploit/report) — Rust only, not in UI yet
- [x] Tauri native app: commands, keyring, streaming, cancel_run, app icon
- [x] Confirmed working live in the native window (earlier session)
- [x] **Markdown + syntax highlighting** in assistant messages (marked/DOMPurify/highlight.js)
- [x] **Rich tool cards** — terminal (shell), line-numbered read, diff (str_replace),
      search (glob/grep), **nmap ports table**, http (status/headers/body), finding
      (severity + MITRE). Collapsible; keyed by tool name off the streamed value.
- [x] **Real tabbed Settings page** — Models & Providers (DeepSeek key + default
      model), General (provider + authority notes), Appearance (dark/light/system
      theme, persisted), About. Replaces the old bare key modal.
- [x] Adversarial multi-agent review (3rd): 4 real bugs found + fixed (below).
- [x] **Pivot to the paid DeepSeek API** (2026-08-26) — DeepSeek base URL + key +
      fixed 3-model catalog; removed the free-model auto-fallback, `ModelFallback`
      event, `activeModel`, and the free/tools catalog filters; relabeled the UI +
      demos (`DEEPSEEK_API_KEY`, `AgentConfig` provider "deepseek"). Verified: model
      picker shows the 3 DeepSeek models, Settings reads "DeepSeek API key", tool
      cards still render (nmap ports table), 61 tests + both builds green.

**Verified:** 61 core tests green; Tauri crate + binary build/link; UI typechecks
+ builds; browser preview drives the tool cards, markdown, theme switch, and prefs
end-to-end, and shows the DeepSeek model catalog + key label.

### Review findings fixed (during the feature work, before the pivot)
1. `run_turn_observed` now re-checks cancel at the top of the step loop, so Stop
   can't fire another model request (was wasting a request + ~25-30s delay). **Kept.**
2–4. Three fixes to the auto model-fallback path (402 vs daily-cap classification,
   ephemeral effective model, append-not-wipe on switch). **Superseded** — the
   whole fallback path was removed in the DeepSeek pivot.

---

## Backlog — what's left (the user wants ALL of this)

**C. Session persistence** — save / list / reopen / delete sessions in the sidebar
(today in-memory). Core JSONL exists; add Tauri commands (`list_sessions`,
`load_session`, autosave per event) + wire the sidebar. Auto session titles.

**D. Red-team differentiators**
- **Findings panel** — surface the engagement's MITRE-tagged findings (shared
  FindingStore) in the UI + export a report. `run_prompt` should stream/return findings.
- **Multi-agent mode** — expose the orchestrator in the UI (a mode toggle); render
  nested specialist activity.

**E. Agent robustness**
- **Context compaction** — summarize/prune so long pentest sessions don't blow the
  model context (dsh has compaction-basic + tool-result pruner). Token growth is unbounded.
- **Slash commands** — /new, /clear, /model, /compact, etc.
- **Turn/step budget** UI, token/usage meter (usage is logged in core).

**F. Larger parity (later)** — real workspaces (cwd per session honored by the
shell/fs tools; the sidebar chip is decorative today), plan/act mode + permission
presets (the mode chips are decorative), goals, background jobs, skills catalog,
MCP client, Code Mode (run_code + SDK), image attachments, message feedback.

**Minor known limitations**
- Markdown links open via `window.open(..., 'noopener,noreferrer')`; in a Tauri
  webview without the opener plugin this may no-op (safe — never navigates away).
  Consider wiring the tauri opener plugin so links open in the OS browser.
- Deeper mid-step cancel (aborting the in-flight step's own request instantly) is
  not implemented — the DeepSeek adapter's `stream()` takes no cancel token; cancel
  drops the current stream and the between-steps check stops the next one. Good enough.
- The adapter crate is still named `decibel-openrouter` though it targets DeepSeek
  (internal label only; rename to `decibel-deepseek` if the pivot sticks).
- `deepseek-v4-flash-vision-exp` accepts images, but the UI has no attachment path
  yet (see F: image attachments).

---

## Suggested next-session order

1. **Session persistence (C)** — makes it a real tool; core JSONL already exists.
2. **Findings panel + multi-agent UI (D)** — the red-team differentiator.
3. **Compaction + slash commands (E)**, then parity (F).

Live agent needs DeepSeek credit. Rebuild = close app + `npm run app`. Keep
committing per feature; run an adversarial review workflow after risky changes
(it has found real bugs three times now).
