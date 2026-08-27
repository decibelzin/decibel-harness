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
vars from spawned processes). Repo: `C:\Users\vi\Desktop\decibel-harness` (git
remote `decibelzin/decibel-harness`, branch `main`). User speaks **Portuguese**.

> **Providers (2026-08-26):** the app is **multi-provider**, all DeepSeek models,
> from two backends — each model carries a `provider` tag and a run routes to the
> matching endpoint + key:
> - **`deepseek`** (paid DeepSeek API, `https://api.deepseek.com`, key from
>   platform.deepseek.com): `deepseek-v4-flash` (default), `deepseek-v4-pro`,
>   `deepseek-v4-flash-vision-exp` — all 1M context, all support tool calls.
> - **`openrouter`** (free tool-capable models, `https://openrouter.ai/api/v1`,
>   key from openrouter.ai/keys): fetched live from OpenRouter's public catalog.
>   **OpenRouter has NO free DeepSeek models anymore** (all `deepseek/*` there are
>   paid), so this free tier is other providers — MiniMax, GLM, Gemma, Nemotron,
>   … (~15, all tool-capable; `thinkingmachines/*` gated ones are skipped).
>
> History: started on OpenRouter free models → pivoted to DeepSeek-paid-only →
> then re-added the free tool-capable OpenRouter models alongside the paid ones
> (the user asked for "free DeepSeek from OpenRouter", but none exist there now).
> The adapter crate is still **named** `decibel-openrouter` (internal label; it's
> a generic OpenAI-compatible adapter pointed per-run at either base URL).

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
Then **Settings → Models & Providers** and paste the key(s) for the models you'll
use (stored in Windows Credential Manager): a **DeepSeek** key
(platform.deepseek.com/api_keys, add credit under Top Up) for the paid models,
and/or an **OpenRouter** key (openrouter.ai/keys) for the free tool-capable
models. Pick a model in the composer's model chip. Dev overrides: `DEEPSEEK_API_KEY`
/ `OPENROUTER_API_KEY` env vars (or a gitignored workspace-root `.env`).

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
- **Paid DeepSeek models are billed** — every run spends real credit; HTTP 402 /
  `Insufficient Balance` → an actionable "add credit at platform.deepseek.com/top_up"
  error. Off-peak vs peak pricing (off-peak ~50% cheaper) + a cache-hit discount.
- **Free OpenRouter models are rate-limited** — a per-day 429 → a "wait for
  reset / add credit / pick a paid DeepSeek model" message. The catalog filters
  to free + tool-capable and drops gated `thinkingmachines/*` (AUTH), so the
  listed free models are usable as agents. There is NO auto-fallback anymore, so
  a rate-limited free model just errors — switch models and retry.
- **Two keys, per provider** — keyring accounts `deepseek` and `openrouter` under
  service `decibel-harness`; `run_prompt(provider,…)` picks the base URL + key.
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
  decibel-openrouter  OpenAI-compatible streaming adapter (pointed per-run at the
                    DeepSeek or OpenRouter base URL via .with_base_url); catalog:
                    deepseek_models() (paid) + openrouter_free_tool_models()
                    (fetched free tool-capable); fetch_full_catalog() = both. .provider tags
                    each. [crate name is legacy — it's a generic adapter now]
  decibel-tools     Tool trait (canonical value + pure render) + registry + pipeline
  decibel-agent     run_turn / run_turn_observed (live Progress), AgentConfig, TurnSignal
  decibel-offsec    9 tools: shell, nmap(structured), http, read/write/edit, glob/grep,
                    add_finding(MITRE); shared proc (tree-kill + secret-env scrub); FindingStore
  decibel-orchestrator  multi-agent: SubagentTool delegates to recon/exploit/report specialists
apps/desktop/
  src-tauri/src/main.rs   Tauri v2. provider_config(provider)→(keyring account, env,
                    base URL). Sessions state = Session per conversation (multi-turn).
                    Commands: list_models (fetch_full_catalog), run_prompt (provider +
                    session_id; reuses the session; streams RunEvt), cancel_run,
                    has/save/delete_api_key(provider), clear_session, session_context,
                    compact_session.
  ui/src/           SolidJS + Vite:
    api.ts          invoke + Channel + browser mock; RunEvent union; per-provider key
                    fns; clearSession/sessionContext/compactSession
    store.ts        conversation, models, theme pref, run-generation guard, sessionId
                    (multi-turn), slash COMMANDS + runSlashCommand (/compact,/context,…)
    markdown.ts     marked + DOMPurify + highlight.js (curated langs), theme-var token colors
    App.tsx         sidebar, hero+composer (with slash-command menu), model picker,
                    tabbed Settings, tool cards, Markdown, system-role messages
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
- [x] **Real tabbed Settings page** — Models & Providers (DeepSeek + OpenRouter
      keys + default model), General (providers + authority notes), Appearance
      (dark/light/system theme, persisted), About. Replaces the old bare key modal.
- [x] Adversarial multi-agent review (3rd): 4 real bugs found + fixed (below).
- [x] **Pivot to the paid DeepSeek API** (2026-08-26) — DeepSeek base URL + key +
      fixed 3-model catalog; removed the free-model auto-fallback, `ModelFallback`
      event, `activeModel`, and the free/tools catalog filters.
- [x] **Multi-provider: added the free tool-capable OpenRouter models** (2026-08-26)
      — `ModelInfo.provider` tag; `fetch_full_catalog()` = paid DeepSeek +
      `openrouter_free_tool_models()` (live from OpenRouter — free + tools, minus
      gated `thinkingmachines/*`); `provider_config` + per-provider
      `resolve_key`/`has/save/delete_api_key(provider)`; `run_prompt(provider,…)`
      routes base URL + key; two key fields in Settings; provider badge in the
      picker. **Discovered OpenRouter no longer lists ANY free DeepSeek models**
      (all `deepseek/*` there are paid), so — per the user — the free tier is all
      tool-capable free models (MiniMax/GLM/Gemma/Nemotron/…). Verified live:
      `fetch_full_catalog()` returns 18 (3 paid DeepSeek + 15 free OpenRouter);
      preview + both key fields OK; 61 tests + all builds green. **Not yet run
      live** against either provider here (needs the user's keys/credit).
- [x] **Multi-turn memory + slash commands** (2026-08-27) — the backend now keeps a
      `Session` per conversation (`Sessions` state, keyed by a frontend `session_id`)
      so the model sees prior turns; `run_prompt(…, session_id, …)` takes/puts the
      session back around the turn (`take_session`/`put_session`). New commands:
      `clear_session`, `session_context` (messages + estimated tokens + last turn's
      provider-reported usage), `compact_session` (a toolless summarization turn →
      reseed the session with just the summary as injected context). Frontend: a
      slash-command autocomplete menu (`/clear /new /compact /context /model
      /settings /help`) with keyboard nav, `system`-role messages for output, a
      `sessionId` rotated on New Session. Verified in preview: menu + filtering +
      `/help` `/context`(estimated) `/model` `/clear`. `/compact` and real-token
      `/context` need the live app + a key (not run live here).
      **Adversarial review (4th) found 9 real bugs; 8 fixed:** per-session async
      lock (`Arc<tokio::Mutex<Session>>`) so concurrent runs/compact can't fork a
      blank session or clobber history on write-back (was reachable via
      Stop-then-resend); compact summarizes on a clone + replaces only on success
      (never corrupts on error); compact seeds the summary as an ASSISTANT message
      (clean alternation); a run-generation guard so a late `/compact` can't clobber;
      `/` submit only runs an EXACT `/name` (bare `/`+Enter and `/new prose` no
      longer wipe/misfire; Tab completes, not executes); the composer draft lives in
      the store (survives the hero↔docked remount) and the textarea autofocuses.

**Verified:** 61 core tests green; Tauri crate + UI build; the live
`fetch_full_catalog()` (what the app's `list_models` calls) returns 18 models
(3 paid DeepSeek + 15 free OpenRouter, all tool-capable); browser preview drives
the tool cards, markdown, theme, prefs, lists paid + free with provider badges,
and shows both key fields. Not yet run live against either provider (needs keys).

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
- [x] **Multi-turn memory** — done (backend keeps a Session per conversation).
- [x] **Slash commands** — done (/clear /new /compact /context /model /settings /help).
- [x] **Context compaction** — a first `/compact` exists (summarize → reseed). Could
  add automatic compaction at a token threshold + a tool-result pruner (dsh-style).
- **Turn/step budget** UI, token/usage meter — `/context` shows usage on demand;
  a persistent meter in the composer is still TODO. AgentConfig.max_steps is fixed at 16.

**F. Larger parity (later)** — plan/act mode + permission presets (the "Standard
mode"/"Full access" chips are still decorative), goals, background jobs, skills
catalog, MCP client, Code Mode (run_code + SDK), image attachments, message
feedback.

**User asked for the "make everything functional" set (2026-08-27)** — the
decorative UI (workspace chip, sidebar workspace, Standard mode, Full access, +,
sidebar icons) built in phases:
- [x] **Phase 1 — real workspace (DONE):** the workspace chip + sidebar pick a
  real directory; the shell/fs/search tools operate in it (`ExecCtx.cwd`/`resolve`,
  `AgentConfig.with_cwd`, `run_prompt(workspace)`, `path_is_dir` validator,
  persisted in localStorage). The fake "fullbreachtoolkit" entry is gone.
- [x] **Phase 2 — session persistence + real sidebar (DONE):** sessions are saved
  to `{app_data}/sessions/{id}.jsonl` (+ `.meta.json`) after each turn/compaction;
  the sidebar lists them (newest first) with open / inline-rename (double-click) /
  delete, highlighting the active one. `list_sessions`/`load_session` (reconstructs
  the display transcript from the log) / `delete_session`/`rename_session`; the
  in-memory session is reinstated on load so multi-turn continues. Reloaded tool
  cards show the tool's rendered output text (the structured value isn't stored).
  **Needs the live app to exercise disk persistence (preview has none).**
- [x] **Phase 3 — plan/act mode + access preset (DONE):** the "Standard mode" chip
  is now an Act/Plan dropdown, the "Full access" chip a Full/Read-only dropdown
  (persisted). `run_prompt(mode, access)`: **plan** → no tools + a plan-only system
  prompt (propose, don't execute); **read-only** → the non-destructive tool subset
  (nmap/http/read/glob/grep/add_finding — no shell/write/edit); else the full toolkit.
- [x] **Phase 4 — image attachments (DONE):** the `+` button attaches an image
  (file → base64 data URL → preview with a remove button; send enabled with an
  image alone). New `ContentBlock::Image { url }` in the LLM vocabulary; the adapter
  emits the OpenAI vision content array (`{type:image_url,image_url:{url}}`) for a
  user message with images (unit-tested); `run_prompt(image)` adds it to the prompt.
  Use a vision model (`deepseek-v4-flash-vision-exp`, or an OpenRouter vision model).

**Adversarial review (5th, of the 4 phases) — 16 findings confirmed, 13 fixed:**
persist_session now fences on session Arc identity (`is_current_session`) so a
delete/reopen mid-run can't resurrect or clobber a session (was high); atomic
temp-file+rename writes; `ExecCtx::resolve` strips leading separators so a `/x`
path can't escape the workspace to the drive root on Windows (was high, unit
tested); the shell tool's relative `workdir` now resolves against the workspace;
`openSession` has a generation guard + a `sessionLoading` gate (blocks sends
during a load); the composer draft is cleared only when a send commits (Enter with
no model no longer eats the text); Enter on an ambiguous slash prefix (`/c`)
COMPLETES to `/clear` instead of executing it; the `+` attach button is gated on
the model's vision modality; draft/image are cleared on session switch; rename is
its own button (no more double-click firing openSession); the textarea regrows its
height on remount. **Deferred (all low):** #3 rename-vs-persist meta race, #4
blocking fs IO on the async worker (files are tiny), #12 reopened tool cards lose
their structured `value` (show rendered text only).

**Minor known limitations**
- Markdown links open via `window.open(..., 'noopener,noreferrer')`; in a Tauri
  webview without the opener plugin this may no-op (safe — never navigates away).
  Consider wiring the tauri opener plugin so links open in the OS browser.
- Deeper mid-step cancel (aborting the in-flight step's own request instantly) is
  not implemented — the DeepSeek adapter's `stream()` takes no cancel token; cancel
  drops the current stream and the between-steps check stops the next one. Good enough.
- **(review finding #5, not fixed — low)** `run_turn` appends the user prompt to
  the surface before the first model call, so a first-step terminal error leaves
  the history ending on a user message; the next turn then sends two consecutive
  user messages. Harmless on DeepSeek/OpenRouter (OpenAI-compatible, accept
  consecutive same-role); would matter for a strict-alternation provider. A safe
  fix (roll back the prompt on first-step error) is a core-loop change deferred.
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
