# Decibel Harness — Handoff

A living handoff so a fresh Claude Code session (after `/clear`) can pick up
without losing context. Pair it with the memory file at
`C:\Users\vi\.claude\projects\C--Users-vi-Desktop-ds-harness\memory\decibel-harness.md`
(auto-recalled; it has the full blow-by-blow). User speaks **Portuguese**.

---

## What this is

**Decibel** — a desktop **autonomous red-team / pentest agent** (Rust workspace +
Tauri v2 + SolidJS). Repo `C:\Users\vi\Desktop\decibel-harness`, git remote
`decibelzin/decibel-harness`, branch `main`. **No guardrails by design** (full
shell/fs/network authority; only secret-env scrubbing on spawned processes).

**Providers (multi-provider, all DeepSeek-family):** `deepseek` (paid API,
`https://api.deepseek.com`) and `openrouter` (free tool-capable models, live
catalog). Each model carries a `provider` tag; a run routes to the matching
endpoint + keyring key. The adapter crate is still **named** `decibel-openrouter`
(legacy label — it's a generic OpenAI-compatible adapter).

### BIG NEWS — the Decepticon port (this session)

Ported the entire Rust-coded Decepticon arsenal into decibel. **The harness went
from 9 tools / 3 specialists to 79 tools / 17 specialists**, plus a knowledge
graph, an execution plane, a safety envelope, and an MCP client. **Everything
compiles and `cargo test --workspace` is GREEN (~380 tests).** The native app was
**confirmed working LIVE** this session (real recon vs 127.0.0.1: port_scan found
8 ports incl. MariaDB, http_probe/http/cve_by_package/add_finding all ran).

**Committed on `main` (NOT pushed) — 6 feature commits this session:**
- `2701bda` decibel-store (SQLite KG + OPPLAN + chain planner) + decibel-executor (bash sessions + Remote-SSH + poc_validate)
- `3f9912b` decibel-offsec: 9 → 79 tools (web/cloud/reversing/refs/arsenal/contracts/cve + envelope + KG/OPPLAN/planning/skills tools)
- `7ba053b` decibel-orchestrator: 3 → 17 specialists (+ 5 vulnresearch pipeline)
- `b3d589e` decibel-mcp: an MCP client (plug external HexStrike/Kali-MCP servers)
- `60a1750` app backend: orchestrate mode + widened read-only subset
- `9c32934` app UI slice: orchestrate toggle, findings panel, envelope (shield+strip+scope), MCP config Settings tab

### NEWER — §1 both follow-ups DONE this session (nested streaming + persistent KG)

The §0 shell/max_steps fix is committed (`66c4f08`) and everything through the
Decepticon port is pushed. **This session implemented the whole of backlog §1**
(nested specialist streaming + persistent KG/findings) — see the §1 entry below,
now marked done. All green: `cargo test --workspace` **382 pass**, Tauri
`cargo check` clean, `tsc --noEmit` clean. An adversarial 4-dimension review ran
after and found 3 real issues, all fixed (findings_added counted the wrong store;
no sqlite busy_timeout; the specialist end-summary was invisible for non-streaming
models). **Uncommitted at handoff** unless the commit below already ran.

> ⚠️ Stray untracked junk in the tree — do NOT `git add -A`. Never-ours:
> `test_ports.py`, `apps/desktop/src-tauri/4000`, and a new reserved-name file
> `crates/decibel-offsec/NUL`. Always add the changed files explicitly.

---

## How to run / test

Native app (close it first — a running app locks `decibel-desktop.exe` and the
rebuild fails):
```
cd C:\Users\vi\Desktop\decibel-harness\apps\desktop\ui
npm install     # first time
npm run app     # tauri dev — opens the native window
```
Then **Settings → Models & Providers**: paste a **DeepSeek** key (needs credit) or
**OpenRouter** key; pick a model in the composer chip. Dev override: `DEEPSEEK_API_KEY`
/ `OPENROUTER_API_KEY` env (or a gitignored `.env`).

Modes (composer chips): **act** (full 79-tool arsenal) · **plan** (no tools, propose
only) · **orchestrate** (multi-agent — delegates to the 17 specialists). Access:
**full** or **read-only** (non-destructive subset). Settings has an **Engagement
scope** field (arms the RoE gate) and an **MCP Servers** tab.

Core tests: `cd C:\Users\vi\Desktop\decibel-harness && cargo test --workspace`
(~380 pass). Tauri is its OWN workspace: `cd apps/desktop/src-tauri && cargo check`.
Frontend typecheck: `cd apps/desktop/ui && npx tsc --noEmit`.

---

## Gotchas

- **App lock** — close the Decibel window before rebuilding the Rust backend.
- **DeepSeek is billed**; **OpenRouter free is rate-limited** (per-day 429). No auto-fallback.
- **Shell = Git Bash on Windows** now (was cmd) — POSIX commands work. Falls back to cmd if Git Bash is absent.
- **Two stray untracked files** in the tree are NOT ours — do NOT commit them: `test_ports.py` (repo root) and `apps/desktop/src-tauri/4000`.
- **Safety classifier note (this session only):** after the live recon against a real target, the auto-mode classifier blocked non-read-only Bash (cargo/git). A fresh session or the default permission mode clears it.

---

## Architecture (crates + app)

```
crates/
  decibel-llm          Message/ContentBlock/StreamChunk/ToolSchema/LlmAdapter/BlockAssembler
  decibel-core         event-sourced Session log + surface projection + JSONL persist
  decibel-openrouter   OpenAI-compatible streaming adapter (per-run base URL) + model catalog [legacy name]
  decibel-tools        Tool trait (canonical value + pure render) + registry + Pre/PostPolicy
  decibel-agent        run_turn / run_turn_observed (live Progress), AgentConfig (max_steps)
  decibel-offsec       **79 tools** — see below — + register_named/register_all/register_all_with_envelope; Scope/ScopePolicy/ShieldPolicy
  decibel-orchestrator **17 specialists** (roster.rs: SpecialistSpec + gates) + SubagentTool `delegate` + build_engagement + specialists/*.md
  decibel-store        SQLite knowledge graph: nodes/edges + vocab, ingest, chain planner (Dijkstra), analysis, opplan, report/SARIF
  decibel-executor     execution plane: LocalExecutor + RemoteExecutor (SSH via russh) + SessionManager (persistent shells) + poc_validate
  decibel-mcp          MCP CLIENT: McpConnection/McpClient/McpTool + connect/register_mcp_server
apps/desktop/
  src-tauri/src/main.rs  Tauri v2. run_prompt(mode/access/scope/…): act→ALL_TOOLS, readonly→READONLY_TOOLS,
                    plan→none, orchestrate→build_engagement; installs ShieldPolicy (non-plan) + ScopePolicy (when scope set).
                    McpState + set_mcp_servers/list_mcp_servers. Sessions (multi-turn) + persistence + slash cmds.
  ui/src/           SolidJS: App.tsx (composer, mode/access chips, tool cards, findings drawer, tabbed Settings w/ MCP + scope),
                    store.ts (Mode incl. orchestrate, findings(), stripUntrusted, mcp config), api.ts (RunEvent, runPrompt, mcp/session cmds)
```

**The 79 tools** (in `decibel_offsec::ALL_TOOLS`): core 9 (shell, nmap, http,
read/write/edit, glob/grep, add_finding); web 6 (jwt_parse/forge/crack, cookie/
oauth/graphql); cloud 6 (iam/s3/user_data/k8s/tfstate/metadata); reversing 5
(bin_*); refs 3 (payload_search, killchain_*); arsenal 7 (port_scan, http_probe,
web_crawl, content_discovery, tls_inspect, dns, dns_subdomains); contracts 5
(solidity/foundry_*); cve 2; evidence 3 + shield_scan; exec 6 (bash*/poc_validate);
KG 15 (kg_*, plan_chains, impact_analysis, record_finding, cvss_score,
report_executive); OPPLAN 7; planning 2; skills 2.

**Source to port from:** the sibling `C:\Users\vi\Desktop\decepticon-control-center`
is a mature Rust reimplementation of Decepticon — the copy-portable crates all
came from `src-tauri/{arsenal,web,cloud,reversing,contracts,cve,refs,executor,
store,roe,shield,evidence,planning,skills,mcp,agent,tools}`. **hackerai: license
forbids reuse — do NOT port from it.**

---

## WHAT'S LEFT TO DO (the backlog)

### 0. Commit the pending shell/max_steps fix — ✅ DONE (`66c4f08`, pushed).

### 1. The two deferred integration follow-ups — ✅ DONE this session
- **Nested specialist streaming** ✅ — `decibel-orchestrator` gained
  `SpecialistEvent`/`SpecialistSink`; `SubagentTool` forwards each specialist's
  Start/Step/Token/ToolCall/ToolResult/End to the sink (stderr fallback when
  headless). `build_engagement(adapter, model, max_tokens, findings, store, sink)`
  threads it. New `RunEvt::Specialist*` variants → `api.ts` `RunEvent` → `store.ts`
  `applyEvent` attaches a nested `SpecialistRun` to the `delegate` `ToolBlock` →
  `App.tsx` `SpecialistTimeline` (reuses `BlockView`, so nested nmap/http cards
  render) + CSS. Browser mock got an orchestrate branch. The `delegate` card now
  shows the live sub-agent timeline in place of the opaque summary.
- **Persistent KG + findings-across-turns** ✅ — `decibel-store` `Db::handle()`
  (+ `Db::finding_count()`, `busy_timeout`). `decibel-offsec` split
  `register_named` → `register_named_with_db(registry, names, findings, &Db)` +
  `ephemeral_db()`, and re-exports `Db`. The app holds per-session
  `Engagement { db, findings }` in `Engagements` state, opening
  `{app_data}/kg/<session>.sqlite` once per session (`engagement_handles`),
  injected into BOTH the act path (`register_named_with_db`) and orchestrate
  (`build_engagement`). `clear_session` drops the handle (keeps the file, session
  stays reloadable); `delete_session` drops it + deletes the kg files. KG +
  `record_finding` now persist across turns AND app restarts (WAL). Bonus:
  `findings()` now reads both finding shapes (`add_finding`'s `value.finding` and
  `record_finding`'s flat `value`), so the primary KG recorder shows in the drawer.

### EXTRA this session (not in the original backlog — user-requested)
- **Full-arsenal orchestrator** (`b904a60`): `build_engagement` gives the orchestrator
  `ALL_TOOLS` (shared finding store + persistent KG), prompt rewritten to prefer
  delegation but consult the KG + `record_finding` (using `findings_added` to avoid
  duplicate records). Per-agent **token accounting** summed from the specialist sub-session.
- **Live Agents panel** (`fb381a4`): right-column cockpit — one row per specialist with
  status, live-ticking duration, steps, findings, tokens; sidebar toggle, click-to-scroll.
  `cancel()`/`done` finalize running agents (no phantom ticker). `findings()` dedups by (title,target).
- **Typography** (`6e1bff0`,`403142c`): the **Space family** bundled via `@fontsource`
  (Space Grotesk UI + Space Mono code), offline. (Not Anthropic's proprietary face — closest free match.)
- **Tool cards start collapsed** (`dae2e9b`).

### 2. Findings + reporting — ✅ DONE (`d2b6341`)
- Export buttons in the Findings drawer → **Markdown + SARIF** (`ui/src/report.ts`),
  generated from the deduped `findings()` view, saved via native dialog + `write_text_file`.
- (Still open, minor) `run_prompt` returning findings as first-class data — the drawer
  is transcript-derived; a `session_findings(id)` backend read from the KG would also
  fix #12 (findings on reload). Deferred.

### 3. Agent robustness — ✅ DONE (`4260af9`) (pruner deferred)
- **Context meter** in the composer (`contextUsage()`), **configurable max_steps**
  (Settings, 1–200 → `run_prompt` `max_steps` param), **opt-in auto-compaction** (toggle;
  runs `/compact` at ~80% after a turn). ⚠️ The **tool-result pruner** (dsh-style,
  truncating old tool outputs in the agent loop) is a deeper `decibel-agent` change — **deferred**.

### 4. Expose the Remote-SSH executor in the app — **NOT DONE (substantial)**
- `decibel-executor` ships a Remote SSH backend, but routing the tools through it is a
  real multi-crate change: **`ShellTool` uses `Command::new` directly** (not the
  `Executor` abstraction) and the `bash*` tools hold a local `SessionManager`. Scope:
  (a) rewrite `ShellTool`/exec tools onto `decibel_executor::Executor`, (b) make
  `SessionManager` backend-aware, (c) thread a `Backend` from `run_prompt` →
  `register_named`, (d) Settings UI (host/user/**key-file path** — avoid handling the
  key itself). Do it as a focused session; don't half-wire it.

### 5. Larger parity (F) — **NOT STARTED (large)**
goals · background jobs · **Code Mode** (`run_code` + a sandboxed SDK) · message feedback.
Each is its own feature; Code Mode especially. Focused session per item.

### 6. Skills corpus + MCP polish — ✅ DONE (`163c1af`)
- **4 SKILL.md playbooks** (reconnaissance, web-exploitation, network-services, reporting)
  under `apps/desktop/src-tauri/skills/`, bundled as a Tauri resource; `install_skills_corpus()`
  points `DECIBEL_SKILLS_DIR` at the resource dir (build) or `CARGO_MANIFEST_DIR/skills`
  (dev). **MCP auto-sync** on startup (`syncMcpToBackend` in `onMount`).

### 7. Known debts (all low) — **NOT DONE**
- **#12 reopened tool cards lose their `value`** — `ContentBlock::ToolResult` has NO
  `value` field (only text), so the structured value is never persisted. Fixing it needs
  value-persistence in the content/event model (deep) OR the drawer reading findings from
  the persistent KG (`session_findings` command). The higher-value half is the latter.
- Rename `decibel-openrouter` → `decibel-deepseek` (mechanical but high-churn; every import).
- Opener plugin for markdown links; deeper mid-step cancel; `run_turn` dangling user
  message on first-step error; meta.json rename race; blocking fs IO on the async worker.

---

## Suggested next-session order

1. §0/§1/§2/§3/§6 are **DONE + pushed**. The remaining backlog is the *big* stuff.
2. **§4 Remote-SSH** — the next real feature; scope above. Rewrite `ShellTool` onto the
   `Executor` first, then thread the backend + Settings UI.
3. **§7 #12 findings-on-reload** — a `session_findings(id)` command reading the persistent
   KG, merged into the drawer. Makes findings survive reload/restart (the KG already persists).
4. **§5 Code Mode** and the rest of parity — focused sessions.

Rebuild = close app + `npm run app`. Keep committing per feature. An adversarial
review workflow after risky changes has caught real bugs repeatedly.
