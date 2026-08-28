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

### BACKGROUND — the Decepticon port (an earlier session, all pushed)

Ported the entire Rust-coded Decepticon arsenal into decibel. **The harness went
from 9 tools / 3 specialists to 79 tools / 17 specialists** (now **80** with
`run_code`), plus a knowledge graph, an execution plane, a safety envelope, and an
MCP client. The native app was **confirmed working LIVE** (real recon vs 127.0.0.1:
port_scan found 8 ports incl. MariaDB, http_probe/http/cve_by_package/add_finding ran).

**Feature commits from that port (all pushed):**
- `2701bda` decibel-store (SQLite KG + OPPLAN + chain planner) + decibel-executor (bash sessions + Remote-SSH + poc_validate)
- `3f9912b` decibel-offsec: 9 → 79 tools (web/cloud/reversing/refs/arsenal/contracts/cve + envelope + KG/OPPLAN/planning/skills tools)
- `7ba053b` decibel-orchestrator: 3 → 17 specialists (+ 5 vulnresearch pipeline)
- `b3d589e` decibel-mcp: an MCP client (plug external HexStrike/Kali-MCP servers)
- `60a1750` app backend: orchestrate mode + widened read-only subset
- `9c32934` app UI slice: orchestrate toggle, findings panel, envelope (shield+strip+scope), MCP config Settings tab

### CURRENT STATE — almost the entire backlog is DONE + PUSHED (latest session)

`origin/main` is at **`95c7ad6`** and everything below is **committed AND pushed**
(working tree clean). Tests: `cargo test --workspace` **385 pass**, Tauri
`cargo check` clean, `tsc --noEmit` clean. The toolkit is now **80 tools** (added
`run_code`). **Every substantial change was adversarially reviewed** (7 review
workflows this session; each caught real bugs, all fixed).

Done this session, in order (each `feat` + a `fix` from its review):
- **§1** nested specialist streaming + persistent per-session KG/findings (`59f3b81`).
- **Agents panel** — live right-column cockpit: per-specialist status/duration/tokens,
  click-to-scroll (`fb381a4`). **Orchestrator got the full arsenal** + per-agent token
  accounting (`b904a60`).
- **Typography** — the **Space family** (Space Grotesk UI + Space Mono code) bundled
  offline via `@fontsource` (`6e1bff0`,`403142c`). Tool cards start **collapsed** (`dae2e9b`).
- **§2** findings export (Markdown + SARIF) (`d2b6341`).
- **§3** context meter + configurable max-steps + opt-in auto-compaction (`4260af9`).
- **§6** SKILL.md corpus (4 playbooks, bundled) + MCP auto-sync on startup (`163c1af`).
- **§7 #12** findings survive reload (`session_findings` reads the persistent KG) (`9813e7a`).
- **§4** the `shell` tool routes through a **Remote (SSH)** backend (`a0a25c3`) — coherent:
  remote mode drops the local-host tools (`REMOTE_LOCAL_ONLY`) so the agent works entirely
  through the remote shell (`e07e9ec`). ⚠️ **SSH path compile-verified only — NEVER run
  against a real box** (no SSH server in the sandbox). Needs one live test on any SSH host.
- **§5** Goals panel (OPPLAN objective tree, `a552c3e`) · 👍/👎 message feedback (`2d41a93`) ·
  **`run_code`** (Code Mode's execution core — write+run a python/node/bash script in one
  call, local or remote, `093c530`). Background jobs ≈ the existing `bash*` session family.

**Only three things genuinely remain** (see §4 follow-up + §5 SDK + §7 debts below):
the Code-Mode **tools-as-functions SDK** (needs an IPC design), the **§4 full-remote**
follow-up (route nmap/bash*/fs remotely; test on a real box), and the low **§7 debts**.

> ⚠️ Stray untracked junk in the tree — do NOT `git add -A`. Never-ours:
> `test_ports.py`, `apps/desktop/src-tauri/4000`, `crates/decibel-offsec/NUL`.
> Always add the changed files explicitly.

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

Modes (composer chips): **act** (full 80-tool arsenal) · **plan** (no tools, propose
only) · **orchestrate** (multi-agent — delegates to the 17 specialists, streamed live in
the **Agents panel**). Access: **full** or **read-only**. The composer has a **context
meter**; the sidebar has **Agents** / **Goals** / **Findings** (Findings drawer exports
MD/SARIF); assistant messages take 👍/👎. Settings: **Engagement scope** (RoE gate),
**max-steps**, **auto-compact**, **Remote SSH**, **MCP Servers** tab.

Core tests: `cd C:\Users\vi\Desktop\decibel-harness && cargo test --workspace`
(**385 pass**). Tauri is its OWN workspace: `cd apps/desktop/src-tauri && cargo check`.
Frontend typecheck: `cd apps/desktop/ui && npx tsc --noEmit`.

---

## Gotchas

- **App lock** — close the Decibel window before rebuilding the Rust backend.
- **A running `npm run app` will NOT pick up a font/import change** — fully quit + restart
  (Vite doesn't hot-swap the `@fontsource` imports in `index.tsx`). Component edits DO HMR.
- **DeepSeek is billed**; **OpenRouter free is rate-limited** (per-day 429). No auto-fallback.
- **Shell = Git Bash on Windows** (was cmd) — POSIX commands work. Falls back to cmd if absent.
- **Remote (SSH) mode** (Settings → Remote execution): `shell`/`run_code` run on the remote
  host; local-host tools are dropped for coherence. **Never tested against a real box** — needs one.
- **Stray untracked junk — NEVER `git add -A`.** Not ours: `test_ports.py`, `apps/desktop/src-tauri/4000`,
  `crates/decibel-offsec/NUL` (Windows reserved name — regenerates). Add changed files explicitly.
- **Windows shell quirks:** `rtk`/`rg` may be absent (use the Grep/Read tools, not `grep`/`cat`);
  `cargo`/`tsc` recompiles are slow. Each big change was verified with `cargo test --workspace` +
  `cd apps/desktop/src-tauri && cargo check` + `cd apps/desktop/ui && npx tsc --noEmit`.

---

## Architecture (crates + app)

```
crates/
  decibel-llm          Message/ContentBlock/StreamChunk/ToolSchema/LlmAdapter/BlockAssembler
  decibel-core         event-sourced Session log + surface projection + JSONL persist
  decibel-openrouter   OpenAI-compatible streaming adapter (per-run base URL) + model catalog [legacy name]
  decibel-tools        Tool trait (canonical value + pure render) + registry + Pre/PostPolicy
  decibel-agent        run_turn / run_turn_observed (live Progress), AgentConfig (max_steps)
  decibel-offsec       **80 tools** — see below — + register_named / register_named_with_db(…, remote) /
                    register_all; re-exports Db, Backend/Executor/make_executor, kg_list_findings, kg_list_objectives,
                    Objective, ephemeral_db, REMOTE_LOCAL_ONLY; shell::run_shell shared by shell + run_code; Scope/Shield
  decibel-orchestrator **17 specialists** + SubagentTool `delegate`; build_engagement(adapter,model,max_tokens,
                    findings, store, remote, sink) → registry; SpecialistEvent/SpecialistSink (nested UI streaming)
  decibel-store        SQLite KG: nodes/edges, ingest, chain planner, analysis, opplan (Objective/list_objectives),
                    report/SARIF; Db(pub Arc<Mutex<Connection>>) — Db::open/handle/finding_count; open_conn sets WAL+busy_timeout
  decibel-executor     execution plane: Executor{Local,Remote(SSH via russh)}, Backend enum, make(), ExecRequest/ExecResult,
                    SessionManager (persistent shells), poc_validate
  decibel-mcp          MCP CLIENT: McpConnection/McpClient/McpTool + connect/register_mcp_server
apps/desktop/
  src-tauri/src/main.rs  Tauri v2. run_prompt(mode/access/scope/image/max_steps/remote/…): act→ALL_TOOLS
                    (minus REMOTE_LOCAL_ONLY when remote), readonly→READONLY_TOOLS, plan→none, orchestrate→build_engagement;
                    ShieldPolicy(non-plan)+ScopePolicy(when scope). Per-session Engagements{db,findings}; SpecialistEvent→RunEvt.
                    Commands: session_findings/session_objectives/write_text_file/session_context/compact + mcp/session/keys.
                    skills corpus wired via DECIBEL_SKILLS_DIR at startup; bundles skills/ as a Tauri resource.
  ui/src/           SolidJS. App.tsx: composer + context meter, mode/access chips, collapsed tool cards, **Agents panel**
                    (right column, live), Findings + **Goals** drawers, 👍/👎 feedback, tabbed Settings (MCP, scope, max-steps,
                    auto-compact, **Remote SSH**). store.ts: applyEvent (incl. SpecialistRun nested under delegate), findings()
                    (both shapes, deduped, + persisted), objectives(), contextUsage(), remoteExec, feedback. report.ts: MD/SARIF.
                    api.ts: RunEvent (+ specialist_* variants), runPrompt, session_findings/objectives, saveExport.
```

**The 80 tools** (in `decibel_offsec::ALL_TOOLS`): core 10 (shell, **run_code**, nmap,
http, read/write/edit, glob/grep, add_finding); web 6 (jwt_parse/forge/crack, cookie/
oauth/graphql); cloud 6; reversing 5 (bin_*); refs 3; arsenal 7 (port_scan, http_probe,
web_crawl, content_discovery, tls_inspect, dns, dns_subdomains); contracts 5; cve 2;
evidence 3 + shield_scan; exec 6 (bash*/poc_validate); KG 15 (kg_*, plan_chains,
impact_analysis, record_finding, cvss_score, report_executive); OPPLAN 7; planning 2; skills 2.

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

### 4. Remote-SSH executor — ✅ FIRST SLICE DONE (`a0a25c3` + `e07e9ec` review fixes)
- The **`shell` tool** now routes through a Remote (SSH) `Executor` when configured
  (Settings → Remote execution: host/port/user/**key-file path**/workspace; no password
  stored). Threaded through `register_named_with_db(..., remote)` + `build_engagement`
  (so orchestrate specialists run remote too). Local path (Git Bash + scrub) unchanged.
- **Coherent by construction**: in remote mode `register_named_with_db` skips the
  local-host tools (`REMOTE_LOCAL_ONLY`: fs, local-vantage network probes, `bash*`,
  `poc_validate`) — the agent does ALL host work via the remote `shell`. Remote shell
  races the cancel token; a missing key file aborts pre-start.
- ⚠️ The SSH path is compile/logic-verified but **never tested against a real box** here.
  Follow-up: route `nmap`/`bash*`/fs via SFTP+remote-sessions for a fuller remote arsenal;
  container backend.

### 5. Larger parity (F) — **mostly DONE; only the tools-as-functions SDK is left**
- ✅ **goals** (`a552c3e`) — a **Goals drawer** surfaces the OPPLAN objective tree via
  `session_objectives(id)`: status pills, phase, parent nesting, priority order.
- ✅ **message feedback** (`2d41a93` + `9364149`) — 👍/👎 on assistant messages, per-session
  (deliberately NOT persisted — the reconstructed transcript re-indexes messages, so a stored
  index would rate the wrong message on reload).
- ✅ **Code Mode — execution core** (`093c530`): a **`run_code`** tool — write a whole script
  (python/node/bash) and run it in one call (quoted heredoc → interpreter, no temp file);
  reuses the shared `run_shell` helper so it runs local OR on the Remote (SSH) host. In
  `ALL_TOOLS`, remote-routed, NOT in READONLY.
  - ❌ **Follow-up — the "SDK" half**: a *tools-as-functions* bridge so the model's code can
    call the other tools programmatically (e.g. `decibel.http(url)`, `decibel.record_finding(…)`).
    Needs an IPC bridge (script↔app tool-call protocol) + a way to give `run_code` the tool
    registry — a real design; do it alone.
- ✅ **background jobs** — effectively covered by the existing **`bash*` session family**
  (`bash`/`bash_input`/`bash_output`/`bash_status`/`bash_kill`): start a long command, poll its
  output, kill it — async execution detached from a single tool call. A separate job system
  would duplicate this; a "jobs panel" UI over the sessions would be the only add.

### 6. Skills corpus + MCP polish — ✅ DONE (`163c1af`)
- **4 SKILL.md playbooks** (reconnaissance, web-exploitation, network-services, reporting)
  under `apps/desktop/src-tauri/skills/`, bundled as a Tauri resource; `install_skills_corpus()`
  points `DECIBEL_SKILLS_DIR` at the resource dir (build) or `CARGO_MANIFEST_DIR/skills`
  (dev). **MCP auto-sync** on startup (`syncMcpToBackend` in `onMount`).

### 7. Known debts (all low) — **#12 findings-on-reload DONE (`9813e7a`)**
- ✅ **#12 (the valuable half)**: `session_findings(id)` command reads the persistent KG
  (`record_finding`) + finding store (`add_finding`); `findings()` merges them so a
  reopened session's findings survive (the transcript still drops the tool `value`, but
  the drawer no longer depends on it). Deep value-persistence in the content model = still open.
- Rename `decibel-openrouter` → `decibel-deepseek` (mechanical but high-churn; every import).
- Opener plugin for markdown links; deeper mid-step cancel; `run_turn` dangling user
  message on first-step error; meta.json rename race; blocking fs IO on the async worker.

---

## Suggested next-session order

1. §0–§4(slice), §5 (goals, feedback, run_code; background jobs ≈ `bash*`), §6, §7#12 are
   **DONE**. What genuinely remains are three focused, design/test-heavy pieces:
2. **Code Mode SDK** (tools-as-functions) — the `run_code` execution core is in; this adds the
   IPC bridge so the script can call the agent's tools programmatically. Design first.
3. **§4 follow-up** — route `nmap`/`bash*`/fs remotely (SFTP + remote sessions) for a full
   remote arsenal; **test against a real SSH box** (the current slice is compile-verified only).
4. **Low §7 debts** — deeper mid-step cancel, meta.json rename race, blocking fs IO on the
   async worker, opener plugin for markdown links, crate rename (all low value).

Rebuild = close app + `npm run app`. Keep committing per feature. An adversarial
review workflow after risky changes has caught real bugs repeatedly (it caught the §4
host-coherence bug — the shell-only remote slice mixed local + remote hosts silently).
