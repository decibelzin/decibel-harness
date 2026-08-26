# Decibel Harness

A lightweight desktop **autonomous red-team agent harness**.

Decibel is a local desktop app (no cloud, no login) that drives an LLM agent
through offensive-security work — reconnaissance, exploitation, post-exploitation,
and reporting — using the standard pentest toolchain already on your machine.
It is powered by [OpenRouter](https://openrouter.ai) and defaults to its
free-tier models, with a live model picker that shows each model's context size
and whether it supports tool calling.

> **Authorized use only.** Decibel is a penetration-testing tool, like nmap,
> sqlmap, or Metasploit. It is authorization-neutral: run it only against systems
> you own or are explicitly permitted to test.

## Design

Decibel is a Rust port of the architecture proven in
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (MIT), with
the multi-agent red-team structure of
[Decepticon](https://github.com/PurpleAILAB/Decepticon) (Apache-2.0) layered on
top. The core is domain-neutral; the offensive focus lives in the toolkit and
presets above it.

Two ideas carry the whole design:

1. **The session is an event-sourced log, and it is the single source of truth.**
   The model's message history is *derived* from an append-only log of
   `SessionEvent`s via an ordered *surface* projection. Compaction shadows a run
   of surface nodes with one replacement rather than deleting anything, so every
   fact stays reconstructable. **Model-visible ⟺ logged.**

2. **The loop is a thin driver over swappable capability seams.** A turn drains
   input; a step is one model request plus the tools it calls. Everything else —
   the model adapter, the tool registry, persistence, subagents — is a seam with
   a defined interface, so the offensive toolkit and the OpenRouter adapter plug
   in without touching the loop.

## Stack

| Layer | Choice | Why |
|---|---|---|
| Shell | Tauri v2 | ~5–10 MB installer, ~100 MB RAM, uses the OS WebView |
| Backend | Rust | the whole harness — streaming, PTY, tools, MCP — in one binary |
| Frontend | SolidJS + Vite | fine-grained reactivity for token streaming, no VDOM cost |
| Model | OpenRouter | free-tier catalog with live autosync |

## Workspace

```
crates/
  decibel-llm      # provider-neutral vocabulary: Message, ContentBlock, StreamChunk, ToolSchema
  decibel-core     # the event-sourced session log, surface projection, JSONL persistence
  # (upcoming) decibel-openrouter, decibel-tools, decibel-agent, decibel-loop, decibel-offsec
apps/
  # (upcoming) desktop  — the Tauri + SolidJS application
```

## Build

```bash
cargo test --workspace
```

## Status

Early development. Milestone 2 (the session core) is complete and tested; the
OpenRouter adapter, tool pipeline, agent loop, offensive toolkit, and the Tauri
UI follow. See the roadmap in the project notes.

## License

MIT. Portions are independent reimplementations of MIT/Apache-2.0-licensed
designs; see source comments for attribution.
