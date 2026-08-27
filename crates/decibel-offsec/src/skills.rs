//! Model-facing [`Tool`] wrappers over a vendored `SKILL.md` playbook loader.
//!
//! A *skill* is a `SKILL.md` markdown playbook with YAML frontmatter (`name`,
//! `description`, `metadata.subdomain`, `metadata.when_to_use`). [`SkillIndex`]
//! walks a skills root, indexes the frontmatter, and offers `find` (search by
//! query/subdomain) and `load_skill` (return the full untruncated body) — the
//! portable filesystem baseline ported straight from Decepticon's `skills` crate
//! (`src-tauri/skills/src/lib.rs`). The loader logic is fully self-contained (no
//! YAML crate, no other Decepticon crates), so it is vendored verbatim below.
//!
//! Two tools mirror the upstream dispatcher arms (`tools/src/lib.rs`):
//!   - `skills_find` — `query`(opt)/`subdomain`(opt)/`limit`(opt, 20) → matching
//!     skill records;
//!   - `skills_load` — `name`(req: an id, slug, or name) → the full skill body.
//!
//! **Corpus directory (configurable).** Each call resolves the skills root the
//! same way the upstream `Ctx` did (env-first), but rebased onto the decibel
//! namespace + the session workspace: the env var `DECIBEL_SKILLS_DIR` when set
//! and non-empty, else the `skills` subdir of the session working directory
//! (`ctx.resolve("skills")`). The index is small, so — like the upstream Tauri
//! command layer — each call reloads it rather than caching a shared handle; no
//! shared state is threaded through `register_named`.
//!
//! **Graceful when the corpus is absent.** A missing (or empty) skills directory
//! is never an error: `SkillIndex::load` over a non-existent dir yields an empty
//! index, so `skills_find` returns `count: 0, skills: []` and `skills_load`
//! returns a `found: false` "no skills available" result. Only a *present,
//! non-empty* corpus that lacks the requested name makes `skills_load` surface a
//! "skill not found" execution error (mirroring the dispatcher's `Err`), so the
//! model learns to correct the name.
//!
//! NOTE / omission vs. upstream: the module doc of the source crate mentions
//! MITRE, but the shipped `SkillRecord` + frontmatter parser only extract
//! name/description/subdomain/when_to_use — there is no MITRE field. Vendored
//! faithfully: no MITRE field is added here.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::util::{arg_str, arg_str_opt, arg_u64_opt};

/// Default number of `skills_find` matches when the model names no `limit`
/// (mirrors the upstream dispatcher default).
const DEFAULT_FIND_LIMIT: u64 = 20;

/// Environment override for the skills corpus directory. When set and non-empty
/// it wins over the workspace-relative `skills` subdir.
const SKILLS_DIR_ENV: &str = "DECIBEL_SKILLS_DIR";

/// Resolve the skills corpus directory for a call: `DECIBEL_SKILLS_DIR` when set
/// and non-empty, else the `skills` subdir under the session working directory
/// (`ctx.resolve("skills")`, which stays inside the workspace).
fn skills_dir(ctx: &ExecCtx) -> PathBuf {
    match std::env::var(SKILLS_DIR_ENV) {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => ctx.resolve("skills"),
    }
}

/// Serialize a value into the canonical tool value, mapping a serde failure to an
/// execution error.
fn to_value<T: Serialize>(v: T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::execution(e.to_string()))
}

// ===========================================================================
// Vendored loader — ported verbatim from decepticon-skills (src-tauri/skills).
// Self-contained: no crate-root refs to rewrite, no external YAML dependency.
// ===========================================================================

/// One indexed `SKILL.md` playbook's frontmatter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SkillRecord {
    /// Virtual id: the posix path under the root, e.g. `/recon/nmap/SKILL.md`.
    pub id: String,
    /// Short handle: parent dir name for `SKILL.md`, else the file stem.
    pub slug: String,
    pub name: String,
    pub description: String,
    pub subdomain: String,
    pub when_to_use: String,
}

/// A filesystem index of `SKILL.md` playbooks under a root directory.
pub struct SkillIndex {
    root: PathBuf,
    records: Vec<(SkillRecord, PathBuf)>,
}

impl SkillIndex {
    /// Load and index every `*.md` skill under `root`. A non-existent root simply
    /// yields an empty index (the graceful "no corpus" case).
    pub fn load(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        let mut files = Vec::new();
        walk(&root, &mut files);

        let mut records = Vec::new();
        for path in files {
            if let Ok(text) = fs::read_to_string(&path) {
                let fm = parse_frontmatter(&text);
                let rel = path.strip_prefix(&root).unwrap_or(&path);
                let id = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
                let slug = slug_for(&path);
                let name = fm.get("name").cloned().unwrap_or_else(|| slug.clone());
                records.push((
                    SkillRecord {
                        id,
                        slug,
                        name,
                        description: fm.get("description").cloned().unwrap_or_default(),
                        subdomain: fm.get("subdomain").cloned().unwrap_or_default(),
                        when_to_use: fm.get("when_to_use").cloned().unwrap_or_default(),
                    },
                    path,
                ));
            }
        }
        records.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        SkillIndex { root, records }
    }

    pub fn all(&self) -> Vec<&SkillRecord> {
        self.records.iter().map(|(r, _)| r).collect()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Search skills by free-text `query` (matched against name/description/
    /// when_to_use/slug), optionally filtered to a `subdomain`. Ranked by a
    /// simple relevance (name hits first). Empty query returns all (filtered).
    pub fn find(&self, query: &str, subdomain: Option<&str>, limit: usize) -> Vec<&SkillRecord> {
        let q = query.to_lowercase();
        let mut scored: Vec<(u8, &SkillRecord)> = self
            .records
            .iter()
            .map(|(r, _)| r)
            .filter(|r| subdomain.map(|s| r.subdomain.eq_ignore_ascii_case(s)).unwrap_or(true))
            .filter_map(|r| {
                if q.is_empty() {
                    return Some((1, r));
                }
                let score = if r.name.to_lowercase().contains(&q) || r.slug.to_lowercase().contains(&q) {
                    3
                } else if r.when_to_use.to_lowercase().contains(&q) {
                    2
                } else if r.description.to_lowercase().contains(&q) {
                    1
                } else {
                    0
                };
                (score > 0).then_some((score, r))
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.id.cmp(&b.1.id)));
        scored.into_iter().take(limit).map(|(_, r)| r).collect()
    }

    /// Load a skill's full body by id, slug, or name (in that resolution order).
    pub fn load_skill(&self, id_or_slug: &str) -> Option<String> {
        let key = id_or_slug.trim();
        let hit = self
            .records
            .iter()
            .find(|(r, _)| r.id == key)
            .or_else(|| self.records.iter().find(|(r, _)| r.slug == key))
            .or_else(|| self.records.iter().find(|(r, _)| r.name.eq_ignore_ascii_case(key)));
        hit.and_then(|(_, path)| fs::read_to_string(path).ok())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("md") {
            out.push(path);
        }
    }
}

fn slug_for(path: &Path) -> String {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if stem.eq_ignore_ascii_case("SKILL") {
        path.parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or(stem)
            .to_string()
    } else {
        stem.to_string()
    }
}

/// Extract the fields we care about from a `---`-fenced YAML frontmatter block.
/// A small purpose-built parser (no YAML dep): handles top-level `key: value`
/// and one level of nesting under `metadata:`.
fn parse_frontmatter(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let trimmed = text.trim_start();
    if !trimmed.starts_with("---") {
        return map;
    }
    // Body between the first two `---` fences.
    let after = &trimmed[3..];
    let end = match after.find("\n---") {
        Some(i) => i,
        None => return map,
    };
    let block = &after[..end];

    let wanted = ["name", "description", "subdomain", "when_to_use"];
    for line in block.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            if wanted.contains(&key) {
                let val = v.trim().trim_matches('"').trim_matches('\'').trim();
                if !val.is_empty() {
                    map.entry(key.to_string()).or_insert_with(|| val.to_string());
                }
            }
        }
    }
    map
}

// ===========================================================================
// skills_find — search SKILL.md playbooks by query and/or subdomain
// ===========================================================================

/// Search the `SKILL.md` playbook corpus by free-text query and/or subdomain.
pub struct SkillsFindTool;

#[async_trait]
impl Tool for SkillsFindTool {
    fn name(&self) -> &str {
        "skills_find"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "skills_find".into(),
            description: "Search the SKILL.md playbook corpus by free-text `query` (matched against \
                a skill's name/description/when_to_use/slug) and/or a `subdomain` filter. Ranked by \
                relevance (name hits first); an empty query returns the whole (filtered) corpus up to \
                `limit`. Returns lightweight records (id, slug, name, description, subdomain, \
                when_to_use) — call skills_load with an id/slug/name to read the full playbook. The \
                corpus lives in DECIBEL_SKILLS_DIR or the workspace `skills/` dir; if absent, returns \
                an empty result."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Free-text query (optional; empty returns all)." },
                    "subdomain": { "type": "string", "description": "Optional subdomain filter (e.g. reconnaissance, web-exploitation)." },
                    "limit": { "type": "integer", "description": "Max matches to return (default 20)." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let query = arg_str_opt(&arguments, "query").unwrap_or_default();
        let subdomain = arg_str_opt(&arguments, "subdomain");
        let limit = arg_u64_opt(&arguments, "limit").unwrap_or(DEFAULT_FIND_LIMIT) as usize;

        let dir = skills_dir(ctx);
        let idx = SkillIndex::load(&dir);
        let available = !idx.is_empty();
        let matches: Vec<SkillRecord> = idx
            .find(&query, subdomain.as_deref(), limit)
            .into_iter()
            .cloned()
            .collect();
        let skills_val = to_value(&matches)?;
        Ok(json!({
            "query": query,
            "subdomain": subdomain,
            "available": available,
            "count": matches.len(),
            "skills": skills_val,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let count = value.get("count").and_then(Value::as_u64).unwrap_or(0);
        let available = value.get("available").and_then(Value::as_bool).unwrap_or(true);
        if count == 0 {
            let why = if available { "no matching skills" } else { "no skills available (corpus absent or empty)" };
            return vec![ContentBlock::text(format!("skills_find: {why}"))];
        }
        let empty = Vec::new();
        let skills = value.get("skills").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("skills_find: {count} match(es)");
        for s in skills.iter().take(25) {
            let slug = s.get("slug").and_then(Value::as_str).unwrap_or("");
            let name = s.get("name").and_then(Value::as_str).unwrap_or("");
            let subdomain = s.get("subdomain").and_then(Value::as_str).unwrap_or("");
            let sd = if subdomain.is_empty() { String::new() } else { format!(" ({subdomain})") };
            out.push_str(&format!("\n  - [{slug}] {name}{sd}"));
        }
        vec![ContentBlock::text(out)]
    }
}

// ===========================================================================
// skills_load — load a skill playbook's full body by id / slug / name
// ===========================================================================

/// Load a `SKILL.md` playbook's full untruncated body by its id, slug, or name.
pub struct SkillsLoadTool;

#[async_trait]
impl Tool for SkillsLoadTool {
    fn name(&self) -> &str {
        "skills_load"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "skills_load".into(),
            description: "Load a SKILL.md playbook's full, untruncated body. Identify it by `name` — \
                which may be the virtual id (e.g. /recon/nmap/SKILL.md), the slug (e.g. nmap), or the \
                skill's frontmatter name (e.g. \"Nmap Service Scan\"), resolved in that order. Use \
                skills_find first to discover ids/slugs. If the corpus is absent/empty, returns a \
                `found: false` result rather than erroring; a present corpus that lacks the name \
                errors so you can correct it."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Skill id, slug, or frontmatter name." }
                },
                "required": ["name"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let name = arg_str(&arguments, "name")?;
        let dir = skills_dir(ctx);
        let idx = SkillIndex::load(&dir);

        // Absent / empty corpus is the graceful "there are no skills" case — never
        // an error, so the model can degrade rather than abort.
        if idx.is_empty() {
            return Ok(json!({
                "query": name,
                "available": false,
                "found": false,
                "skill": null,
                "note": "no skills available (skills directory absent or empty)",
            }));
        }
        // A present corpus that lacks the name mirrors the upstream dispatcher's
        // `Err("skill not found")`, so the model learns to fix the identifier.
        match idx.load_skill(&name) {
            Some(body) => Ok(json!({
                "query": name,
                "available": true,
                "found": true,
                "skill": body,
            })),
            None => Err(ToolError::execution(format!("skill not found: `{name}`"))),
        }
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let found = value.get("found").and_then(Value::as_bool).unwrap_or(false);
        if !found {
            let note = value.get("note").and_then(Value::as_str).unwrap_or("skill not found");
            let query = value.get("query").and_then(Value::as_str).unwrap_or("");
            return vec![ContentBlock::text(format!("skills_load `{query}`: {note}"))];
        }
        let body = value.get("skill").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(body.to_string())]
    }
}

// ===========================================================================
// Tests — the vendored loader unit tests (paths fixed to unique temp dirs) plus
// tool-level tests driving each tool through a ToolRegistry.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;
    use decibel_tools::{ToolCall, ToolRegistry};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    const NMAP_SKILL: &str = "---\nname: Nmap Service Scan\ndescription: Enumerate open ports and service versions\nmetadata:\n  subdomain: reconnaissance\n  when_to_use: port scan, service discovery, enumeration\n---\n# Nmap\nRun nmap -sV against the target.\n";
    const SQLI_SKILL: &str = "---\nname: SQL Injection\ndescription: Detect and exploit SQL injection\nmetadata:\n  subdomain: web-exploitation\n  when_to_use: sqli, database, injection\n---\n# SQLi\nTry sqlmap.\n";

    fn write_skill(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    /// A fresh, unique temp dir (avoids the source fixture's cross-test race on a
    /// per-pid path).
    fn unique_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("dcb-skills-{tag}-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// A skills-root fixture with the two sample playbooks.
    fn fixture() -> PathBuf {
        let dir = unique_dir("idx");
        write_skill(&dir, "recon/nmap/SKILL.md", NMAP_SKILL);
        write_skill(&dir, "web/sqli/SKILL.md", SQLI_SKILL);
        dir
    }

    // ---- Vendored loader unit tests (from decepticon-skills). ----

    #[test]
    fn indexes_frontmatter_and_slugs() {
        let idx = SkillIndex::load(fixture());
        assert_eq!(idx.len(), 2);
        let nmap = idx.all().iter().find(|r| r.slug == "nmap").cloned().unwrap();
        assert_eq!(nmap.name, "Nmap Service Scan");
        assert_eq!(nmap.subdomain, "reconnaissance");
        assert_eq!(nmap.id, "/recon/nmap/SKILL.md");
        assert!(nmap.when_to_use.contains("service discovery"));
    }

    #[test]
    fn find_matches_and_ranks() {
        let idx = SkillIndex::load(fixture());
        let hits = idx.find("sql", None, 10);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].slug, "sqli");

        // when_to_use keyword hit.
        let hits2 = idx.find("enumeration", None, 10);
        assert_eq!(hits2[0].slug, "nmap");

        // subdomain filter.
        let web = idx.find("", Some("web-exploitation"), 10);
        assert_eq!(web.len(), 1);
        assert_eq!(web[0].slug, "sqli");
    }

    #[test]
    fn load_by_slug_id_and_name() {
        let idx = SkillIndex::load(fixture());
        assert!(idx.load_skill("nmap").unwrap().contains("nmap -sV"));
        assert!(idx.load_skill("/web/sqli/SKILL.md").unwrap().contains("sqlmap"));
        assert!(idx.load_skill("SQL Injection").unwrap().contains("SQLi"));
        assert!(idx.load_skill("does-not-exist").is_none());
    }

    #[test]
    fn absent_root_is_empty_not_an_error() {
        let idx = SkillIndex::load(unique_dir("absent").join("nope"));
        assert!(idx.is_empty());
        assert!(idx.find("anything", None, 10).is_empty());
        assert!(idx.load_skill("anything").is_none());
    }

    // ---- Tool-level tests through a ToolRegistry. ----

    /// A registry with both skills tools.
    fn registry() -> ToolRegistry {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(SkillsFindTool));
        reg.register(Arc::new(SkillsLoadTool));
        reg
    }

    async fn call(reg: &ToolRegistry, name: &str, args: Value, ctx: &ExecCtx) -> decibel_tools::ToolResult {
        reg.execute(
            ToolCall { call_id: CallId::from("c1"), name: name.into(), arguments: args },
            ctx,
        )
        .await
    }

    /// An `ExecCtx` whose cwd is the parent of a `skills/` corpus, so
    /// `ctx.resolve("skills")` lands on the fixture. Guards against a stray
    /// `DECIBEL_SKILLS_DIR` in the test environment overriding it.
    fn ctx_with_corpus() -> ExecCtx {
        // Ensure the env override is not in play so the workspace-relative dir wins.
        std::env::remove_var(SKILLS_DIR_ENV);
        let root = unique_dir("ws");
        let skills = root.join("skills");
        write_skill(&skills, "recon/nmap/SKILL.md", NMAP_SKILL);
        write_skill(&skills, "web/sqli/SKILL.md", SQLI_SKILL);
        ExecCtx::new().with_cwd(root)
    }

    #[tokio::test]
    async fn find_then_load_over_workspace_corpus() {
        let reg = registry();
        let ctx = ctx_with_corpus();

        // Free-text find ranks the sql skill first for "sql".
        let f = call(&reg, "skills_find", json!({ "query": "sql" }), &ctx).await;
        assert!(!f.is_error, "skills_find failed: {:?}", f.content);
        let fv = f.value.unwrap();
        assert_eq!(fv["available"], true);
        assert_eq!(fv["count"], 1);
        assert_eq!(fv["skills"][0]["slug"], "sqli");

        // Empty query + subdomain filter returns just the recon skill.
        let f2 = call(&reg, "skills_find", json!({ "subdomain": "reconnaissance" }), &ctx).await;
        let f2v = f2.value.unwrap();
        assert_eq!(f2v["count"], 1);
        assert_eq!(f2v["skills"][0]["slug"], "nmap");

        // Load by slug returns the full body.
        let l = call(&reg, "skills_load", json!({ "name": "nmap" }), &ctx).await;
        assert!(!l.is_error, "skills_load failed: {:?}", l.content);
        let lv = l.value.unwrap();
        assert_eq!(lv["found"], true);
        assert!(lv["skill"].as_str().unwrap().contains("nmap -sV"));

        // Load by frontmatter name and by virtual id also resolve.
        let byname = call(&reg, "skills_load", json!({ "name": "SQL Injection" }), &ctx).await;
        assert!(byname.value.unwrap()["skill"].as_str().unwrap().contains("SQLi"));
        let byid = call(&reg, "skills_load", json!({ "name": "/web/sqli/SKILL.md" }), &ctx).await;
        assert!(byid.value.unwrap()["skill"].as_str().unwrap().contains("sqlmap"));

        // A present corpus that lacks the name errors (dispatcher fidelity).
        let miss = call(&reg, "skills_load", json!({ "name": "no-such-skill" }), &ctx).await;
        assert!(miss.is_error);
        assert_eq!(miss.error_code.as_deref(), Some("EXEC_ERROR"));
    }

    #[tokio::test]
    async fn absent_corpus_is_graceful() {
        std::env::remove_var(SKILLS_DIR_ENV);
        let reg = registry();
        // cwd has no `skills/` subdir → the corpus is absent.
        let ctx = ExecCtx::new().with_cwd(unique_dir("empty-ws"));

        let f = call(&reg, "skills_find", json!({ "query": "anything" }), &ctx).await;
        assert!(!f.is_error, "skills_find must not error on an absent corpus");
        let fv = f.value.unwrap();
        assert_eq!(fv["available"], false);
        assert_eq!(fv["count"], 0);
        assert_eq!(fv["skills"].as_array().unwrap().len(), 0);

        // skills_load is graceful (found:false), NOT an error, when the corpus is absent.
        let l = call(&reg, "skills_load", json!({ "name": "nmap" }), &ctx).await;
        assert!(!l.is_error, "skills_load must not error on an absent corpus");
        let lv = l.value.unwrap();
        assert_eq!(lv["found"], false);
        assert_eq!(lv["available"], false);
        assert!(lv["skill"].is_null());
    }

    #[tokio::test]
    async fn missing_required_arg_is_invalid_args() {
        let reg = registry();
        let ctx = ExecCtx::new();
        let r = call(&reg, "skills_load", json!({}), &ctx).await; // no name
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
