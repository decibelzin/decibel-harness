//! The Decibel offensive toolkit: the model-facing tools that make the harness
//! a red-team agent.
//!
//! Every tool implements [`decibel_tools::Tool`] (a canonical JSON value plus a
//! pure `render`), so the same facts drive the model, a replayed UI card, and a
//! future Code Mode. There is no sandbox — the shell and filesystem tools run
//! with the operator's full authority; the only withholding is secret-looking
//! env vars, kept out of spawned processes so a key never leaks into context.
//!
//! [`register_all`] installs the whole toolkit into a [`ToolRegistry`] and
//! returns the shared [`FindingStore`] the app reads to build a report.

pub mod findings;
pub mod fs;
pub mod http;
pub mod nmap;
pub mod proc;
pub mod search;
pub mod shell;
pub mod util;
// Ported Decepticon arsenal modules: offline analyzers + native recon.
pub mod arsenal;
pub mod cloud;
pub mod contracts;
pub mod cve;
pub mod evidence;
pub mod exec;
pub mod kg;
pub mod opplan;
pub mod planning;
pub mod refs;
pub mod reversing;
pub mod roe;
pub mod shield;
pub mod skills;
pub mod web;

use std::sync::Arc;

use decibel_tools::ToolRegistry;

pub use findings::{AddFindingTool, Finding, FindingStore};
pub use fs::{ReadFileTool, StrReplaceTool, WriteFileTool};
pub use http::HttpTool;
pub use nmap::NmapTool;
pub use search::{GlobTool, GrepTool};
pub use shell::ShellTool;
pub use web::tools::{
    CookieAuditTool, GraphqlPlanTool, JwtCrackTool, JwtForgeTool, JwtParseTool, OAuthAuditTool,
};
pub use arsenal::tools::{
    ContentDiscoveryTool, DnsSubdomainsTool, DnsTool, HttpProbeTool, PortScanTool, TlsInspectTool,
    WebCrawlTool,
};
pub use cloud::tools::{
    IamPolicyAuditTool, K8sAuditTool, MetadataEndpointsTool, S3BucketsFromTextTool, TfstateAuditTool,
    UserDataSecretsTool,
};
pub use refs::tools::{KillchainLookupTool, KillchainSuggestTool, PayloadSearchTool};
pub use reversing::tools::{
    BinIdentifyTool, BinPackerTool, BinRopTool, BinStringsTool, BinSymbolsReportTool,
};
pub use contracts::tools::{
    FoundryAccessTestTool, FoundryFlashloanTestTool, FoundryReentrancyTestTool, SolidityScanFileTool,
    SolidityScanTool,
};
pub use cve::tools::{CveByPackageTool, CveLookupTool};
pub use evidence::tools::{EvidenceAsciicastTool, EvidenceSealTool, EvidenceVerifyTool};
pub use roe::{Scope, ScopePolicy};
pub use shield::{ShieldPolicy, ShieldScanTool};
pub use exec::{
    BashInputTool, BashKillTool, BashOutputTool, BashStatusTool, BashTool, PocValidateTool,
};
pub use kg::{
    CredentialReachabilityTool, CvssScoreTool, ImpactAnalysisTool, KgEdgeTool, KgIngestTool,
    KgNeighborsTool, KgNodeTool, KgQueryTool, KgStatsTool, MarkCrownJewelTool, PlanChainsTool,
    PromoteChainTool, RecordFindingTool, ReportExecutiveTool, UnexploredSurfaceTool,
};
pub use opplan::{
    AddObjectiveTool, GetObjectiveTool, ListObjectivesTool, LoadOpplanTool, ObjectiveCollapseTool,
    ObjectiveExpandTool, UpdateObjectiveTool,
};
pub use planning::{CompleteEngagementPlanningTool, ValidatePlanDocTool};
pub use skills::{SkillsFindTool, SkillsLoadTool};

/// Every tool name the toolkit provides, in registration order.
pub const ALL_TOOLS: &[&str] = &[
    "shell", "nmap", "http", "read_file", "write_file", "str_replace", "glob", "grep", "add_finding",
    // Pure web/auth analyzers (offline, no deps) — ported from Decepticon's tools/web.
    "jwt_parse", "jwt_forge", "jwt_crack", "cookie_audit", "oauth_audit", "graphql_plan",
    // Pure cloud analyzers (offline) — Decepticon tools/cloud.
    "iam_policy_audit", "s3_buckets_from_text", "user_data_secrets", "k8s_audit", "tfstate_audit", "metadata_endpoints",
    // Binary reversing-triage (offline) — Decepticon tools/reversing.
    "bin_identify", "bin_strings", "bin_packer", "bin_rop", "bin_symbols_report",
    // Offline reference corpus — Decepticon tools/refs.
    "payload_search", "killchain_lookup", "killchain_suggest",
    // Native recon (network-reaching; RoE-gate later) — Decepticon arsenal.
    "port_scan", "http_probe", "web_crawl", "content_discovery", "tls_inspect", "dns", "dns_subdomains",
    // Smart-contract analyzers (offline) — Decepticon tools/contracts.
    "solidity_scan", "solidity_scan_file", "foundry_reentrancy_test", "foundry_access_test", "foundry_flashloan_test",
    // CVE intelligence (network) — Decepticon tools/cve.
    "cve_lookup", "cve_by_package",
    // Safety envelope tools — Decepticon evidence + shield.
    "evidence_seal", "evidence_verify", "evidence_asciicast", "shield_scan",
    // Execution plane — persistent shell sessions + PoC validation (decibel-executor).
    "bash", "bash_input", "bash_output", "bash_status", "bash_kill", "poc_validate",
    // Knowledge graph + chain planner + analyses + reporting (decibel-store).
    "kg_node", "kg_edge", "mark_crown_jewel", "kg_query", "kg_stats", "kg_neighbors", "kg_ingest",
    "plan_chains", "promote_chain", "impact_analysis", "unexplored_surface", "credential_reachability",
    "record_finding", "cvss_score", "report_executive",
    // OPPLAN objective tree (decibel-store).
    "add_objective", "update_objective", "get_objective", "list_objectives", "objective_expand",
    "objective_collapse", "load_opplan",
    // Engagement planning + skills corpus (Decepticon planning/skills).
    "complete_engagement_planning", "validate_plan_doc", "skills_find", "skills_load",
];

/// Register the named subset of the toolkit into `registry`, sharing `findings`
/// as the store `add_finding` records into. Unknown names are ignored, so a
/// specialist can name exactly the tools it should have. `add_finding` is only
/// installed when named.
pub fn register_named(registry: &mut ToolRegistry, names: &[&str], findings: &FindingStore) {
    // One shared session manager for the whole `bash*` family in this registry, so
    // a session opened by `bash` is visible to bash_output/bash_status/bash_kill.
    // Created unconditionally (cheap — an empty map) and used only by the bash arms.
    let sessions = Arc::new(decibel_executor::SessionManager::new("."));
    // One shared in-memory knowledge-graph store for the KG/OPPLAN tools in this
    // registry. The Tauri app will later hand in a file-backed, per-engagement Db
    // shared with the UI; an ephemeral in-memory graph keeps the toolkit
    // self-contained until then. `Db` is not Clone — share the inner Arc.
    let store = decibel_store::Db(Arc::new(std::sync::Mutex::new(decibel_store::open_memory())));
    for name in names {
        match *name {
            "shell" => registry.register(Arc::new(ShellTool)),
            "nmap" => registry.register(Arc::new(NmapTool)),
            "http" => registry.register(Arc::new(HttpTool)),
            "read_file" => registry.register(Arc::new(ReadFileTool)),
            "write_file" => registry.register(Arc::new(WriteFileTool)),
            "str_replace" => registry.register(Arc::new(StrReplaceTool)),
            "glob" => registry.register(Arc::new(GlobTool)),
            "grep" => registry.register(Arc::new(GrepTool)),
            "add_finding" => registry.register(Arc::new(AddFindingTool::new(findings.clone()))),
            "jwt_parse" => registry.register(Arc::new(JwtParseTool)),
            "jwt_forge" => registry.register(Arc::new(JwtForgeTool)),
            "jwt_crack" => registry.register(Arc::new(JwtCrackTool)),
            "cookie_audit" => registry.register(Arc::new(CookieAuditTool)),
            "oauth_audit" => registry.register(Arc::new(OAuthAuditTool)),
            "graphql_plan" => registry.register(Arc::new(GraphqlPlanTool)),
            "iam_policy_audit" => registry.register(Arc::new(IamPolicyAuditTool)),
            "s3_buckets_from_text" => registry.register(Arc::new(S3BucketsFromTextTool)),
            "user_data_secrets" => registry.register(Arc::new(UserDataSecretsTool)),
            "k8s_audit" => registry.register(Arc::new(K8sAuditTool)),
            "tfstate_audit" => registry.register(Arc::new(TfstateAuditTool)),
            "metadata_endpoints" => registry.register(Arc::new(MetadataEndpointsTool)),
            "bin_identify" => registry.register(Arc::new(BinIdentifyTool)),
            "bin_strings" => registry.register(Arc::new(BinStringsTool)),
            "bin_packer" => registry.register(Arc::new(BinPackerTool)),
            "bin_rop" => registry.register(Arc::new(BinRopTool)),
            "bin_symbols_report" => registry.register(Arc::new(BinSymbolsReportTool)),
            "payload_search" => registry.register(Arc::new(PayloadSearchTool)),
            "killchain_lookup" => registry.register(Arc::new(KillchainLookupTool)),
            "killchain_suggest" => registry.register(Arc::new(KillchainSuggestTool)),
            "port_scan" => registry.register(Arc::new(PortScanTool)),
            "http_probe" => registry.register(Arc::new(HttpProbeTool)),
            "web_crawl" => registry.register(Arc::new(WebCrawlTool)),
            "content_discovery" => registry.register(Arc::new(ContentDiscoveryTool)),
            "tls_inspect" => registry.register(Arc::new(TlsInspectTool)),
            "dns" => registry.register(Arc::new(DnsTool)),
            "dns_subdomains" => registry.register(Arc::new(DnsSubdomainsTool)),
            "solidity_scan" => registry.register(Arc::new(SolidityScanTool)),
            "solidity_scan_file" => registry.register(Arc::new(SolidityScanFileTool)),
            "foundry_reentrancy_test" => registry.register(Arc::new(FoundryReentrancyTestTool)),
            "foundry_access_test" => registry.register(Arc::new(FoundryAccessTestTool)),
            "foundry_flashloan_test" => registry.register(Arc::new(FoundryFlashloanTestTool)),
            "cve_lookup" => registry.register(Arc::new(CveLookupTool::new())),
            "cve_by_package" => registry.register(Arc::new(CveByPackageTool)),
            "evidence_seal" => registry.register(Arc::new(EvidenceSealTool)),
            "evidence_verify" => registry.register(Arc::new(EvidenceVerifyTool)),
            "evidence_asciicast" => registry.register(Arc::new(EvidenceAsciicastTool)),
            "shield_scan" => registry.register(Arc::new(ShieldScanTool)),
            "bash" => registry.register(Arc::new(BashTool::new(sessions.clone()))),
            "bash_input" => registry.register(Arc::new(BashInputTool::new(sessions.clone()))),
            "bash_output" => registry.register(Arc::new(BashOutputTool::new(sessions.clone()))),
            "bash_status" => registry.register(Arc::new(BashStatusTool::new(sessions.clone()))),
            "bash_kill" => registry.register(Arc::new(BashKillTool::new(sessions.clone()))),
            "poc_validate" => registry.register(Arc::new(PocValidateTool)),
            "kg_node" => registry.register(Arc::new(KgNodeTool::new(decibel_store::Db(store.0.clone())))),
            "kg_edge" => registry.register(Arc::new(KgEdgeTool::new(decibel_store::Db(store.0.clone())))),
            "mark_crown_jewel" => registry.register(Arc::new(MarkCrownJewelTool::new(decibel_store::Db(store.0.clone())))),
            "kg_query" => registry.register(Arc::new(KgQueryTool::new(decibel_store::Db(store.0.clone())))),
            "kg_stats" => registry.register(Arc::new(KgStatsTool::new(decibel_store::Db(store.0.clone())))),
            "kg_neighbors" => registry.register(Arc::new(KgNeighborsTool::new(decibel_store::Db(store.0.clone())))),
            "kg_ingest" => registry.register(Arc::new(KgIngestTool::new(decibel_store::Db(store.0.clone())))),
            "plan_chains" => registry.register(Arc::new(PlanChainsTool::new(decibel_store::Db(store.0.clone())))),
            "promote_chain" => registry.register(Arc::new(PromoteChainTool::new(decibel_store::Db(store.0.clone())))),
            "impact_analysis" => registry.register(Arc::new(ImpactAnalysisTool::new(decibel_store::Db(store.0.clone())))),
            "unexplored_surface" => registry.register(Arc::new(UnexploredSurfaceTool::new(decibel_store::Db(store.0.clone())))),
            "credential_reachability" => registry.register(Arc::new(CredentialReachabilityTool::new(decibel_store::Db(store.0.clone())))),
            "record_finding" => registry.register(Arc::new(RecordFindingTool::new(decibel_store::Db(store.0.clone())))),
            "cvss_score" => registry.register(Arc::new(CvssScoreTool::new(decibel_store::Db(store.0.clone())))),
            "report_executive" => registry.register(Arc::new(ReportExecutiveTool::new(decibel_store::Db(store.0.clone())))),
            "add_objective" => registry.register(Arc::new(AddObjectiveTool::new(decibel_store::Db(store.0.clone())))),
            "update_objective" => registry.register(Arc::new(UpdateObjectiveTool::new(decibel_store::Db(store.0.clone())))),
            "get_objective" => registry.register(Arc::new(GetObjectiveTool::new(decibel_store::Db(store.0.clone())))),
            "list_objectives" => registry.register(Arc::new(ListObjectivesTool::new(decibel_store::Db(store.0.clone())))),
            "objective_expand" => registry.register(Arc::new(ObjectiveExpandTool::new(decibel_store::Db(store.0.clone())))),
            "objective_collapse" => registry.register(Arc::new(ObjectiveCollapseTool::new(decibel_store::Db(store.0.clone())))),
            "load_opplan" => registry.register(Arc::new(LoadOpplanTool::new(decibel_store::Db(store.0.clone())))),
            "complete_engagement_planning" => registry.register(Arc::new(CompleteEngagementPlanningTool)),
            "validate_plan_doc" => registry.register(Arc::new(ValidatePlanDocTool)),
            "skills_find" => registry.register(Arc::new(SkillsFindTool)),
            "skills_load" => registry.register(Arc::new(SkillsLoadTool)),
            _ => None,
        };
    }
}

/// Register the complete offensive toolkit into `registry` and return the
/// shared finding store the tools record into.
///
/// Tools installed: every name in [`ALL_TOOLS`] — the core toolkit
/// (`shell`, `nmap`, `http`, `read_file`, `write_file`, `str_replace`, `glob`,
/// `grep`, `add_finding`) plus the pure web/auth analyzers (`jwt_parse`,
/// `jwt_forge`, `jwt_crack`, `cookie_audit`, `oauth_audit`, `graphql_plan`).
pub fn register_all(registry: &mut ToolRegistry) -> FindingStore {
    let findings = FindingStore::new();
    register_named(registry, ALL_TOOLS, &findings);
    findings
}

/// Register the full toolkit plus the **safety envelope** for autonomous
/// operation on an authorized engagement:
/// - a prompt-injection **shield** ([`ShieldPolicy`], a post-policy) that frames
///   every tool's model-facing output as untrusted DATA (an injection hidden in a
///   scraped page or captured response becomes content to analyze, never
///   instructions to follow) — the canonical `value` a UI card reads is untouched;
/// - a Rules-of-Engagement **scope gate** ([`ScopePolicy`], a pre-policy) that
///   rejects a tool call whose target is outside `scope`. An empty (`None` or
///   ruleless) scope leaves the gate inert, so it is safe to install
///   unconditionally and only bites once the operator lists a target.
///
/// Returns the shared [`FindingStore`] like [`register_all`].
pub fn register_all_with_envelope(registry: &mut ToolRegistry, scope: Option<Scope>) -> FindingStore {
    let findings = register_all(registry);
    registry.add_post_policy(Arc::new(ShieldPolicy::default()));
    if let Some(scope) = scope {
        registry.add_pre_policy(Arc::new(ScopePolicy::new(scope)));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_all_installs_every_tool() {
        let mut registry = ToolRegistry::new();
        let _findings = register_all(&mut registry);
        let names: Vec<String> = registry.schemas().into_iter().map(|s| s.name).collect();
        for expected in ALL_TOOLS {
            assert!(names.contains(&expected.to_string()), "missing tool {expected}");
        }
        assert_eq!(names.len(), ALL_TOOLS.len());
    }
}
