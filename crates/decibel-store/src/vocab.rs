//! Knowledge-graph vocabulary — the recognized node and edge kinds (ported from
//! upstream `decepticon_core/types/kg.py`), including the AD/ADCS and Solidity
//! sets. `kind` stays a free `TEXT` column (no DB CHECK, to keep ingest forgiving
//! and migrations cheap), so these are the *documented* vocabulary the tools and
//! analyses reason over — not a hard constraint. `known_node`/`known_edge` let a
//! tool warn on an out-of-vocabulary kind without rejecting it.

/// Node kinds. PascalCase, matching the graph's existing convention.
pub const NODE_KINDS: &[&str] = &[
    // Infra / recon.
    "Host", "Service", "Entrypoint", "URL", "Technology", "Port",
    // Findings / intel.
    "Vulnerability", "CVE", "Finding", "CrownJewel", "Credential", "Secret",
    // Vuln-research pipeline.
    "Candidate", "Hypothesis", "Patch", "AttackPath",
    // Active Directory / ADCS.
    "ADUser", "ADComputer", "ADGroup", "ADDomain", "ADOU", "ADGPO",
    "ADCertTemplate", "ADCertAuthority", "ADDomainController",
    // Solidity / EVM.
    "Contract", "Function", "StateVar", "Modifier", "Event",
];

/// Edge kinds. UPPER_SNAKE_CASE. The attack-traversable subset lives in
/// `crate::chain::ATTACK_RELS`; this is the full recognized set (adds structural
/// and AD-object rels that are not themselves attack steps).
pub const EDGE_KINDS: &[&str] = &[
    // Attack progression.
    "EXPLOITS", "ENABLES", "LEAKS", "LEADS_TO", "PIVOTS_TO", "ESCALATES_TO",
    "HAS_VULN", "CAN_ACCESS", "ADMIN_TO",
    // Structure.
    "RESOLVES_TO", "RUNS", "EXPOSES", "USES", "HAS_CVE", "HAS_FINDING",
    // AttackPath materialization (promote_chain) — structural, not attack-traversable.
    "STARTS_AT", "REACHES", "STEP",
    // Credential / session.
    "AUTHENTICATES_TO", "HAS_SESSION", "MEMBER_OF", "CAN_RDP", "CAN_PSREMOTE",
    // AD object control.
    "GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER", "OWNS",
    "FORCE_CHANGE_PASSWORD", "ADD_MEMBER", "ADD_KEY_CREDENTIAL_LINK",
    "ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT", "CONTAINS", "GP_LINK",
    // AD/DC attacks.
    "DCSYNC", "READ_LAPS_PASSWORD", "READ_GMSA_PASSWORD", "GOLDEN_CERT", "SYNC_LAPS",
    // ADCS ESC1–ESC16.
    "ADCS_ESC1", "ADCS_ESC2", "ADCS_ESC3", "ADCS_ESC4", "ADCS_ESC5", "ADCS_ESC6",
    "ADCS_ESC7", "ADCS_ESC8", "ADCS_ESC9", "ADCS_ESC10", "ADCS_ESC11", "ADCS_ESC12",
    "ADCS_ESC13", "ADCS_ESC14", "ADCS_ESC15", "ADCS_ESC16",
    // Solidity.
    "CALLS", "READS", "WRITES", "HAS_FUNCTION", "HAS_MODIFIER",
];

/// Whether `kind` is a recognized node kind (case-sensitive PascalCase).
pub fn known_node(kind: &str) -> bool {
    NODE_KINDS.contains(&kind)
}

/// Whether `kind` is a recognized edge kind (case-sensitive UPPER_SNAKE).
pub fn known_edge(kind: &str) -> bool {
    EDGE_KINDS.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocabularies_are_unique_and_cover_ad_adcs() {
        use std::collections::BTreeSet;
        let n: BTreeSet<_> = NODE_KINDS.iter().collect();
        assert_eq!(n.len(), NODE_KINDS.len(), "duplicate node kind");
        let e: BTreeSet<_> = EDGE_KINDS.iter().collect();
        assert_eq!(e.len(), EDGE_KINDS.len(), "duplicate edge kind");
        // AD/ADCS present on both sides.
        assert!(known_node("ADCertTemplate"));
        assert!(known_node("ADUser"));
        assert!(known_edge("DCSYNC"));
        assert!(known_edge("ADCS_ESC1") && known_edge("ADCS_ESC16"));
        assert!(known_edge("AUTHENTICATES_TO"));
        // Solidity present.
        assert!(known_node("Contract") && known_edge("CALLS"));
        // Unknowns are not falsely recognized.
        assert!(!known_edge("NOT_A_REL") && !known_node("Nope"));
    }

    #[test]
    fn every_attack_rel_is_a_known_edge() {
        for r in crate::chain::ATTACK_RELS {
            assert!(known_edge(r), "attack rel {r} missing from EDGE_KINDS vocab");
        }
    }
}
