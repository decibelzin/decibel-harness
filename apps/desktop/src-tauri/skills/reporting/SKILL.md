---
name: Findings & reporting
description: How to record a high-quality finding — severity, target, MITRE technique, reproducing evidence — and build the knowledge graph so analyses and the executive report have something to work with.
subdomain: reporting
when_to_use: Whenever you confirm a weakness and need to record it, or at the end of a phase/engagement when consolidating results into a report.
---

# Findings & reporting

A finding is only useful if it is **recorded, concrete, and reproducible**. Vague
"the site looks insecure" notes are worthless; "unauthenticated MariaDB 12.2.2 on
3306 — `mysql -h host -uroot` returns the `mysql` schema" is actionable.

## Record with `record_finding`, not just `add_finding`

`record_finding` writes into the persistent **knowledge graph** (survives across
turns, feeds `impact_analysis`, `plan_chains`, and the executive report). Prefer it.
Give every finding:

- **severity** — critical / high / medium / low / info, by real impact.
- **title** — specific and self-contained.
- **target** — `host:port` or the exact URL/param.
- **detail** — the reproducing evidence: the actual request/command and the response.
- a **MITRE ATT&CK** technique id where it fits (T1190, T1078, T1046, T1592, …).

Record **once** per distinct exposure. Do not re-record what another specialist
already recorded (check the delegation's `findings_added`) — duplicates pollute the
report.

## Build the graph

Use `kg_node` / `kg_edge` to capture hosts, services, credentials, and how they
connect; `mark_crown_jewel` for the high-value targets. A populated graph lets
`plan_chains` find attack paths and `credential_reachability` / `unexplored_surface`
guide the next phase. `kg_ingest` can absorb structured tool output (nmap, nuclei,
etc.) directly.

## Score and report

- `cvss_score` for a defensible severity from a CVSS vector.
- `report_executive` for a CISO-readable markdown summary at the end of a phase or the
  engagement — it stitches findings, graph stats, and attack chains for the engagement.

Finish an engagement by consolidating: confirm every concrete exposure is recorded,
then generate the executive report.
