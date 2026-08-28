// Findings report renderers. Generated frontend-side from the live `findings()`
// view (deduplicated, from both add_finding and record_finding), so an export
// reflects exactly what the drawer shows — in act and orchestrate mode alike.

import type { Finding } from './store'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
function sevRank(s: string): number {
  const i = SEV_ORDER.indexOf(s.toLowerCase())
  return i === -1 ? 99 : i
}

/** A CISO-readable executive report in Markdown. */
export function findingsToMarkdown(findings: Finding[]): string {
  const counts: Record<string, number> = {}
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1

  const out: string[] = ['# Engagement Findings', '']
  out.push(`**${findings.length}** finding${findings.length === 1 ? '' : 's'} recorded.`, '')
  if (findings.length) {
    out.push('| Severity | Count |', '|---|---|')
    for (const s of SEV_ORDER) if (counts[s]) out.push(`| ${s} | ${counts[s]} |`)
    out.push('')
  }
  out.push('---', '')

  const sorted = [...findings].sort((a, b) => sevRank(a.severity) - sevRank(b.severity))
  for (const f of sorted) {
    out.push(`## [${f.severity.toUpperCase()}] ${f.title}`)
    if (f.target) out.push(`- **Target:** \`${f.target}\``)
    if (f.mitre) out.push(`- **MITRE ATT&CK:** ${f.mitre}`)
    out.push('')
    if (f.description) out.push(f.description, '')
  }
  return out.join('\n')
}

/** A valid SARIF 2.1.0 document (one rule + result per finding). */
export function findingsToSarif(findings: Finding[]): string {
  const level = (s: string) => {
    const v = s.toLowerCase()
    if (v === 'critical' || v === 'high') return 'error'
    if (v === 'medium' || v === 'low') return 'warning'
    return 'note'
  }
  const rules = findings.map((f, i) => ({
    id: `decibel-finding-${i + 1}`,
    name: f.title,
    shortDescription: { text: f.title },
    ...(f.description ? { fullDescription: { text: f.description } } : {}),
    ...(f.mitre ? { properties: { 'mitre-attack': f.mitre } } : {}),
  }))
  const results = findings.map((f, i) => ({
    ruleId: `decibel-finding-${i + 1}`,
    ruleIndex: i,
    level: level(f.severity),
    message: { text: f.description || f.title },
    ...(f.target
      ? { locations: [{ physicalLocation: { artifactLocation: { uri: f.target } } }] }
      : {}),
    properties: { severity: f.severity, ...(f.mitre ? { 'mitre-attack': f.mitre } : {}) },
  }))
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Decibel',
            informationUri: 'https://github.com/decibelzin/decibel-harness',
            rules,
          },
        },
        results,
      },
    ],
  }
  return JSON.stringify(sarif, null, 2)
}
