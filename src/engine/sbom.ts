// SBOM ingestion + VEX + CISA KEV intersection. Supports CycloneDX 1.4+
// JSON (preferred) and SPDX 2.x JSON. VEX statements may be inlined in
// CycloneDX or supplied separately. The output is structured for both
// the viewer and CSV export, and is reconciled against the architecture
// so the assessor can see which app-tier components have SBOM coverage.

import { Architecture, SbomAnalysis, SbomComponent, SbomVulnerability, VexStatement } from '../types/assessment';
import { CISA_KEV_CVES } from '../data/cisaKev';

type CycloneDxDoc = {
  bomFormat?: string;
  serialNumber?: string;
  components?: { name: string; version?: string; type?: string; purl?: string; licenses?: { license?: { id?: string; name?: string } }[] }[];
  vulnerabilities?: {
    id: string;
    ratings?: { score?: number; severity?: string }[];
    affects?: { ref: string }[];
    description?: string;
    analysis?: { state?: string; justification?: string; detail?: string };
  }[];
  metadata?: { component?: { name?: string } };
};

type SpdxDoc = {
  spdxVersion?: string;
  name?: string;
  packages?: { name: string; versionInfo?: string; downloadLocation?: string; externalRefs?: { referenceCategory?: string; referenceLocator?: string }[]; licenseConcluded?: string }[];
};

// Hard ceiling on SBOM document size — CycloneDX/SPDX docs for very
// large estates can hit tens of MB legitimately, but anything above
// this is almost certainly a DoS payload.
const MAX_SBOM_BYTES = 50 * 1024 * 1024;

function safeParseJson(content: string): unknown | null {
  if (content.length > MAX_SBOM_BYTES) return null;
  try { return JSON.parse(content); } catch { return null; }
}

export function detectSbomFormat(content: string): SbomAnalysis['format'] {
  const j = safeParseJson(content) as Record<string, unknown> | null;
  if (j && typeof j === 'object') {
    if ('bomFormat' in j && j['bomFormat'] === 'CycloneDX') return 'cyclonedx';
    if ('spdxVersion' in j || 'SPDXID' in j) return 'spdx';
  }
  return 'unknown';
}

function severityFromScore(score?: number, label?: string): SbomVulnerability['severity'] {
  if (label) {
    const l = label.toLowerCase();
    if (l.startsWith('crit')) return 'Critical';
    if (l === 'high') return 'High';
    if (l === 'medium' || l === 'moderate') return 'Medium';
    if (l === 'low') return 'Low';
  }
  if (typeof score === 'number') {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score > 0)    return 'Low';
  }
  return 'Unknown';
}

function vexFromState(s?: string): VexStatement['status'] {
  switch ((s || '').toLowerCase()) {
    case 'not_affected':
    case 'not affected':         return 'not_affected';
    case 'exploitable':
    case 'in_triage':
    case 'affected':             return 'affected';
    case 'resolved':
    case 'fixed':                return 'fixed';
    case 'investigating':
    case 'under_investigation':  return 'under_investigation';
    default:                     return 'under_investigation';
  }
}

function parseCycloneDx(j: CycloneDxDoc): { components: SbomComponent[]; vulnerabilities: SbomVulnerability[]; vex: VexStatement[]; docName: string } {
  const components: SbomComponent[] = (j.components ?? []).map(c => ({
    name: c.name,
    version: c.version ?? '',
    type: c.type,
    purl: c.purl,
    licenses: (c.licenses ?? []).map(l => l.license?.id || l.license?.name || '').filter(Boolean)
  }));
  const vulnerabilities: SbomVulnerability[] = [];
  const vex: VexStatement[] = [];
  for (const v of j.vulnerabilities ?? []) {
    const score = v.ratings?.[0]?.score;
    const sevLabel = v.ratings?.[0]?.severity;
    const affects = (v.affects ?? []).map(a => {
      // CycloneDX references look like "bom-ref/<...>" or component name
      const m = /^bom-ref\/(.+)$/.exec(a.ref) ?? /^(.+)$/.exec(a.ref);
      return m ? m[1] : a.ref;
    });
    vulnerabilities.push({
      id: v.id,
      cvssScore: score,
      severity: severityFromScore(score, sevLabel),
      affectsComponents: affects,
      description: v.description,
      kev: CISA_KEV_CVES.has(v.id)
    });
    if (v.analysis?.state) {
      vex.push({
        id: v.id,
        status: vexFromState(v.analysis.state),
        justification: v.analysis.justification,
        detail: v.analysis.detail
      });
    }
  }
  return { components, vulnerabilities, vex, docName: j.metadata?.component?.name ?? j.serialNumber ?? 'CycloneDX SBOM' };
}

function parseSpdx(j: SpdxDoc): { components: SbomComponent[]; vulnerabilities: SbomVulnerability[]; vex: VexStatement[]; docName: string } {
  const components: SbomComponent[] = (j.packages ?? []).map(p => {
    const purl = (p.externalRefs ?? []).find(r => r.referenceCategory === 'PACKAGE-MANAGER' || r.referenceCategory === 'PACKAGE_MANAGER')?.referenceLocator;
    return { name: p.name, version: p.versionInfo ?? '', purl, licenses: p.licenseConcluded ? [p.licenseConcluded] : [] };
  });
  // SPDX core does not embed vulnerabilities; expect a separate VEX file
  return { components, vulnerabilities: [], vex: [], docName: j.name ?? 'SPDX SBOM' };
}

function reconcileWithArchitecture(arch: Architecture, components: SbomComponent[]): string[] {
  // Heuristic: an architecture component "matches" the SBOM if its name
  // shares a token with a component name in the SBOM (e.g. an "ECS"
  // app whose image name appears in the SBOM). We surface the
  // architectural component ids that have any SBOM presence so the
  // viewer can highlight gaps.
  const sbomTokens = new Set(components.flatMap(c => c.name.toLowerCase().split(/[^a-z0-9]+/).filter(t => t.length >= 3)));
  return arch.components
    .filter(c => c.layer === 'app' || c.layer === 'integration')
    .filter(c => c.name.toLowerCase().split(/[^a-z0-9]+/).some(t => sbomTokens.has(t)))
    .map(c => c.id);
}

export function analyzeSbom(content: string, arch: Architecture, extraVex?: VexStatement[]): SbomAnalysis {
  const format = detectSbomFormat(content);
  let parsed: { components: SbomComponent[]; vulnerabilities: SbomVulnerability[]; vex: VexStatement[]; docName: string };
  const j = safeParseJson(content);
  if (j === null) {
    parsed = { components: [], vulnerabilities: [], vex: [], docName: content.length > MAX_SBOM_BYTES ? 'too-large' : 'unparseable' };
  } else if (format === 'cyclonedx') parsed = parseCycloneDx(j as CycloneDxDoc);
  else if (format === 'spdx') parsed = parseSpdx(j as SpdxDoc);
  else parsed = { components: [], vulnerabilities: [], vex: [], docName: 'unknown' };
  const vex = [...parsed.vex, ...(extraVex ?? [])];
  const kevHits = parsed.vulnerabilities.filter(v => v.kev);
  const affected = reconcileWithArchitecture(arch, parsed.components);
  const summary = `${parsed.components.length} components; ${parsed.vulnerabilities.length} vulnerabilities (${kevHits.length} on CISA KEV); ${vex.length} VEX statements; SBOM-mapped architecture components: ${affected.length}.`;
  return {
    format,
    documentName: parsed.docName,
    componentCount: parsed.components.length,
    components: parsed.components,
    vulnerabilities: parsed.vulnerabilities,
    vexStatements: vex,
    kevHits,
    affectedArchitectureComponents: affected,
    summary
  };
}
