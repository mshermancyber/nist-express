// Mermaid diagram generators for:
//   - Architecture diagram (component graph by layer)
//   - Security overlay (trust boundaries, encryption zones, auth flows)
//   - Data Flow Diagram (DFD — entities/processes/stores/flows)
//
// All diagrams render client-side via the Mermaid library loaded in
// public/view.html. Identifiers are sanitised to satisfy Mermaid's
// node-id grammar.

import { Architecture, ArchitectureComponent, DataFlow } from '../types/assessment';

function safeId(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9_]/g, '_');
}

function quote(label: string): string {
  return label.replace(/"/g, '\\"').replace(/\n/g, ' ');
}

function componentLabel(c: ArchitectureComponent): string {
  const svc = c.awsService ? `<br/><i>${c.awsService}</i>` : '';
  return `${c.name}${svc}`;
}

const LAYER_TITLE: Record<ArchitectureComponent['layer'], string> = {
  edge: 'Edge Tier',
  identity: 'Identity Tier',
  app: 'Application Tier',
  data: 'Data Tier',
  integration: 'Integration Tier',
  logging: 'Logging Tier',
  monitoring: 'Monitoring Tier',
  backup: 'Backup Tier',
  admin: 'Admin Tier'
};

const LAYER_ORDER: ArchitectureComponent['layer'][] = [
  'edge', 'identity', 'app', 'data', 'integration', 'logging', 'monitoring', 'backup', 'admin'
];

export function renderArchitectureMermaid(arch: Architecture): string {
  const lines: string[] = [];
  lines.push('flowchart LR');
  lines.push('  classDef edge fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#e2e8f0;');
  lines.push('  classDef identity fill:#1e293b,stroke:#a855f7,stroke-width:2px,color:#e2e8f0;');
  lines.push('  classDef app fill:#1e293b,stroke:#22c55e,stroke-width:2px,color:#e2e8f0;');
  lines.push('  classDef data fill:#1e293b,stroke:#f59e0b,stroke-width:2px,color:#e2e8f0;');
  lines.push('  classDef integration fill:#1e293b,stroke:#06b6d4,stroke-width:2px,color:#e2e8f0;');
  lines.push('  classDef logging fill:#1e293b,stroke:#94a3b8,stroke-width:2px,color:#e2e8f0;');
  lines.push('  classDef monitoring fill:#1e293b,stroke:#ec4899,stroke-width:2px,color:#e2e8f0;');
  lines.push('  classDef backup fill:#1e293b,stroke:#eab308,stroke-width:2px,color:#e2e8f0;');
  lines.push('  classDef admin fill:#1e293b,stroke:#ef4444,stroke-width:2px,color:#e2e8f0;');

  for (const layer of LAYER_ORDER) {
    const inLayer = arch.components.filter(c => c.layer === layer);
    if (inLayer.length === 0) continue;
    lines.push(`  subgraph ${safeId(layer)}["${LAYER_TITLE[layer]}"]`);
    lines.push('    direction TB');
    for (const c of inLayer) {
      lines.push(`    ${safeId(c.id)}["${quote(componentLabel(c))}"]:::${layer}`);
    }
    lines.push('  end');
  }

  for (const f of arch.flows) {
    const arrow = f.encrypted ? '-->' : '-.->';
    lines.push(`  ${safeId(f.fromComponentId)} ${arrow}|"${quote(f.label)}"| ${safeId(f.toComponentId)}`);
  }

  return lines.join('\n');
}

export function renderSecurityOverlayMermaid(arch: Architecture): string {
  const lines: string[] = [];
  lines.push('flowchart TB');
  lines.push('  classDef sensitive fill:#1e293b,stroke:#ef4444,stroke-width:3px,color:#fecaca;');
  lines.push('  classDef privileged fill:#1e293b,stroke:#f97316,stroke-width:3px,color:#fed7aa;');
  lines.push('  classDef boundary fill:#0b1220,stroke:#38bdf8,stroke-width:2px,color:#bae6fd;');
  lines.push('  classDef telemetry fill:#1e293b,stroke:#a78bfa,stroke-width:2px,color:#ddd6fe;');
  lines.push('  classDef standard fill:#1e293b,stroke:#64748b,stroke-width:1px,color:#cbd5e1;');

  // Subgraphs per trust boundary
  for (const tb of arch.trustBoundaries) {
    lines.push(`  subgraph ${safeId(tb.name)}["TRUST BOUNDARY: ${tb.name}"]`);
    lines.push('    direction TB');
    for (const cid of tb.componentIds) {
      const c = arch.components.find(x => x.id === cid);
      if (!c) continue;
      const cls = c.containsSensitiveData
        ? 'sensitive'
        : c.layer === 'admin' || c.layer === 'identity'
        ? 'privileged'
        : c.layer === 'logging' || c.layer === 'monitoring' || c.layer === 'backup'
        ? 'telemetry'
        : 'standard';
      const lock = c.encryptionAtRest && c.encryptionInTransit ? '🔒 ' : '';
      const star = c.containsSensitiveData ? '⚠ ' : '';
      lines.push(`    ${safeId(c.id)}["${lock}${star}${quote(c.name)}"]:::${cls}`);
    }
    lines.push('  end');
  }

  // Boundary-crossing flows highlighted
  for (const f of arch.flows) {
    if (!f.crossesTrustBoundary) continue;
    const label = `${f.label}${f.encrypted ? ' (encrypted)' : ' (CLEAR)'}${f.carriesSensitiveData ? ' [sensitive]' : ''}`;
    const arrow = f.encrypted ? '-->' : '==>';
    lines.push(`  ${safeId(f.fromComponentId)} ${arrow}|"${quote(label)}"| ${safeId(f.toComponentId)}`);
  }

  return lines.join('\n');
}

export function renderDataFlowMermaid(arch: Architecture): string {
  // Classic DFD: external entities (edge users + integrations) are
  // double-bordered, processes are circles, data stores are cylinders.
  // We map architecture layers onto these shapes so STRIDE per element
  // is unambiguous downstream.
  const lines: string[] = [];
  lines.push('flowchart LR');
  lines.push('  classDef ext fill:#0b1220,stroke:#38bdf8,stroke-width:3px,color:#bae6fd;');
  lines.push('  classDef proc fill:#1e293b,stroke:#22c55e,stroke-width:2px,color:#bbf7d0;');
  lines.push('  classDef store fill:#1e293b,stroke:#f59e0b,stroke-width:2px,color:#fde68a;');

  for (const c of arch.components) {
    const sid = safeId(c.id);
    const label = quote(c.name);
    if (c.id === 'users' || c.layer === 'integration') {
      lines.push(`  ${sid}[/"${label}"/]:::ext`);
    } else if (c.layer === 'data' || c.layer === 'logging' || c.layer === 'backup') {
      lines.push(`  ${sid}[("${label}")]:::store`);
    } else {
      lines.push(`  ${sid}(("${label}")):::proc`);
    }
  }

  for (const f of arch.flows as DataFlow[]) {
    const label = quote(`${f.label} [${f.protocol}]`);
    lines.push(`  ${safeId(f.fromComponentId)} -->|"${label}"| ${safeId(f.toComponentId)}`);
  }

  return lines.join('\n');
}
