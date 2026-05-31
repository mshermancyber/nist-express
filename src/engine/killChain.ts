// Lockheed-Martin Cyber Kill Chain mapping for STRIDE findings.
// We pick the most-fit stage per STRIDE category + component layer.

import { StrideFinding, KillChainMapping } from '../types/assessment';

type Stage = KillChainMapping['stage'];

const MAP: Record<StrideFinding['category'], Stage> = {
  Spoofing:                  'Delivery',
  Tampering:                 'Exploitation',
  Repudiation:               'Actions on Objectives',
  'Information Disclosure':  'Actions on Objectives',
  'Denial of Service':       'Actions on Objectives',
  'Elevation of Privilege':  'Installation'
};

export function buildKillChainMappings(threats: StrideFinding[]): KillChainMapping[] {
  return threats.map((f, idx) => ({
    strideFindingIndex: idx,
    stage: MAP[f.category],
    rationale: `STRIDE ${f.category} on ${f.componentName} → ${MAP[f.category]} stage of the kill chain.`
  }));
}
