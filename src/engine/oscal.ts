// OSCAL v1.1.2 System Security Plan generator. We emit a structural
// subset that FedRAMP / agency ingestion pipelines accept; we do not
// claim to be a full OSCAL producer (no XML, no profiles, no
// component-defs). The mapping is direct: ArbPackage.ssp →
// implemented-requirements; architecture components → system-implementation
// components; categorization → security-impact-level + system-information.

import { randomUUID } from 'crypto';
import { ArbPackage, Assessment, OscalSsp } from '../types/assessment';

const OSCAL_VERSION = '1.1.2';
const FEDRAMP_PROFILE_HREF = 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json';

function impactToOscal(level: string): string {
  return `fips-199-${level.toLowerCase()}`;
}

export function buildOscalSsp(a: Assessment, pkg: ArbPackage): OscalSsp {
  const ssp: OscalSsp = {
    uuid: randomUUID(),
    metadata: {
      title: `System Security Plan — ${a.business.applicationName}`,
      'last-modified': pkg.generatedAt,
      version: String(pkg.packageVersion),
      'oscal-version': OSCAL_VERSION,
      parties: [
        { uuid: randomUUID(), type: 'organization', name: 'System Owner' },
        { uuid: randomUUID(), type: 'organization', name: 'Assessor' }
      ]
    },
    'import-profile': { href: FEDRAMP_PROFILE_HREF },
    'system-characteristics': {
      'system-name': a.business.applicationName,
      description: a.business.businessProblem || 'See assessment for details.',
      'security-sensitivity-level': impactToOscal(pkg.categorization.overallCategorization),
      'system-information': {
        'information-types': pkg.categorization.informationTypes.map(it => ({
          uuid: randomUUID(),
          title: it.name,
          categorizations: [
            { system: 'https://doi.org/10.6028/NIST.SP.800-60v2r1', 'information-type-ids': [it.code] }
          ],
          'confidentiality-impact': { base: impactToOscal(it.confidentiality) },
          'integrity-impact': { base: impactToOscal(it.integrity) },
          'availability-impact': { base: impactToOscal(it.availability) }
        }))
      },
      'security-impact-level': {
        'security-objective-confidentiality': impactToOscal(pkg.categorization.confidentialityImpact),
        'security-objective-integrity': impactToOscal(pkg.categorization.integrityImpact),
        'security-objective-availability': impactToOscal(pkg.categorization.availabilityImpact)
      },
      status: { state: 'under-development' },
      'authorization-boundary': {
        description: `Authorization boundary includes the components named in the architecture diagram. ${pkg.architecture.components.length} components across ${new Set(pkg.architecture.components.map(c => c.layer)).size} architectural layers.`
      }
    },
    'system-implementation': {
      users: [
        { uuid: randomUUID(), title: 'System Administrator', 'role-ids': ['system-admin'] },
        { uuid: randomUUID(), title: 'End User', 'role-ids': ['end-user'] }
      ],
      components: pkg.architecture.components.map(c => ({
        uuid: randomUUID(),
        type: c.awsService ? 'service' : 'process',
        title: c.name,
        description: `${c.description} Layer: ${c.layer}; trust zone: ${c.trustZone}.`,
        status: { state: 'operational' }
      }))
    },
    'control-implementation': {
      description: `Tailored NIST 800-53 Rev 5 implementation for ${a.business.applicationName} at FIPS 199 ${pkg.categorization.overallCategorization}.`,
      'implemented-requirements': pkg.ssp.map(c => {
        const compUuid = randomUUID();
        return {
          uuid: randomUUID(),
          'control-id': c.id.toLowerCase().replace(/[^a-z0-9-]/g, '-'),
          statements: [{
            'statement-id': `${c.id.toLowerCase()}_smt`,
            uuid: randomUUID(),
            'by-components': [{
              'component-uuid': compUuid,
              uuid: randomUUID(),
              description: c.implementationStatement
            }]
          }],
          'responsible-roles': [{ 'role-id': roleIdFor(c.responsibleParty) }],
          remarks: `Inheritance: ${c.inheritance}. Status: ${c.implementationStatus}. CIS v8 mapping: ${c.cisMappings.join(', ') || 'n/a'}. Rationale: ${c.rationale}`
        };
      })
    }
  };
  return ssp;
}

function roleIdFor(party: string): string {
  return party.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}
