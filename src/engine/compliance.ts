// Compliance Mapping Matrix. Cross-walks the NIST 800-53 controls
// the SSP includes to the other frameworks selected on the
// questionnaire. Coverage is marked Full / Partial / Gap based on
// whether at least one mapped control is present and whether the
// implementation status is in good standing.

import {
  Assessment, ComplianceMapping, SspControl, Compliance
} from '../types/assessment';
import { NIST_171_REQUIREMENTS } from '../data/nist171';

interface FrameworkMap {
  framework: Compliance;
  controls: {
    id: string;
    description: string;
    nistControls: string[]; // NIST 800-53 IDs that satisfy
  }[];
}

const FRAMEWORK_MAPS: FrameworkMap[] = [
  {
    framework: 'SOC2',
    controls: [
      { id: 'CC6.1', description: 'Logical access security – restriction', nistControls: ['AC-2', 'AC-3', 'IA-2', 'IA-5'] },
      { id: 'CC6.6', description: 'Boundary protection', nistControls: ['SC-7', 'SC-8'] },
      { id: 'CC6.7', description: 'Transmission of confidential information', nistControls: ['SC-8', 'SC-13'] },
      { id: 'CC6.8', description: 'Malicious code protection', nistControls: ['SI-2', 'SI-3', 'SI-7'] },
      { id: 'CC7.2', description: 'System monitoring', nistControls: ['SI-4', 'AU-6'] },
      { id: 'CC7.3', description: 'Incident response', nistControls: ['IR-4', 'IR-6'] },
      { id: 'A1.2', description: 'Recoverability', nistControls: ['CP-2', 'CP-9', 'CP-10'] }
    ]
  },
  {
    framework: 'ISO 27001',
    controls: [
      { id: 'A.5.15', description: 'Access control', nistControls: ['AC-2', 'AC-3', 'AC-6'] },
      { id: 'A.5.17', description: 'Authentication information', nistControls: ['IA-2', 'IA-5'] },
      { id: 'A.8.5', description: 'Secure authentication', nistControls: ['IA-2'] },
      { id: 'A.8.15', description: 'Logging', nistControls: ['AU-2', 'AU-3', 'AU-12'] },
      { id: 'A.8.16', description: 'Monitoring activities', nistControls: ['SI-4'] },
      { id: 'A.8.24', description: 'Use of cryptography', nistControls: ['SC-12', 'SC-13', 'SC-28'] },
      { id: 'A.5.30', description: 'ICT readiness for business continuity', nistControls: ['CP-2', 'CP-10'] }
    ]
  },
  {
    framework: 'PCI DSS',
    controls: [
      { id: 'Req 3', description: 'Protect stored cardholder data', nistControls: ['SC-28', 'SC-12'] },
      { id: 'Req 4', description: 'Encrypt CHD in transit', nistControls: ['SC-8', 'SC-13'] },
      { id: 'Req 7', description: 'Restrict access by business need', nistControls: ['AC-3', 'AC-6'] },
      { id: 'Req 8', description: 'Identify users and authenticate', nistControls: ['IA-2', 'IA-5'] },
      { id: 'Req 10', description: 'Log and monitor all access', nistControls: ['AU-2', 'AU-3', 'AU-6', 'AU-12'] },
      { id: 'Req 11', description: 'Test security regularly', nistControls: ['RA-5', 'SA-11'] }
    ]
  },
  {
    framework: 'HIPAA',
    controls: [
      { id: '164.308(a)(1)', description: 'Security Management Process', nistControls: ['RA-3', 'PM-9'] },
      { id: '164.308(a)(3)', description: 'Workforce security', nistControls: ['PS-3', 'AC-2'] },
      { id: '164.308(a)(4)', description: 'Information access management', nistControls: ['AC-3', 'AC-6'] },
      { id: '164.312(a)', description: 'Access control', nistControls: ['AC-3', 'IA-2'] },
      { id: '164.312(b)', description: 'Audit controls', nistControls: ['AU-2', 'AU-3', 'AU-12'] },
      { id: '164.312(e)', description: 'Transmission security', nistControls: ['SC-8', 'SC-13'] }
    ]
  },
  {
    framework: 'FedRAMP',
    controls: [
      // FedRAMP baselines map directly to NIST 800-53 — we surface the highest-leverage ones.
      { id: 'FedRAMP-AC', description: 'Access Control family', nistControls: ['AC-2', 'AC-3', 'AC-6', 'AC-17'] },
      { id: 'FedRAMP-AU', description: 'Audit and Accountability', nistControls: ['AU-2', 'AU-3', 'AU-6', 'AU-9', 'AU-12'] },
      { id: 'FedRAMP-CP', description: 'Contingency Planning', nistControls: ['CP-2', 'CP-9', 'CP-10'] },
      { id: 'FedRAMP-SC', description: 'System and Communications', nistControls: ['SC-7', 'SC-8', 'SC-12', 'SC-13', 'SC-28'] }
    ]
  },
  {
    framework: 'GDPR',
    controls: [
      { id: 'Art. 25', description: 'Data protection by design and by default', nistControls: ['SC-28', 'AC-6', 'CM-7'] },
      { id: 'Art. 32', description: 'Security of processing', nistControls: ['SC-8', 'SC-28', 'AU-2', 'IR-4'] },
      { id: 'Art. 33', description: 'Notification of breach', nistControls: ['IR-6'] }
    ]
  },
  {
    framework: 'CCPA',
    controls: [
      { id: 'CCPA-Sec', description: 'Reasonable security procedures', nistControls: ['SC-28', 'AC-3', 'AU-2'] },
      { id: 'CCPA-DSR', description: 'Consumer rights request handling', nistControls: ['AC-3', 'AU-2'] }
    ]
  },
  {
    framework: 'NIST 800-53',
    controls: [
      // Identity: this is the master framework — we still emit a meta row.
      { id: 'NIST-Self', description: 'NIST 800-53 Rev 5 baseline coverage', nistControls: ['AC-2', 'AU-2', 'SC-7', 'SI-4', 'CP-2'] }
    ]
  },
  {
    framework: 'Internal Policy Only',
    controls: [
      { id: 'Internal', description: 'Internal security policy compliance', nistControls: ['PM-9', 'PL-2'] }
    ]
  },
  {
    framework: 'NIST CSF 2.0',
    controls: [
      { id: 'GV.OC',  description: 'Govern — Organizational Context', nistControls: ['PM-9', 'PL-2'] },
      { id: 'GV.RM',  description: 'Govern — Risk Management Strategy', nistControls: ['PM-9', 'RA-3'] },
      { id: 'ID.AM',  description: 'Identify — Asset Management', nistControls: ['CM-8'] },
      { id: 'ID.RA',  description: 'Identify — Risk Assessment', nistControls: ['RA-3', 'RA-5'] },
      { id: 'PR.AA',  description: 'Protect — Identity Management and Access Control', nistControls: ['AC-2', 'AC-3', 'AC-6', 'IA-2', 'IA-5'] },
      { id: 'PR.DS',  description: 'Protect — Data Security', nistControls: ['SC-8', 'SC-12', 'SC-28'] },
      { id: 'PR.PS',  description: 'Protect — Platform Security', nistControls: ['CM-2', 'CM-6', 'SI-2'] },
      { id: 'DE.CM',  description: 'Detect — Continuous Monitoring', nistControls: ['AU-6', 'SI-4', 'CA-7'] },
      { id: 'DE.AE',  description: 'Detect — Adverse Event Analysis', nistControls: ['AU-6', 'IR-4'] },
      { id: 'RS.MA',  description: 'Respond — Incident Management', nistControls: ['IR-4', 'IR-6'] },
      { id: 'RC.RP',  description: 'Recover — Recovery Plan Execution', nistControls: ['CP-2', 'CP-10'] }
    ]
  },
  {
    framework: 'NIST AI RMF',
    controls: [
      { id: 'GOVERN-1', description: 'Govern AI risk policies and roles', nistControls: ['PM-9', 'PL-2'] },
      { id: 'MAP-2',    description: 'Map system context, intended use, and stakeholders', nistControls: ['PL-2'] },
      { id: 'MEASURE-2.7', description: 'Measure safety and security of the system', nistControls: ['SI-4', 'AU-6'] },
      { id: 'MANAGE-1', description: 'Manage AI risks: prioritization, treatment, validation', nistControls: ['RA-3', 'PM-9'] },
      { id: 'MEASURE-2.10', description: 'Measure security: pre-deployment + runtime evaluation', nistControls: ['CA-7', 'RA-5'] }
    ]
  },
  {
    framework: 'EU AI Act',
    controls: [
      { id: 'Art. 9',  description: 'Risk management system throughout the AI system lifecycle', nistControls: ['PM-9', 'RA-3'] },
      { id: 'Art. 10', description: 'Data and data governance for training, validation, and testing', nistControls: ['SC-28', 'AC-3'] },
      { id: 'Art. 12', description: 'Automatic recording of events (logs)', nistControls: ['AU-2', 'AU-3', 'AU-12'] },
      { id: 'Art. 13', description: 'Transparency and information to users', nistControls: ['PL-2'] },
      { id: 'Art. 14', description: 'Human oversight measures', nistControls: ['AC-3', 'PM-9'] },
      { id: 'Art. 15', description: 'Accuracy, robustness, and cybersecurity', nistControls: ['SI-2', 'SC-7', 'SI-4'] }
    ]
  },
  {
    framework: 'HITRUST CSF',
    controls: [
      { id: '01.x', description: 'Information Protection Program', nistControls: ['PM-9', 'PL-2'] },
      { id: '06.x', description: 'Configuration Management', nistControls: ['CM-2', 'CM-6', 'CM-8'] },
      { id: '07.x', description: 'Vulnerability Management', nistControls: ['RA-5', 'SI-2'] },
      { id: '09.x', description: 'Transmission Protection', nistControls: ['SC-8', 'SC-13'] },
      { id: '10.x', description: 'Password Management', nistControls: ['IA-5'] },
      { id: '11.x', description: 'Access Control', nistControls: ['AC-2', 'AC-3', 'AC-6'] },
      { id: '13.x', description: 'Incident Management', nistControls: ['IR-4', 'IR-6'] }
    ]
  },
  {
    framework: 'DORA',
    controls: [
      { id: 'Art. 5',  description: 'ICT risk management framework', nistControls: ['PM-9', 'RA-3'] },
      { id: 'Art. 8',  description: 'Protection and prevention measures', nistControls: ['SC-7', 'SC-8', 'SC-28'] },
      { id: 'Art. 10', description: 'Detection of anomalous activities', nistControls: ['SI-4', 'AU-6'] },
      { id: 'Art. 11', description: 'Response and recovery', nistControls: ['IR-4', 'CP-2', 'CP-10'] },
      { id: 'Art. 17', description: 'Major ICT incident reporting', nistControls: ['IR-6'] },
      { id: 'Art. 24', description: 'Digital operational resilience testing', nistControls: ['CA-7', 'RA-5'] }
    ]
  },
  {
    framework: 'FFIEC',
    controls: [
      { id: 'IS-1',  description: 'Information Security Program', nistControls: ['PM-9', 'PL-2'] },
      { id: 'IS-3',  description: 'Access Management', nistControls: ['AC-2', 'AC-3', 'IA-2'] },
      { id: 'IS-5',  description: 'Network Security', nistControls: ['SC-7'] },
      { id: 'IS-8',  description: 'Logging and Monitoring', nistControls: ['AU-2', 'SI-4'] },
      { id: 'BCP-1', description: 'Business Continuity Planning', nistControls: ['CP-2', 'CP-9', 'CP-10'] }
    ]
  },
  {
    framework: 'IRS Pub 1075',
    controls: [
      { id: '9.3.1.AC-2', description: 'Account Management — FTI access', nistControls: ['AC-2'] },
      { id: '9.3.7.AU-2', description: 'Auditable Events — FTI processing', nistControls: ['AU-2', 'AU-3', 'AU-12'] },
      { id: '9.3.13.IA-2', description: 'Identification & Authentication for FTI access', nistControls: ['IA-2', 'IA-5'] },
      { id: '9.3.17.SC-7', description: 'Boundary Protection of FTI', nistControls: ['SC-7'] },
      { id: '9.3.17.SC-28', description: 'Protection of FTI at Rest', nistControls: ['SC-28', 'SC-12'] }
    ]
  }
];

export function buildComplianceMappings(a: Assessment, ssp: SspControl[]): ComplianceMapping[] {
  const sspIds = new Set(ssp.map(s => s.id));
  const out: ComplianceMapping[] = [];
  for (const fm of FRAMEWORK_MAPS) {
    if (!a.compliance.frameworks.includes(fm.framework)) continue;
    for (const control of fm.controls) {
      const covered = control.nistControls.filter(id => sspIds.has(id));
      const coverage: ComplianceMapping['coverage'] = covered.length === control.nistControls.length
        ? 'Full'
        : covered.length > 0
        ? 'Partial'
        : 'Gap';
      out.push({
        framework: fm.framework,
        controlId: control.id,
        description: control.description,
        satisfiedByControlIds: covered,
        coverage
      });
    }
  }

  // NIST 800-171 + CMMC — emit the 110 CUI requirements when in scope.
  // CMMC L2 mirrors 800-171 r2 1:1, so we surface both.
  const want171 = a.compliance.frameworks.includes('NIST 800-171');
  const wantCmmc = a.compliance.frameworks.includes('CMMC');
  if (want171 || wantCmmc) {
    for (const req of NIST_171_REQUIREMENTS) {
      const covered = req.nist800_53.filter(id => sspIds.has(id));
      const coverage: ComplianceMapping['coverage'] = covered.length === req.nist800_53.length
        ? 'Full'
        : covered.length > 0
        ? 'Partial'
        : 'Gap';
      if (want171) {
        out.push({ framework: 'NIST 800-171', controlId: req.id, description: req.description, satisfiedByControlIds: covered, coverage });
      }
      if (wantCmmc) {
        out.push({ framework: 'CMMC', controlId: req.id, description: req.description, satisfiedByControlIds: covered, coverage });
      }
    }
  }

  return out;
}
