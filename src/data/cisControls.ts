// CIS Controls v8 — the 18 top-level controls. Each entry lists the
// representative safeguard IDs we map to from NIST 800-53. Used by
// the SSP engine to produce a cross-framework view.

export interface CisControlV8 {
  id: string;
  name: string;
  description: string;
  safeguards: { id: string; description: string; ig: 1 | 2 | 3 }[];
}

export const CIS_CONTROLS_V8: CisControlV8[] = [
  {
    id: '1',
    name: 'Inventory and Control of Enterprise Assets',
    description: 'Actively manage all enterprise assets connected to infrastructure.',
    safeguards: [
      { id: '1.1', description: 'Establish and maintain detailed enterprise asset inventory', ig: 1 },
      { id: '1.2', description: 'Address unauthorized assets', ig: 1 }
    ]
  },
  {
    id: '2',
    name: 'Inventory and Control of Software Assets',
    description: 'Actively manage all software on the network.',
    safeguards: [
      { id: '2.1', description: 'Establish and maintain a software inventory', ig: 1 },
      { id: '2.6', description: 'Allowlist authorized libraries', ig: 2 }
    ]
  },
  {
    id: '3',
    name: 'Data Protection',
    description: 'Identify, classify, and securely handle data throughout its lifecycle.',
    safeguards: [
      { id: '3.3', description: 'Configure data access control lists', ig: 1 },
      { id: '3.6', description: 'Encrypt data on end-user devices', ig: 1 },
      { id: '3.10', description: 'Encrypt sensitive data in transit', ig: 2 },
      { id: '3.11', description: 'Encrypt sensitive data at rest', ig: 2 }
    ]
  },
  {
    id: '4',
    name: 'Secure Configuration of Enterprise Assets and Software',
    description: 'Establish and maintain secure configuration for assets and software.',
    safeguards: [
      { id: '4.1', description: 'Establish and maintain secure configuration process', ig: 1 },
      { id: '4.2', description: 'Establish and maintain configuration for network infrastructure', ig: 1 },
      { id: '4.8', description: 'Uninstall or disable unnecessary services', ig: 2 }
    ]
  },
  {
    id: '5',
    name: 'Account Management',
    description: 'Use processes and tools to assign and manage authorization to credentials.',
    safeguards: [
      { id: '5.1', description: 'Establish and maintain an inventory of accounts', ig: 1 },
      { id: '5.2', description: 'Use unique passwords', ig: 1 },
      { id: '5.3', description: 'Disable dormant accounts', ig: 1 },
      { id: '5.4', description: 'Restrict administrator privileges to dedicated admin accounts', ig: 1 }
    ]
  },
  {
    id: '6',
    name: 'Access Control Management',
    description: 'Use processes to create, assign, manage, and revoke access credentials.',
    safeguards: [
      { id: '6.1', description: 'Establish access granting process', ig: 1 },
      { id: '6.2', description: 'Establish access revoking process', ig: 1 },
      { id: '6.3', description: 'Require MFA for externally exposed apps', ig: 1 },
      { id: '6.5', description: 'Require MFA for administrative access', ig: 1 },
      { id: '6.6', description: 'Establish and maintain an inventory of authentication systems', ig: 2 },
      { id: '6.7', description: 'Centralize access control', ig: 2 },
      { id: '6.8', description: 'Define and maintain role-based access control', ig: 3 }
    ]
  },
  {
    id: '7',
    name: 'Continuous Vulnerability Management',
    description: 'Develop a plan to continuously assess and track vulnerabilities.',
    safeguards: [
      { id: '7.1', description: 'Establish and maintain a vulnerability management process', ig: 1 },
      { id: '7.3', description: 'Perform automated OS patch management', ig: 1 },
      { id: '7.4', description: 'Perform automated application patch management', ig: 1 },
      { id: '7.5', description: 'Perform automated vulnerability scans of internal assets', ig: 2 },
      { id: '7.6', description: 'Perform automated vulnerability scans of externally exposed assets', ig: 2 },
      { id: '7.7', description: 'Remediate detected vulnerabilities', ig: 2 }
    ]
  },
  {
    id: '8',
    name: 'Audit Log Management',
    description: 'Collect, alert, review, and retain audit logs.',
    safeguards: [
      { id: '8.2', description: 'Collect audit logs', ig: 1 },
      { id: '8.5', description: 'Collect detailed audit logs', ig: 2 },
      { id: '8.10', description: 'Retain audit logs', ig: 2 },
      { id: '8.11', description: 'Conduct audit log reviews', ig: 2 }
    ]
  },
  {
    id: '9',
    name: 'Email and Web Browser Protections',
    description: 'Improve protections and detections of threats from email/web vectors.',
    safeguards: [
      { id: '9.1', description: 'Ensure use of only fully supported browsers', ig: 1 }
    ]
  },
  {
    id: '10',
    name: 'Malware Defenses',
    description: 'Prevent or control malware installation, spread, and execution.',
    safeguards: [
      { id: '10.1', description: 'Deploy and maintain anti-malware software', ig: 1 }
    ]
  },
  {
    id: '11',
    name: 'Data Recovery',
    description: 'Establish data recovery practices sufficient to restore in-scope data.',
    safeguards: [
      { id: '11.1', description: 'Establish and maintain data recovery process', ig: 1 },
      { id: '11.2', description: 'Perform automated backups', ig: 1 },
      { id: '11.3', description: 'Protect recovery data', ig: 1 },
      { id: '11.4', description: 'Establish and maintain isolated instance of recovery data', ig: 2 },
      { id: '11.5', description: 'Test data recovery', ig: 2 }
    ]
  },
  {
    id: '12',
    name: 'Network Infrastructure Management',
    description: 'Establish and maintain secure network infrastructure.',
    safeguards: [
      { id: '12.2', description: 'Establish and maintain a secure network architecture', ig: 2 },
      { id: '12.7', description: 'Ensure remote devices use VPN/Zero Trust access', ig: 2 }
    ]
  },
  {
    id: '13',
    name: 'Network Monitoring and Defense',
    description: 'Operate processes and tooling to comprehensively monitor and defend network.',
    safeguards: [
      { id: '13.1', description: 'Centralize security event alerting', ig: 2 },
      { id: '13.10', description: 'Perform application layer filtering', ig: 3 }
    ]
  },
  {
    id: '14',
    name: 'Security Awareness and Skills Training',
    description: 'Establish and maintain a security awareness program.',
    safeguards: [
      { id: '14.1', description: 'Establish and maintain a security awareness program', ig: 1 },
      { id: '14.9', description: 'Conduct role-specific security awareness training', ig: 2 }
    ]
  },
  {
    id: '15',
    name: 'Service Provider Management',
    description: 'Manage service providers holding sensitive data or critical IT platforms.',
    safeguards: [
      { id: '15.1', description: 'Establish and maintain an inventory of service providers', ig: 1 }
    ]
  },
  {
    id: '16',
    name: 'Application Software Security',
    description: 'Manage security of in-house, hosted, or acquired application software.',
    safeguards: [
      { id: '16.10', description: 'Apply secure design principles in application architectures', ig: 2 },
      { id: '16.11', description: 'Leverage vetted modules or services for application security components', ig: 2 },
      { id: '16.12', description: 'Implement code-level security checks', ig: 3 }
    ]
  },
  {
    id: '17',
    name: 'Incident Response Management',
    description: 'Establish a program to develop and maintain incident response capability.',
    safeguards: [
      { id: '17.1', description: 'Designate personnel to manage incident handling', ig: 1 },
      { id: '17.2', description: 'Establish and maintain contact information for reporting incidents', ig: 1 },
      { id: '17.4', description: 'Establish and maintain an incident response process', ig: 2 },
      { id: '17.5', description: 'Assign key roles and responsibilities', ig: 2 }
    ]
  },
  {
    id: '18',
    name: 'Penetration Testing',
    description: 'Test the effectiveness and resiliency of enterprise assets through penetration testing.',
    safeguards: [
      { id: '18.1', description: 'Establish and maintain a penetration testing program', ig: 2 }
    ]
  }
];

export function findCisSafeguard(id: string): { control: CisControlV8; description: string } | undefined {
  for (const c of CIS_CONTROLS_V8) {
    const sg = c.safeguards.find(s => s.id === id);
    if (sg) return { control: c, description: sg.description };
  }
  return undefined;
}
