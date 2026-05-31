// NIST SP 800-171 Rev 2 — Protecting Controlled Unclassified
// Information in Nonfederal Systems. All 110 basic + derived
// requirements, each mapped to the 800-53 control(s) that satisfy
// them. Used by the compliance crosswalk so a CMMC / CUI assessment
// can be emitted against the same SSP.

export interface Nist171Requirement {
  id: string;            // 3.x.y.z
  family: string;        // 3.1 Access Control, 3.3 Audit, ...
  description: string;
  nist800_53: string[];  // Mapped Rev 5 control ids
}

export const NIST_171_FAMILIES: Record<string, string> = {
  '3.1':  'Access Control',
  '3.2':  'Awareness and Training',
  '3.3':  'Audit and Accountability',
  '3.4':  'Configuration Management',
  '3.5':  'Identification and Authentication',
  '3.6':  'Incident Response',
  '3.7':  'Maintenance',
  '3.8':  'Media Protection',
  '3.9':  'Personnel Security',
  '3.10': 'Physical Protection',
  '3.11': 'Risk Assessment',
  '3.12': 'Security Assessment',
  '3.13': 'System and Communications Protection',
  '3.14': 'System and Information Integrity'
};

function fam(id: string): string { return id.split('.').slice(0, 2).join('.'); }

export const NIST_171_REQUIREMENTS: Nist171Requirement[] = [
  // 3.1 Access Control (22 reqs)
  { id: '3.1.1', family: fam('3.1.1'), description: 'Limit system access to authorized users, processes acting on behalf of authorized users, and devices.', nist800_53: ['AC-2', 'AC-3', 'AC-17'] },
  { id: '3.1.2', family: fam('3.1.2'), description: 'Limit system access to the types of transactions and functions that authorized users are permitted to execute.', nist800_53: ['AC-2', 'AC-3'] },
  { id: '3.1.3', family: fam('3.1.3'), description: 'Control the flow of CUI in accordance with approved authorizations.', nist800_53: ['AC-4'] },
  { id: '3.1.4', family: fam('3.1.4'), description: 'Separate the duties of individuals to reduce the risk of malevolent activity without collusion.', nist800_53: ['AC-5'] },
  { id: '3.1.5', family: fam('3.1.5'), description: 'Employ the principle of least privilege.', nist800_53: ['AC-6'] },
  { id: '3.1.6', family: fam('3.1.6'), description: 'Use non-privileged accounts when accessing non-security functions.', nist800_53: ['AC-6'] },
  { id: '3.1.7', family: fam('3.1.7'), description: 'Prevent non-privileged users from executing privileged functions and audit such functions.', nist800_53: ['AC-6', 'AU-2'] },
  { id: '3.1.8', family: fam('3.1.8'), description: 'Limit unsuccessful logon attempts.', nist800_53: ['AC-7'] },
  { id: '3.1.9', family: fam('3.1.9'), description: 'Provide privacy and security notices.', nist800_53: ['AC-8'] },
  { id: '3.1.10', family: fam('3.1.10'), description: 'Use session lock with pattern-hiding displays.', nist800_53: ['AC-11'] },
  { id: '3.1.11', family: fam('3.1.11'), description: 'Terminate user session after defined condition.', nist800_53: ['AC-12'] },
  { id: '3.1.12', family: fam('3.1.12'), description: 'Monitor and control remote access sessions.', nist800_53: ['AC-17'] },
  { id: '3.1.13', family: fam('3.1.13'), description: 'Employ cryptographic mechanisms to protect remote access sessions.', nist800_53: ['AC-17', 'SC-8'] },
  { id: '3.1.14', family: fam('3.1.14'), description: 'Route remote access via managed access control points.', nist800_53: ['AC-17'] },
  { id: '3.1.15', family: fam('3.1.15'), description: 'Authorize remote execution of privileged commands.', nist800_53: ['AC-17', 'AC-6'] },
  { id: '3.1.16', family: fam('3.1.16'), description: 'Authorize wireless access prior to allowing connections.', nist800_53: ['AC-18'] },
  { id: '3.1.17', family: fam('3.1.17'), description: 'Protect wireless access using authentication and encryption.', nist800_53: ['AC-18'] },
  { id: '3.1.18', family: fam('3.1.18'), description: 'Control connection of mobile devices.', nist800_53: ['AC-19'] },
  { id: '3.1.19', family: fam('3.1.19'), description: 'Encrypt CUI on mobile devices.', nist800_53: ['AC-19', 'SC-28'] },
  { id: '3.1.20', family: fam('3.1.20'), description: 'Verify and control connections to external systems.', nist800_53: ['AC-20'] },
  { id: '3.1.21', family: fam('3.1.21'), description: 'Limit use of portable storage devices on external systems.', nist800_53: ['AC-20'] },
  { id: '3.1.22', family: fam('3.1.22'), description: 'Control information posted on publicly accessible systems.', nist800_53: ['AC-22'] },

  // 3.2 Awareness and Training (3 reqs)
  { id: '3.2.1', family: fam('3.2.1'), description: 'Ensure managers/system admins are aware of security risks.', nist800_53: ['AT-2'] },
  { id: '3.2.2', family: fam('3.2.2'), description: 'Ensure personnel are trained to carry out security-related duties.', nist800_53: ['AT-3'] },
  { id: '3.2.3', family: fam('3.2.3'), description: 'Provide insider threat training.', nist800_53: ['AT-2'] },

  // 3.3 Audit and Accountability (9 reqs)
  { id: '3.3.1', family: fam('3.3.1'), description: 'Create and retain audit records.', nist800_53: ['AU-2', 'AU-12'] },
  { id: '3.3.2', family: fam('3.3.2'), description: 'Ensure individual users can be traced for their actions.', nist800_53: ['AU-3', 'IA-2'] },
  { id: '3.3.3', family: fam('3.3.3'), description: 'Review and update logged events.', nist800_53: ['AU-2'] },
  { id: '3.3.4', family: fam('3.3.4'), description: 'Alert on audit logging process failures.', nist800_53: ['AU-5'] },
  { id: '3.3.5', family: fam('3.3.5'), description: 'Correlate audit record review with detection processes.', nist800_53: ['AU-6'] },
  { id: '3.3.6', family: fam('3.3.6'), description: 'Provide reporting capability from audit records.', nist800_53: ['AU-7'] },
  { id: '3.3.7', family: fam('3.3.7'), description: 'Synchronize internal system clocks.', nist800_53: ['AU-8'] },
  { id: '3.3.8', family: fam('3.3.8'), description: 'Protect audit information from unauthorized modification.', nist800_53: ['AU-9'] },
  { id: '3.3.9', family: fam('3.3.9'), description: 'Limit management of audit logging to subset of users.', nist800_53: ['AU-9', 'AC-6'] },

  // 3.4 Configuration Management (9 reqs)
  { id: '3.4.1', family: fam('3.4.1'), description: 'Establish baseline configurations + inventories.', nist800_53: ['CM-2', 'CM-8'] },
  { id: '3.4.2', family: fam('3.4.2'), description: 'Enforce security configuration settings.', nist800_53: ['CM-6'] },
  { id: '3.4.3', family: fam('3.4.3'), description: 'Track, review, approve, and audit changes.', nist800_53: ['CM-3'] },
  { id: '3.4.4', family: fam('3.4.4'), description: 'Analyze security impact prior to implementation.', nist800_53: ['CM-4'] },
  { id: '3.4.5', family: fam('3.4.5'), description: 'Restrict who can implement changes.', nist800_53: ['CM-5'] },
  { id: '3.4.6', family: fam('3.4.6'), description: 'Employ least functionality.', nist800_53: ['CM-7'] },
  { id: '3.4.7', family: fam('3.4.7'), description: 'Restrict programs / functions / ports.', nist800_53: ['CM-7'] },
  { id: '3.4.8', family: fam('3.4.8'), description: 'Apply deny-by-exception (allow-list).', nist800_53: ['CM-7'] },
  { id: '3.4.9', family: fam('3.4.9'), description: 'Control and monitor user-installed software.', nist800_53: ['CM-11'] },

  // 3.5 Identification and Authentication (11 reqs)
  { id: '3.5.1', family: fam('3.5.1'), description: 'Identify users, processes, and devices.', nist800_53: ['IA-2', 'IA-3'] },
  { id: '3.5.2', family: fam('3.5.2'), description: 'Authenticate users, processes, and devices.', nist800_53: ['IA-2', 'IA-3'] },
  { id: '3.5.3', family: fam('3.5.3'), description: 'Use MFA for privileged accounts + network access.', nist800_53: ['IA-2'] },
  { id: '3.5.4', family: fam('3.5.4'), description: 'Employ replay-resistant authentication.', nist800_53: ['IA-2'] },
  { id: '3.5.5', family: fam('3.5.5'), description: 'Prevent reuse of identifiers.', nist800_53: ['IA-4'] },
  { id: '3.5.6', family: fam('3.5.6'), description: 'Disable identifiers after defined inactivity.', nist800_53: ['IA-4'] },
  { id: '3.5.7', family: fam('3.5.7'), description: 'Enforce minimum password complexity.', nist800_53: ['IA-5'] },
  { id: '3.5.8', family: fam('3.5.8'), description: 'Prohibit password reuse.', nist800_53: ['IA-5'] },
  { id: '3.5.9', family: fam('3.5.9'), description: 'Allow temporary password use after immediate change.', nist800_53: ['IA-5'] },
  { id: '3.5.10', family: fam('3.5.10'), description: 'Store and transmit only cryptographically-protected passwords.', nist800_53: ['IA-5'] },
  { id: '3.5.11', family: fam('3.5.11'), description: 'Obscure feedback of authentication information.', nist800_53: ['IA-6'] },

  // 3.6 Incident Response (3 reqs)
  { id: '3.6.1', family: fam('3.6.1'), description: 'Establish operational incident-handling capability.', nist800_53: ['IR-4'] },
  { id: '3.6.2', family: fam('3.6.2'), description: 'Track, document, and report incidents.', nist800_53: ['IR-5', 'IR-6'] },
  { id: '3.6.3', family: fam('3.6.3'), description: 'Test incident response capability.', nist800_53: ['IR-3'] },

  // 3.7 Maintenance (6 reqs)
  { id: '3.7.1', family: fam('3.7.1'), description: 'Perform maintenance on systems.', nist800_53: ['MA-2'] },
  { id: '3.7.2', family: fam('3.7.2'), description: 'Provide controls on tools used for maintenance.', nist800_53: ['MA-3'] },
  { id: '3.7.3', family: fam('3.7.3'), description: 'Sanitize equipment removed for offsite maintenance.', nist800_53: ['MA-2', 'MP-6'] },
  { id: '3.7.4', family: fam('3.7.4'), description: 'Check media containing diagnostic programs for malicious code.', nist800_53: ['SI-3'] },
  { id: '3.7.5', family: fam('3.7.5'), description: 'Require MFA to establish nonlocal maintenance sessions.', nist800_53: ['MA-4'] },
  { id: '3.7.6', family: fam('3.7.6'), description: 'Supervise maintenance activities of personnel without escort privileges.', nist800_53: ['MA-5'] },

  // 3.8 Media Protection (9 reqs)
  { id: '3.8.1', family: fam('3.8.1'), description: 'Protect CUI on system media.', nist800_53: ['MP-2', 'MP-4'] },
  { id: '3.8.2', family: fam('3.8.2'), description: 'Limit access to CUI on system media.', nist800_53: ['MP-2'] },
  { id: '3.8.3', family: fam('3.8.3'), description: 'Sanitize or destroy media before disposal.', nist800_53: ['MP-6'] },
  { id: '3.8.4', family: fam('3.8.4'), description: 'Mark media with CUI markings.', nist800_53: ['MP-3'] },
  { id: '3.8.5', family: fam('3.8.5'), description: 'Control access to CUI media; maintain accountability.', nist800_53: ['MP-5'] },
  { id: '3.8.6', family: fam('3.8.6'), description: 'Implement cryptographic mechanisms during transport.', nist800_53: ['MP-5', 'SC-28'] },
  { id: '3.8.7', family: fam('3.8.7'), description: 'Control the use of removable media.', nist800_53: ['MP-7'] },
  { id: '3.8.8', family: fam('3.8.8'), description: 'Prohibit portable storage devices with no identifiable owner.', nist800_53: ['MP-7'] },
  { id: '3.8.9', family: fam('3.8.9'), description: 'Protect confidentiality of backups at storage locations.', nist800_53: ['CP-9', 'SC-28'] },

  // 3.9 Personnel Security (2 reqs)
  { id: '3.9.1', family: fam('3.9.1'), description: 'Screen individuals prior to authorizing access to CUI.', nist800_53: ['PS-3'] },
  { id: '3.9.2', family: fam('3.9.2'), description: 'Ensure CUI systems are protected during/after personnel actions.', nist800_53: ['PS-4', 'PS-5'] },

  // 3.10 Physical Protection (6 reqs)
  { id: '3.10.1', family: fam('3.10.1'), description: 'Limit physical access to systems / equipment / environments.', nist800_53: ['PE-2', 'PE-3'] },
  { id: '3.10.2', family: fam('3.10.2'), description: 'Protect and monitor the physical facility.', nist800_53: ['PE-6'] },
  { id: '3.10.3', family: fam('3.10.3'), description: 'Escort visitors and monitor visitor activity.', nist800_53: ['PE-3'] },
  { id: '3.10.4', family: fam('3.10.4'), description: 'Maintain audit logs of physical access.', nist800_53: ['PE-3'] },
  { id: '3.10.5', family: fam('3.10.5'), description: 'Control and manage physical access devices.', nist800_53: ['PE-3'] },
  { id: '3.10.6', family: fam('3.10.6'), description: 'Enforce safeguarding measures for CUI at alternate work sites.', nist800_53: ['PE-3'] },

  // 3.11 Risk Assessment (3 reqs)
  { id: '3.11.1', family: fam('3.11.1'), description: 'Periodically assess risk to systems.', nist800_53: ['RA-3'] },
  { id: '3.11.2', family: fam('3.11.2'), description: 'Scan for vulnerabilities periodically.', nist800_53: ['RA-5'] },
  { id: '3.11.3', family: fam('3.11.3'), description: 'Remediate vulnerabilities.', nist800_53: ['RA-5', 'SI-2'] },

  // 3.12 Security Assessment (4 reqs)
  { id: '3.12.1', family: fam('3.12.1'), description: 'Periodically assess security controls.', nist800_53: ['CA-2'] },
  { id: '3.12.2', family: fam('3.12.2'), description: 'Develop and implement plans of action.', nist800_53: ['CA-5'] },
  { id: '3.12.3', family: fam('3.12.3'), description: 'Monitor security controls on an ongoing basis.', nist800_53: ['CA-7'] },
  { id: '3.12.4', family: fam('3.12.4'), description: 'Develop and maintain system security plan.', nist800_53: ['PL-2'] },

  // 3.13 System and Communications Protection (16 reqs)
  { id: '3.13.1', family: fam('3.13.1'), description: 'Monitor / control / protect communications at boundaries.', nist800_53: ['SC-7'] },
  { id: '3.13.2', family: fam('3.13.2'), description: 'Employ architectural designs / software development techniques.', nist800_53: ['SA-8'] },
  { id: '3.13.3', family: fam('3.13.3'), description: 'Separate user functionality from system management.', nist800_53: ['SC-2'] },
  { id: '3.13.4', family: fam('3.13.4'), description: 'Prevent unauthorized info transfer via shared resources.', nist800_53: ['SC-4'] },
  { id: '3.13.5', family: fam('3.13.5'), description: 'Implement subnetworks for publicly accessible system components.', nist800_53: ['SC-7'] },
  { id: '3.13.6', family: fam('3.13.6'), description: 'Deny network traffic by default; permit by exception.', nist800_53: ['SC-7'] },
  { id: '3.13.7', family: fam('3.13.7'), description: 'Prevent remote devices from simultaneously connecting non-securely.', nist800_53: ['SC-7'] },
  { id: '3.13.8', family: fam('3.13.8'), description: 'Implement cryptography to prevent unauthorized disclosure during transmission.', nist800_53: ['SC-8'] },
  { id: '3.13.9', family: fam('3.13.9'), description: 'Terminate network connections at end of session / inactivity.', nist800_53: ['SC-10'] },
  { id: '3.13.10', family: fam('3.13.10'), description: 'Establish and manage cryptographic keys.', nist800_53: ['SC-12'] },
  { id: '3.13.11', family: fam('3.13.11'), description: 'Employ FIPS-validated cryptography.', nist800_53: ['SC-13'] },
  { id: '3.13.12', family: fam('3.13.12'), description: 'Prohibit remote activation of collaborative devices.', nist800_53: ['SC-15'] },
  { id: '3.13.13', family: fam('3.13.13'), description: 'Control and monitor mobile code.', nist800_53: ['SC-18'] },
  { id: '3.13.14', family: fam('3.13.14'), description: 'Control and monitor VoIP.', nist800_53: ['SC-19'] },
  { id: '3.13.15', family: fam('3.13.15'), description: 'Protect authenticity of communications sessions.', nist800_53: ['SC-23'] },
  { id: '3.13.16', family: fam('3.13.16'), description: 'Protect confidentiality of CUI at rest.', nist800_53: ['SC-28'] },

  // 3.14 System and Information Integrity (7 reqs)
  { id: '3.14.1', family: fam('3.14.1'), description: 'Identify / report / correct system flaws timely.', nist800_53: ['SI-2'] },
  { id: '3.14.2', family: fam('3.14.2'), description: 'Provide malicious code protection.', nist800_53: ['SI-3'] },
  { id: '3.14.3', family: fam('3.14.3'), description: 'Monitor security alerts and advisories.', nist800_53: ['SI-5'] },
  { id: '3.14.4', family: fam('3.14.4'), description: 'Update malicious code protection mechanisms.', nist800_53: ['SI-3'] },
  { id: '3.14.5', family: fam('3.14.5'), description: 'Perform periodic and real-time scans of system files.', nist800_53: ['SI-3'] },
  { id: '3.14.6', family: fam('3.14.6'), description: 'Monitor org-defined events to detect attacks.', nist800_53: ['SI-4'] },
  { id: '3.14.7', family: fam('3.14.7'), description: 'Identify unauthorized use of the system.', nist800_53: ['SI-4'] }
];

export function nist171Family(id: string): string {
  const k = id.split('.').slice(0, 2).join('.');
  return NIST_171_FAMILIES[k] ?? k;
}
