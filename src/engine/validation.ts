// Pre-generation validator. Surfaces consistency issues and emits
// clarification questions when assessor judgment is needed. Refuses
// to fabricate unknown requirements (returns clarifications instead).

import { Assessment, ValidationReport, ClarificationQuestion } from '../types/assessment';
import { scanAssessmentForInjection } from './promptInjection';

export interface ValidationOutput {
  report: ValidationReport;
  clarifications: ClarificationQuestion[];
}

export function validate(a: Assessment): ValidationOutput {
  const issues: ValidationReport['issues'] = [];
  const clarifications: ClarificationQuestion[] = [];

  if (!a.business.applicationName || a.business.applicationName.trim().length < 2) {
    issues.push({ severity: 'error', field: 'business.applicationName', message: 'Application name is required.' });
  }
  if (!a.business.businessProblem || a.business.businessProblem.trim().length < 10) {
    issues.push({ severity: 'warn', field: 'business.businessProblem', message: 'Business problem statement is short or missing.' });
    clarifications.push({
      field: 'business.businessProblem',
      question: 'In one or two sentences, what is the business problem this application solves?',
      reason: 'Drives the executive summary and prioritisation of compensating controls.'
    });
  }
  if (!a.business.userTypes.length) {
    issues.push({ severity: 'error', field: 'business.userTypes', message: 'Select at least one user type.' });
  }
  if (!a.data.dataCategories.length) {
    issues.push({ severity: 'warn', field: 'data.dataCategories', message: 'No data categories selected — categorisation will default to Operational.' });
  }
  // RTO/RPO consistency
  const rtoOrder = ['15 Minutes', '1 Hour', '4 Hours', '24 Hours', '72 Hours'];
  const rpoOrder = ['No Data Loss', '15 Minutes', '1 Hour', '24 Hours'];
  if (a.recovery.rpo === 'No Data Loss' && (a.recovery.rto === '24 Hours' || a.recovery.rto === '72 Hours')) {
    issues.push({
      severity: 'warn', field: 'recovery',
      message: 'No Data Loss RPO with a relaxed RTO is unusual — confirm objectives are correct.'
    });
    clarifications.push({
      field: 'recovery',
      question: 'You selected No Data Loss but a long RTO. Did you intend zero data loss with a quick recovery, or longer downtime with zero loss?',
      reason: 'RTO and RPO interact and drive backup architecture cost; confirm both.'
    });
  }
  if (rtoOrder.indexOf(a.recovery.rto) < 0 || rpoOrder.indexOf(a.recovery.rpo) < 0) {
    issues.push({ severity: 'error', field: 'recovery', message: 'RTO or RPO value invalid.' });
  }

  if (!a.compliance.frameworks.length) {
    issues.push({ severity: 'info', field: 'compliance.frameworks', message: 'No external frameworks selected; internal policy will be used.' });
  }

  if (a.business.userTypes.includes('Public Users') && !a.data.confidentialToCompany && a.data.sensitiveDataTags.length === 0) {
    clarifications.push({
      field: 'data',
      question: 'Public users will interact with the system, but no confidentiality or sensitive-data flag is set. Confirm: is any user input considered confidential?',
      reason: 'Public-facing systems usually still process at least PII; assessor needs to confirm.'
    });
  }

  if (a.data.sensitiveDataTags.includes('PCI') && !a.compliance.frameworks.includes('PCI DSS')) {
    issues.push({
      severity: 'warn', field: 'compliance.frameworks',
      message: 'PCI data declared but PCI DSS not selected as a compliance framework.'
    });
  }
  if (a.data.sensitiveDataTags.includes('PHI') && !a.compliance.frameworks.includes('HIPAA')) {
    issues.push({
      severity: 'warn', field: 'compliance.frameworks',
      message: 'PHI declared but HIPAA not selected as a compliance framework.'
    });
  }

  for (let i = 0; i < a.integrations.length; i++) {
    const it = a.integrations[i]!;
    if (!it.source || !it.destination) {
      issues.push({ severity: 'error', field: `integrations[${i}]`, message: 'Source and destination required.' });
    }
    if (it.authentication === 'None' || it.authentication === 'Basic Auth') {
      issues.push({
        severity: 'warn', field: `integrations[${i}].authentication`,
        message: `Integration uses ${it.authentication} — unacceptable for sensitive data.`
      });
    }
  }

  // Prompt-injection scan — surface as warnings so reviewers see them
  // before approving. The findings are also clarification questions
  // because the reviewer is the right human to investigate.
  for (const f of scanAssessmentForInjection(a)) {
    issues.push({
      severity: 'warn',
      field: f.field,
      message: `Possible prompt-injection content detected (${f.label}): "${f.excerpt}". Review before approval.`
    });
    clarifications.push({
      field: f.field,
      question: `The ${f.field} field contains text that looks like a prompt-injection attempt (${f.label}). Confirm it was authored intentionally or remove it.`,
      reason: 'Prompt-injection content can mislead AI augmentation and downstream readers.'
    });
  }

  const passed = !issues.some(i => i.severity === 'error');
  return {
    report: { passed, issues },
    clarifications
  };
}
