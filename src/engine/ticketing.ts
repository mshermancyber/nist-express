// Jira / ServiceNow integration. Configuration via env vars:
//   JIRA_BASE_URL, JIRA_USER, JIRA_TOKEN, JIRA_PROJECT_KEY
//   SERVICENOW_BASE_URL, SERVICENOW_USER, SERVICENOW_PASSWORD, SERVICENOW_TABLE (default: incident)
//
// In the absence of credentials we simulate by returning a fake id so
// the workflow is testable end-to-end without a live system. Calls
// that go to a real backend use HTTPS with basic-auth (or Bearer for
// Jira Cloud).

import { ResidualRisk, ExternalTicket } from '../types/assessment';

export type TicketSystem = 'jira' | 'servicenow';

function severityForRisk(r: ResidualRisk): string {
  return r.residualRisk === 'Critical' ? 'Highest' : r.residualRisk === 'High' ? 'High' : r.residualRisk === 'Medium' ? 'Medium' : 'Low';
}

export async function createTicket(system: TicketSystem, risk: ResidualRisk, assessmentName: string): Promise<ExternalTicket> {
  if (system === 'jira') return createJira(risk, assessmentName);
  return createServiceNow(risk, assessmentName);
}

async function createJira(risk: ResidualRisk, app: string): Promise<ExternalTicket> {
  const base = process.env.JIRA_BASE_URL;
  const user = process.env.JIRA_USER;
  const token = process.env.JIRA_TOKEN;
  const project = process.env.JIRA_PROJECT_KEY ?? 'ARB';
  const summary = `[${risk.residualRisk}] ${risk.description.slice(0, 120)}`;
  const description = `Source: ${risk.source}\nApplication: ${app}\nInherent: ${risk.inherentRisk} | Residual: ${risk.residualRisk}\nRationale: ${risk.rationale}\nTreatment: ${risk.treatment}\nOwner: ${risk.owner}`;
  if (!base || !user || !token) {
    return { riskId: risk.id, system: 'jira', externalId: `MOCK-JIRA-${risk.id}`, status: 'Open (mock)', createdAt: new Date().toISOString() };
  }
  const { safeFetch } = await import('./safeFetch');
  const auth = 'Basic ' + Buffer.from(`${user}:${token}`).toString('base64');
  const r = await safeFetch(`${base.replace(/\/+$/, '')}/rest/api/3/issue`, {
    method: 'POST',
    headers: { authorization: auth, 'content-type': 'application/json' },
    timeoutMs: 10_000,
    body: JSON.stringify({
      fields: {
        project: { key: project },
        summary,
        issuetype: { name: 'Task' },
        priority: { name: severityForRisk(risk) },
        description: { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: description }] }] }
      }
    })
  });
  if (!r.ok) throw new Error(`Jira returned ${r.status}: ${await r.text().catch(() => '')}`);
  const j = await r.json() as { key: string; self: string };
  return { riskId: risk.id, system: 'jira', externalId: j.key, url: `${base.replace(/\/+$/, '')}/browse/${j.key}`, status: 'Open', createdAt: new Date().toISOString() };
}

async function createServiceNow(risk: ResidualRisk, app: string): Promise<ExternalTicket> {
  const base = process.env.SERVICENOW_BASE_URL;
  const user = process.env.SERVICENOW_USER;
  const pass = process.env.SERVICENOW_PASSWORD;
  const table = process.env.SERVICENOW_TABLE ?? 'incident';
  if (!base || !user || !pass) {
    return { riskId: risk.id, system: 'servicenow', externalId: `MOCK-SN-${risk.id}`, status: 'New (mock)', createdAt: new Date().toISOString() };
  }
  const { safeFetch } = await import('./safeFetch');
  const auth = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
  const r = await safeFetch(`${base.replace(/\/+$/, '')}/api/now/table/${encodeURIComponent(table)}`, {
    method: 'POST',
    headers: { authorization: auth, 'content-type': 'application/json' },
    timeoutMs: 10_000,
    body: JSON.stringify({
      short_description: `[${risk.residualRisk}] ${risk.description.slice(0, 120)}`,
      description: `Source: ${risk.source}\nApplication: ${app}\nInherent: ${risk.inherentRisk} | Residual: ${risk.residualRisk}\nRationale: ${risk.rationale}`,
      impact: risk.residualRisk === 'Critical' ? '1' : risk.residualRisk === 'High' ? '2' : '3',
      urgency: risk.residualRisk === 'Critical' ? '1' : risk.residualRisk === 'High' ? '2' : '3'
    })
  });
  if (!r.ok) throw new Error(`ServiceNow returned ${r.status}: ${await r.text().catch(() => '')}`);
  const j = await r.json() as { result?: { sys_id: string; number: string } };
  return {
    riskId: risk.id, system: 'servicenow',
    externalId: j.result?.number ?? 'unknown',
    url: `${base.replace(/\/+$/, '')}/nav_to.do?uri=${encodeURIComponent(table)}.do?sys_id=${encodeURIComponent(j.result?.sys_id ?? '')}`,
    status: 'New',
    createdAt: new Date().toISOString()
  };
}
