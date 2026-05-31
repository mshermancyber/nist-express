// CRUD routes for Assessments. All input is validated through zod so
// arbitrary user data never reaches the engine without conforming to
// the typed shape. Input size is already capped at 512kb by the
// global express.json() limit in server.ts.

import { Router } from 'express';
import { z } from 'zod';
import { randomUUID as uuid } from 'crypto';
import { Assessment } from '../types/assessment';
import {
  deleteAssessment, getAssessment, listAssessments, saveAssessment, canAccessAssessment
} from '../store/assessmentStore';
import { getUserById } from '../store/userStore';
import { appendAudit } from '../store/auditStore';
import { getSession } from '../auth/auth';

const userTypes = z.enum(['Employees', 'Customers', 'Vendors', 'Partners', 'Public Users', 'Contractors', 'System-to-System']);
const dataCats = z.enum(['Customer Information', 'Employee Information', 'Financial Data', 'Source Code', 'Intellectual Property', 'Operational Data', 'Public Information']);
const sensitive = z.enum(['PII', 'PCI', 'PHI', 'Trade Secrets', 'Regulated Data', 'Export Controlled Data']);
const rto = z.enum(['15 Minutes', '1 Hour', '4 Hours', '24 Hours', '72 Hours']);
const rpo = z.enum(['No Data Loss', '15 Minutes', '1 Hour', '24 Hours']);
const pop = z.enum(['Under 100', '100-1000', '1000-10000', '10000+']);
const compliance = z.enum(['NIST 800-53', 'NIST 800-171', 'CMMC', 'NIST CSF 2.0', 'NIST AI RMF', 'EU AI Act', 'SOC2', 'ISO 27001', 'PCI DSS', 'HIPAA', 'HITRUST CSF', 'FedRAMP', 'GDPR', 'CCPA', 'DORA', 'FFIEC', 'IRS Pub 1075', 'Internal Policy Only']);
const hosting = z.enum(['AWS', 'Azure', 'GCP', 'Hybrid', 'On-Prem']);
const protocol = z.enum(['HTTPS', 'TLS', 'SFTP', 'gRPC', 'JDBC/ODBC', 'AMQP', 'Kafka', 'Other']);
const auth = z.enum(['OAuth2', 'SAML', 'API Key', 'mTLS', 'Service Account', 'Basic Auth', 'None']);

const integrationSchema = z.object({
  source: z.string().min(1).max(120),
  destination: z.string().min(1).max(120),
  protocol,
  authentication: auth,
  dataDirection: z.enum(['inbound', 'outbound', 'bidirectional']),
  description: z.string().max(500).optional()
});

const assessmentSchema = z.object({
  business: z.object({
    applicationName: z.string().min(2).max(120),
    businessArea: z.string().max(120).optional(),
    businessProblem: z.string().min(0).max(2000),
    userTypes: z.array(userTypes).min(0),
    userInteractionDescription: z.string().max(2000).default('')
  }),
  data: z.object({
    dataCategories: z.array(dataCats).default([]),
    confidentialToCompany: z.boolean().default(false),
    sensitiveDataTags: z.array(sensitive).default([])
  }),
  impact: z.object({
    confidentialityWorstCase: z.string().max(500).default(''),
    integrityWorstCase: z.string().max(500).default(''),
    availabilityWorstCase: z.string().max(500).default('')
  }),
  recovery: z.object({ rto, rpo }),
  population: z.object({
    userCount: pop,
    expectedGrowth: z.string().max(500).default('')
  }),
  integrations: z.array(integrationSchema).max(50).default([]),
  compliance: z.object({ frameworks: z.array(compliance).default([]) }),
  hosting: z.object({ model: hosting }),
  advanced: z.object({
    forceMfa: z.boolean().optional(),
    forceOkta: z.boolean().optional(),
    preferredAwsRegion: z.string().max(40).optional(),
    multiRegion: z.boolean().optional(),
    customControlIds: z.array(z.string().max(20)).max(200).optional(),
    excludeControlIds: z.array(z.string().max(20)).max(200).optional(),
    loggingRetentionDays: z.number().int().min(1).max(36500).optional(),
    customAwsServices: z.array(z.string().max(80)).max(50).optional()
  }).partial().optional()
});

export const assessmentsRouter = Router();

function tenancy(req: import('express').Request): { userId: string; roles: string[]; team?: string } | undefined {
  const s = getSession(req);
  if (!s) return undefined;
  const user = getUserById(s.userId);
  return { userId: s.userId, roles: s.roles, team: user?.team };
}

assessmentsRouter.get('/', (req, res) => {
  const t = tenancy(req);
  res.json({ assessments: listAssessments(t ? { userId: t.userId, team: t.team, isAdmin: t.roles.includes('admin') } : undefined) });
});

assessmentsRouter.post('/', (req, res) => {
  const parsed = assessmentSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid assessment', issues: parsed.error.format() });
    return;
  }
  const now = new Date().toISOString();
  const session = getSession(req);
  const user = session ? getUserById(session.userId) : undefined;
  const a: Assessment = {
    id: uuid(),
    createdAt: now,
    updatedAt: now,
    status: 'draft',
    ownerId: session?.userId,
    team: user?.team,
    ...parsed.data
  };
  saveAssessment(a);
  appendAudit({ actor: session?.userId ?? 'anonymous', action: 'assessment.create', target: a.id, details: { name: a.business.applicationName, team: a.team } });
  res.status(201).json(a);
});

assessmentsRouter.get('/:id', (req, res) => {
  const a = getAssessment(req.params.id);
  if (!a) { res.status(404).json({ error: 'not found' }); return; }
  const t = tenancy(req);
  if (!canAccessAssessment(a, t)) { res.status(403).json({ error: 'forbidden' }); return; }
  res.json(a);
});

// POST /api/assessments/import — accept a JSON file (full Assessment
// or just the input body) and create a fresh assessment from it.
// The id/createdAt/updatedAt fields are always regenerated server-side
// so two re-imports of the same file produce two distinct rows.
assessmentsRouter.post('/import', (req, res) => {
  // Accept both wire shapes: a bare assessment body, or a previously
  // exported assessment with id/timestamps that we strip before validating.
  const raw = (typeof req.body === 'object' && req.body) ? req.body as Record<string, unknown> : {};
  const stripped = { ...raw } as Record<string, unknown>;
  delete stripped.id; delete stripped.createdAt; delete stripped.updatedAt; delete stripped.status;

  const parsed = assessmentSchema.safeParse(stripped);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid assessment JSON', issues: parsed.error.format() });
    return;
  }
  const now = new Date().toISOString();
  const a: Assessment = {
    id: uuid(),
    createdAt: now,
    updatedAt: now,
    status: 'draft',
    ...parsed.data
  };
  saveAssessment(a);
  res.status(201).json(a);
});

assessmentsRouter.put('/:id', (req, res) => {
  const existing = getAssessment(req.params.id);
  if (!existing) { res.status(404).json({ error: 'not found' }); return; }
  const t = tenancy(req);
  if (!canAccessAssessment(existing, t)) { res.status(403).json({ error: 'forbidden' }); return; }
  const parsed = assessmentSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid assessment', issues: parsed.error.format() });
    return;
  }
  const updated: Assessment = {
    ...existing,
    ...parsed.data,
    updatedAt: new Date().toISOString()
  };
  saveAssessment(updated);
  res.json(updated);
});

assessmentsRouter.delete('/:id', (req, res) => {
  const existing = getAssessment(req.params.id);
  if (!existing) { res.status(404).end(); return; }
  const t = tenancy(req);
  if (!canAccessAssessment(existing, t)) { res.status(403).json({ error: 'forbidden' }); return; }
  const ok = deleteAssessment(req.params.id);
  res.status(ok ? 204 : 404).end();
});
