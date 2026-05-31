// OpenAPI 3.0 spec served at /api/openapi.json. Hand-curated subset
// covering the routes external integrators are most likely to call.
// Comprehensive schemas live in src/types/assessment.ts; the spec here
// favours operational clarity over completeness.

import { Router } from 'express';

export const openapiRouter = Router();

openapiRouter.get('/openapi.json', (_req, res) => {
  res.json({
    openapi: '3.0.3',
    info: {
      title: 'nist-express ARB Platform',
      version: '1.0.0',
      license: { name: 'GPL-3.0-only' },
      description: 'Enterprise Security Architecture Assessment platform. Produces NIST 800-53 SSPs, OSCAL, FedRAMP packages, threat models, and more from a guided questionnaire.'
    },
    servers: [{ url: '/' }],
    components: {
      securitySchemes: {
        cookieSession: { type: 'apiKey', in: 'cookie', name: 'arb_session' },
        bearerApiKey: { type: 'http', scheme: 'bearer', bearerFormat: 'arb_...' },
        scimBearer: { type: 'http', scheme: 'bearer', bearerFormat: 'SCIM_TOKEN' }
      },
      schemas: {
        Error: { type: 'object', properties: { error: { type: 'string' } } },
        Assessment: { type: 'object' },          // full schema in src/types/assessment.ts
        ArbPackage: { type: 'object' }
      }
    },
    paths: {
      '/healthz':    { get: { tags: ['Health'], summary: 'Liveness',  responses: { '200': { description: 'OK' } } } },
      '/livez':      { get: { tags: ['Health'], summary: 'Liveness',  responses: { '200': { description: 'OK' } } } },
      '/readyz':     { get: { tags: ['Health'], summary: 'Readiness', responses: { '200': { description: 'Ready' }, '503': { description: 'Starting or draining' } } } },
      '/metrics':    { get: { tags: ['Health'], summary: 'Prometheus metrics', responses: { '200': { description: 'text/plain' } } } },

      '/api/auth/login':           { post: { tags: ['Auth'], summary: 'Sign in (optionally TOTP)', responses: { '200': { description: 'OK' }, '401': { description: 'Invalid credentials' }, '429': { description: 'Throttled' } } } },
      '/api/auth/logout':          { post: { tags: ['Auth'], summary: 'Clear session', responses: { '204': { description: 'OK' } } } },
      '/api/auth/me':              { get:  { tags: ['Auth'], summary: 'Current session', responses: { '200': { description: 'OK' } } } },
      '/api/auth/sudo':            { post: { tags: ['Auth'], summary: 'Re-authenticate to enter sudo mode', responses: { '200': { description: 'OK' }, '401': { description: 'Bad password / TOTP' } } } },
      '/api/auth/rotate-secret':   { post: { tags: ['Auth'], summary: 'Rotate session secret (admin + sudo)', responses: { '200': { description: 'Rotated' } } } },
      '/api/auth/totp/enroll':     { post: { tags: ['Auth'], summary: 'Generate TOTP secret + provisioning URI', responses: { '200': { description: 'OK' } } } },
      '/api/auth/api-keys':        { get: { tags: ['Auth'], summary: 'List API keys (self)', responses: { '200': { description: 'OK' } } }, post: { tags: ['Auth'], summary: 'Issue API key (raw shown once)', responses: { '201': { description: 'Created' } } } },

      '/api/assessments':          { get: { tags: ['Assessments'], summary: 'List (filtered by tenant)', responses: { '200': { description: 'OK' } } }, post: { tags: ['Assessments'], summary: 'Create', responses: { '201': { description: 'Created' } } } },
      '/api/assessments/{id}':     { get: { tags: ['Assessments'], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], summary: 'Fetch', responses: { '200': { description: 'OK' }, '403': { description: 'Forbidden' } } }, put: { tags: ['Assessments'], summary: 'Update' }, delete: { tags: ['Assessments'], summary: 'Delete' } },
      '/api/assessments/import':   { post: { tags: ['Assessments'], summary: 'Import JSON (creates fresh draft)' } },

      '/api/generate/{id}':        { post: { tags: ['Generate'], summary: 'Generate ARB package' }, get: { tags: ['Generate'], summary: 'Fetch latest package' } },
      '/api/generate/{id}/versions': { get: { tags: ['Generate'], summary: 'List historical versions' } },
      '/api/generate/{id}/diff/{from}/{to}': { get: { tags: ['Generate'], summary: 'Diff two versions' } },

      '/api/export/{id}.{ext}':    { get: { tags: ['Export'], summary: 'Download package (ext: json, md, html, pdf, oscal.json, ssp.csv, evidence.csv, residual-risk.csv, audit-events.csv, stride.csv, cost.csv, compliance.csv, diff.csv, fair.csv, sbom.csv)', responses: { '200': { description: 'File body' } } } },

      '/api/fedramp/{id}':         { get: { tags: ['FedRAMP'], summary: 'FedRAMP package JSON' } },
      '/api/fedramp/{id}/poam.csv': { get: { tags: ['FedRAMP'], summary: 'POA&M CSV' } },
      '/api/fedramp/{id}/poam.oscal.json': { get: { tags: ['FedRAMP'], summary: 'POA&M OSCAL JSON' } },
      '/api/fedramp/{id}/pack.tar': { get: { tags: ['FedRAMP'], summary: 'Full FedRAMP package as tar' } },
      '/api/fedramp/status':       { get: { tags: ['FedRAMP'], summary: 'FIPS attestation' } },

      '/api/sbom/{id}/upload':     { post: { tags: ['Attachments'], summary: 'Upload SBOM (multipart/form-data)' } },
      '/api/iac/{id}/upload':      { post: { tags: ['Attachments'], summary: 'Upload IaC (multipart/form-data)' } },
      '/api/cloud/{id}/upload':    { post: { tags: ['Attachments'], summary: 'Upload cloud snapshot (multipart/form-data)' } },

      '/api/approval/{id}/request': { post: { tags: ['Approval'], summary: 'Open approval request' } },
      '/api/approval/{id}/sign':    { post: { tags: ['Approval'], summary: 'Sign as approver-{security|risk|architecture|compliance} (sudo required)' } },

      '/api/risks/{aid}/{rid}/accept': { post: { tags: ['Risk'], summary: 'Accept residual risk with expiry + rationale' } },
      '/api/risks/{aid}/{rid}/ticket': { post: { tags: ['Risk'], summary: 'Create Jira / ServiceNow ticket' } },

      '/api/asvs-self':            { get: { tags: ['Self'], summary: 'OWASP ASVS self-attestation' } },
      '/api/sbom-self':            { get: { tags: ['Self'], summary: 'Platform CycloneDX SBOM' } },

      '/scim/v2/Users':            { get: { tags: ['SCIM'], summary: 'List users', security: [{ scimBearer: [] }] }, post: { tags: ['SCIM'], summary: 'Create user', security: [{ scimBearer: [] }] } },
      '/scim/v2/Users/{id}':       { get: { tags: ['SCIM'], security: [{ scimBearer: [] }] }, put: { tags: ['SCIM'], security: [{ scimBearer: [] }] }, patch: { tags: ['SCIM'], security: [{ scimBearer: [] }] }, delete: { tags: ['SCIM'], security: [{ scimBearer: [] }] } }
    },
    security: [{ cookieSession: [] }, { bearerApiKey: [] }]
  });
});
