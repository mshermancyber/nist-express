// Pre-built assessment templates. Each template fills the wizard with
// sensible defaults for a common system archetype. Users then refine
// any field before generating.

import { Assessment } from '../types/assessment';

type TemplateBody = Omit<Assessment, 'id' | 'createdAt' | 'updatedAt' | 'status'>;

export interface TemplateDef {
  id: string;
  name: string;
  description: string;
  body: TemplateBody;
}

export const TEMPLATES: TemplateDef[] = [
  {
    id: 'saas-standard',
    name: 'Standard SaaS Application',
    description: 'Multi-tenant customer-facing SaaS with PII, public sign-up, SOC2 + GDPR scope.',
    body: {
      business: { applicationName: 'New SaaS Product', businessProblem: 'Customer-facing SaaS replacing a legacy vendor.', userTypes: ['Customers', 'Public Users', 'Employees'], userInteractionDescription: 'Customers self-onboard via web; staff use an internal admin console.' },
      data: { dataCategories: ['Customer Information', 'Operational Data'], confidentialToCompany: true, sensitiveDataTags: ['PII'] },
      impact: { confidentialityWorstCase: 'Regulatory action, customer trust loss', integrityWorstCase: 'Financial loss', availabilityWorstCase: 'Customer outage and SLA penalties' },
      recovery: { rto: '4 Hours', rpo: '1 Hour' },
      population: { userCount: '1000-10000', expectedGrowth: 'Step changes with sales cycles' },
      integrations: [{ source: 'SaaS', destination: 'Stripe', protocol: 'HTTPS', authentication: 'API Key', dataDirection: 'bidirectional' }],
      compliance: { frameworks: ['SOC2', 'GDPR', 'NIST CSF 2.0'] },
      hosting: { model: 'AWS' }
    }
  },
  {
    id: 'microservice-internal',
    name: 'Internal Microservice',
    description: 'Single-purpose internal microservice consumed by other internal services.',
    body: {
      business: { applicationName: 'New Internal Microservice', businessProblem: 'Extracts a capability from a monolith for reuse.', userTypes: ['Employees', 'System-to-System'], userInteractionDescription: 'Other internal services call this via REST/gRPC.' },
      data: { dataCategories: ['Operational Data'], confidentialToCompany: true, sensitiveDataTags: [] },
      impact: { confidentialityWorstCase: 'Internal operational disruption', integrityWorstCase: 'Incorrect downstream decisions', availabilityWorstCase: 'Dependent services fail' },
      recovery: { rto: '4 Hours', rpo: '1 Hour' },
      population: { userCount: 'Under 100', expectedGrowth: 'Flat' },
      integrations: [],
      compliance: { frameworks: ['Internal Policy Only', 'SOC2'] },
      hosting: { model: 'AWS' }
    }
  },
  {
    id: 'data-warehouse',
    name: 'Data Warehouse / Analytics',
    description: 'Centralised analytics warehouse with regulated data and broad enterprise consumption.',
    body: {
      business: { applicationName: 'Enterprise Data Warehouse', businessProblem: 'Single source of truth for cross-domain analytics.', userTypes: ['Employees', 'Contractors', 'System-to-System'], userInteractionDescription: 'Analysts query via BI tools; pipelines load from operational systems.' },
      data: { dataCategories: ['Customer Information', 'Financial Data', 'Operational Data', 'Employee Information'], confidentialToCompany: true, sensitiveDataTags: ['PII', 'Regulated Data'] },
      impact: { confidentialityWorstCase: 'Regulatory fines and lawsuits', integrityWorstCase: 'Incorrect business decisions; material financial loss', availabilityWorstCase: 'Decision latency and analyst impact' },
      recovery: { rto: '24 Hours', rpo: '1 Hour' },
      population: { userCount: '1000-10000', expectedGrowth: '20% YoY data volume' },
      integrations: [{ source: 'Warehouse', destination: 'Looker', protocol: 'HTTPS', authentication: 'OAuth2', dataDirection: 'outbound' }],
      compliance: { frameworks: ['SOC2', 'GDPR', 'NIST 800-53'] },
      hosting: { model: 'AWS' }
    }
  },
  {
    id: 'ai-enabled',
    name: 'AI-Enabled Product',
    description: 'Customer-facing product with a generative-AI feature; under the EU AI Act and NIST AI RMF.',
    body: {
      business: { applicationName: 'AI-Enabled Product', businessProblem: 'Augments a workflow with generative AI.', userTypes: ['Customers', 'Public Users'], userInteractionDescription: 'Users send natural-language prompts; the product calls an LLM and returns structured results.' },
      data: { dataCategories: ['Customer Information', 'Source Code', 'Intellectual Property'], confidentialToCompany: true, sensitiveDataTags: ['PII', 'Trade Secrets'] },
      impact: { confidentialityWorstCase: 'Disclosure of customer prompts containing PII triggers regulatory action', integrityWorstCase: 'Hallucinated outputs drive incorrect customer decisions', availabilityWorstCase: 'Customer-facing outage' },
      recovery: { rto: '1 Hour', rpo: '15 Minutes' },
      population: { userCount: '10000+', expectedGrowth: 'Aggressive growth' },
      integrations: [{ source: 'AI Product', destination: 'OpenAI', protocol: 'HTTPS', authentication: 'API Key', dataDirection: 'bidirectional' }],
      compliance: { frameworks: ['SOC2', 'GDPR', 'EU AI Act', 'NIST AI RMF'] },
      hosting: { model: 'AWS' }
    }
  },
  {
    id: 'mobile-backend',
    name: 'Mobile App Backend',
    description: 'BFF / API tier for native mobile clients with public sign-up.',
    body: {
      business: { applicationName: 'Mobile Backend', businessProblem: 'Backend-for-frontend for the consumer mobile apps.', userTypes: ['Customers', 'Public Users', 'System-to-System'], userInteractionDescription: 'iOS/Android clients call REST endpoints over the public internet.' },
      data: { dataCategories: ['Customer Information'], confidentialToCompany: true, sensitiveDataTags: ['PII'] },
      impact: { confidentialityWorstCase: 'Regulatory action and customer trust loss', integrityWorstCase: 'Financial loss from compromised transactions', availabilityWorstCase: 'Customer outage and app store backlash' },
      recovery: { rto: '1 Hour', rpo: '15 Minutes' },
      population: { userCount: '10000+', expectedGrowth: 'Spiky around marketing campaigns' },
      integrations: [{ source: 'Mobile Backend', destination: 'Push Notification Service', protocol: 'HTTPS', authentication: 'API Key', dataDirection: 'outbound' }],
      compliance: { frameworks: ['SOC2', 'GDPR', 'CCPA'] },
      hosting: { model: 'AWS' }
    }
  }
];

export function getTemplate(id: string): TemplateDef | undefined {
  return TEMPLATES.find(t => t.id === id);
}
