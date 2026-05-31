// Package viewer — renders the ArbPackage JSON returned by the API
// into the dark-mode dashboard. Sections each get a card; Mermaid
// diagrams render client-side.

(() => {
  const params = new URLSearchParams(window.location.search);
  const id = params.get('id');
  if (!id) { document.getElementById('title').textContent = 'Missing assessment id'; return; }

  const SECTIONS = [
    { id: 'exec', title: 'Executive Summary' },
    { id: 'diff', title: 'Changes Since Last Version' },
    { id: 'cat', title: 'FIPS 199 Categorization' },
    { id: 'class', title: 'Data Classification' },
    { id: 'arch', title: 'Architecture' },
    { id: 'overlay', title: 'Security Overlay' },
    { id: 'dfd', title: 'Data Flow Diagram' },
    { id: 'stride', title: 'STRIDE Threat Model' },
    { id: 'flowstride', title: 'STRIDE per Data Flow' },
    { id: 'mitre', title: 'MITRE ATT&CK Mapping' },
    { id: 'capec', title: 'CAPEC Attack Patterns' },
    { id: 'linddun', title: 'LINDDUN Privacy Threats' },
    { id: 'dpia', title: 'DPIA (GDPR Art. 35)' },
    { id: 'ops', title: 'Operational Threats' },
    { id: 'ssp', title: 'System Security Plan' },
    { id: 'audit', title: 'Auditable Events' },
    { id: 'recovery', title: 'Recovery Assessment' },
    { id: 'cost', title: 'Cost Estimate' },
    { id: 'compliance', title: 'Compliance Mapping' },
    { id: 'waf', title: 'AWS Well-Architected' },
    { id: 'evidence', title: 'Evidence Requests' },
    { id: 'risk', title: 'Residual Risk Register' },
    { id: 'iac', title: 'IaC Reconciliation' },
    { id: 'approval', title: 'Approval Workflow' },
    { id: 'assumptions', title: 'Assumptions' },
    { id: 'clarifications', title: 'Clarifications' }
  ];

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k === 'html') node.innerHTML = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) node.setAttribute(k, v);
    }
    for (const c of children) {
      if (c == null) continue;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return node;
  }

  function badge(level) {
    const cls = level === 'Critical' ? 'crit' : level === 'High' ? 'high' : level === 'Medium' ? 'med' : 'low';
    return el('span', { class: 'badge ' + cls }, level);
  }
  function coverageBadge(level) {
    const cls = level === 'Full' ? 'full' : level === 'Partial' ? 'partial' : 'gap';
    return el('span', { class: 'badge ' + cls }, level);
  }
  function bullets(items, fallback = 'None') {
    if (!items || !items.length) return el('p', { class: 'muted' }, fallback);
    const ul = el('ul');
    for (const i of items) ul.appendChild(el('li', {}, i));
    return ul;
  }
  function table(headers, rows) {
    const t = el('table');
    const thead = el('thead'); const tr = el('tr');
    for (const h of headers) tr.appendChild(el('th', {}, h));
    thead.appendChild(tr); t.appendChild(thead);
    const tb = el('tbody');
    for (const r of rows) {
      const trr = el('tr');
      for (const c of r) trr.appendChild(c instanceof Node ? el('td', {}, c) : el('td', {}, String(c ?? '')));
      tb.appendChild(trr);
    }
    t.appendChild(tb);
    return t;
  }

  function card(id, title, body) {
    const c = el('section', { class: 'card', id });
    c.appendChild(el('h3', {}, title));
    if (Array.isArray(body)) for (const b of body) c.appendChild(b);
    else c.appendChild(body);
    return c;
  }

  async function renderMermaid(node, source) {
    try {
      const { svg } = await window.__mermaid.render('m_' + Math.random().toString(36).slice(2, 8), source);
      node.innerHTML = svg;
    } catch (e) {
      node.innerHTML = '<pre>' + source.replace(/[<>&]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c])) + '</pre>';
    }
  }

  async function load() {
    const [pr, ar, sr] = await Promise.all([
      fetch(`/api/generate/${id}`),
      fetch(`/api/assessments/${id}`),
      fetch('/api/auth/me')
    ]);
    if (!pr.ok) { document.getElementById('title').textContent = 'Package not found'; return; }
    const p = await pr.json();
    const a = ar.ok ? await ar.json() : null;
    window.__session = sr.ok ? await sr.json() : null;
    render(a, p);
  }

  function render(a, p) {
    document.getElementById('title').textContent = (a && a.business.applicationName) || 'ARB Package';
    document.getElementById('subtitle').textContent = `Generated ${new Date(p.generatedAt).toLocaleString()} · Category ${p.categorization.overallCategorization} · Posture ${p.executiveSummary.riskPosture}`;
    const toc = document.getElementById('package-toc');
    for (const s of SECTIONS) toc.appendChild(el('a', { href: '#' + s.id }, s.title));

    const xr = document.getElementById('export-row');
    for (const fmt of ['html', 'md', 'json', 'pdf']) {
      xr.appendChild(el('a', { class: 'btn secondary', href: `/api/export/${id}.${fmt}` }, fmt.toUpperCase()));
    }
    xr.appendChild(el('a', { class: 'btn secondary', href: `/api/export/${id}.oscal.json`, title: 'NIST OSCAL System Security Plan' }, 'OSCAL'));
    for (const csv of ['ssp', 'evidence', 'residual-risk', 'audit-events', 'stride', 'cost', 'compliance']) {
      xr.appendChild(el('a', { class: 'btn secondary', href: `/api/export/${id}.${csv}.csv`, title: `${csv} CSV` }, `CSV: ${csv}`));
    }
    xr.appendChild(el('a', { class: 'btn', href: '/dashboard.html' }, 'Dashboard'));

    const root = document.getElementById('content');

    // Validation banner
    if (!p.validationReport.passed) {
      const banner = el('div', { class: 'alert error' });
      banner.appendChild(el('strong', {}, 'Validation issues detected: '));
      banner.appendChild(document.createTextNode(p.validationReport.issues.map(i => `[${i.severity}] ${i.field}: ${i.message}`).join(' · ')));
      root.appendChild(banner);
    }

    // Executive Summary
    root.appendChild(card('exec', 'Executive Summary', [
      el('p', { html: `<strong>${p.executiveSummary.oneLiner}</strong>` }),
      el('p', {}, p.executiveSummary.businessContext),
      (() => {
        const kv = el('dl', { class: 'kv' });
        kv.appendChild(el('dt', {}, 'Risk posture')); kv.appendChild(el('dd', {}, badge(p.executiveSummary.riskPosture === 'High' ? 'High' : p.executiveSummary.riskPosture === 'Elevated' ? 'Medium' : 'Low')));
        kv.appendChild(el('dt', {}, 'Recommendation')); kv.appendChild(el('dd', {}, p.executiveSummary.goNoGoAdvice));
        return kv;
      })(),
      el('h4', {}, 'Conditions'),
      bullets(p.executiveSummary.conditions, 'No conditions.'),
      el('h4', {}, 'Top Residual Risks'),
      bullets(p.executiveSummary.topRisks, 'No high/critical residual risks.'),
      el('h4', {}, 'Key Recommendations'),
      bullets(p.executiveSummary.keyRecommendations)
    ]));

    // Categorization
    const catKv = el('dl', { class: 'kv' });
    catKv.appendChild(el('dt', {}, 'Confidentiality')); catKv.appendChild(el('dd', {}, p.categorization.confidentialityImpact));
    catKv.appendChild(el('dt', {}, 'Integrity')); catKv.appendChild(el('dd', {}, p.categorization.integrityImpact));
    catKv.appendChild(el('dt', {}, 'Availability')); catKv.appendChild(el('dd', {}, p.categorization.availabilityImpact));
    catKv.appendChild(el('dt', {}, 'Overall')); catKv.appendChild(el('dd', { html: `<strong>${p.categorization.overallCategorization}</strong> (high-water mark)` }));
    root.appendChild(card('cat', 'FIPS 199 Categorization', [
      catKv,
      el('h4', {}, 'Information Types'),
      table(['Code', 'Name', 'C', 'I', 'A', 'Basis'], p.categorization.informationTypes.map(i => [i.code, i.name, i.confidentiality, i.integrity, i.availability, i.basisInAssessment])),
      el('h4', {}, 'Rationale'), bullets(p.categorization.rationale)
    ]));

    // Data classification
    root.appendChild(card('class', 'Data Classification', [
      el('p', { html: `<strong>Primary classification:</strong> ${p.dataClassification.primaryClassification}` }),
      el('h4', {}, 'Handling requirements'),
      bullets(p.dataClassification.handlingRequirements),
      el('p', { html: `<strong>Retention:</strong> ${p.dataClassification.retentionGuidance}` }),
      el('p', { html: `<strong>Disposition:</strong> ${p.dataClassification.dispositionGuidance}` })
    ]));

    // Architecture diagram
    const archDiv = el('pre', { class: 'mermaid' });
    root.appendChild(card('arch', 'Architecture Diagram', archDiv));
    renderMermaid(archDiv, p.architectureDiagramMermaid);

    // Security overlay
    const overlayDiv = el('pre', { class: 'mermaid' });
    root.appendChild(card('overlay', 'Security Overlay', overlayDiv));
    renderMermaid(overlayDiv, p.securityOverlayDiagramMermaid);

    // DFD
    const dfdDiv = el('pre', { class: 'mermaid' });
    root.appendChild(card('dfd', 'Data Flow Diagram', dfdDiv));
    renderMermaid(dfdDiv, p.dataFlowDiagramMermaid);

    // Components table
    root.appendChild(card('arch_components', 'Architecture Components', [
      table(
        ['Component', 'Layer', 'AWS Service', 'Trust Zone', 'Sensitive', 'Rationale'],
        p.architecture.components.map(c => [c.name, c.layer, c.awsService || '—', c.trustZone, c.containsSensitiveData ? 'yes' : 'no', c.rationale])
      ),
      el('h4', {}, 'Why these choices'),
      bullets(p.architecture.rationale)
    ]));

    // STRIDE
    root.appendChild(card('stride', 'STRIDE Threat Model', [
      table(
        ['Component', 'Category', 'Likelihood', 'Impact', 'Inherent', 'Residual', 'Mitigations'],
        p.threatModel.map(t => [t.componentName, t.category, t.likelihood, t.impact, badge(t.inherentRisk), badge(t.residualRisk), t.mitigations.join(', ')])
      )
    ]));

    // Operational threats
    root.appendChild(card('ops', 'Operational Threats', [
      table(
        ['Category', 'Likelihood', 'Impact', 'Description', 'Recommendation', 'Controls'],
        p.operationalThreatModel.map(o => [o.category, o.likelihood, o.impact, o.description, o.recommendation, o.controlReferences.join(', ')])
      )
    ]));

    // SSP
    const sspBody = el('div');
    for (const c of p.ssp) {
      const det = el('details');
      det.appendChild(el('summary', { html: `<strong>${c.id} — ${c.name}</strong> <span class="muted">(${c.family}) · ${c.inheritance} · ${c.implementationStatus}</span>` }));
      det.appendChild(el('p', { html: `<strong>Implementation:</strong> ${escapeHtml(c.implementationStatement)}` }));
      det.appendChild(el('p', { html: `<strong>Evidence:</strong> ${escapeHtml(c.evidence.join('; '))}` }));
      det.appendChild(el('p', { html: `<strong>CIS v8:</strong> ${escapeHtml(c.cisMappings.join(', ') || '—')} &nbsp;|&nbsp; <strong>Responsible:</strong> ${escapeHtml(c.responsibleParty)}` }));
      det.appendChild(el('p', { class: 'muted', html: `<strong>Rationale:</strong> ${escapeHtml(c.rationale)}` }));
      det.appendChild(el('p', { class: 'muted', html: `<strong>Assessment guidance:</strong> ${escapeHtml(c.assessmentGuidance)}` }));
      sspBody.appendChild(det);
    }
    root.appendChild(card('ssp', `System Security Plan (NIST 800-53 Rev 5) — ${p.ssp.length} controls`, sspBody));

    // Audit events
    root.appendChild(card('audit', 'Auditable Events', [
      table(
        ['Event', 'Source', 'CIA', 'Retention', 'Alerting', 'Severity', 'Controls'],
        p.auditableEvents.map(e => [e.name, e.source, e.ciaMapping.join('/'), e.retentionDays + 'd', e.alerting, e.severityOnAlert, e.controlReferences.join(', ')])
      )
    ]));

    // Recovery
    const recKv = el('dl', { class: 'kv' });
    recKv.appendChild(el('dt', {}, 'RTO')); recKv.appendChild(el('dd', {}, p.recovery.rto));
    recKv.appendChild(el('dt', {}, 'RPO')); recKv.appendChild(el('dd', {}, p.recovery.rpo));
    recKv.appendChild(el('dt', {}, 'Tier')); recKv.appendChild(el('dd', {}, p.recovery.availabilityTier));
    recKv.appendChild(el('dt', {}, 'Multi-AZ')); recKv.appendChild(el('dd', {}, String(p.recovery.multiAz)));
    recKv.appendChild(el('dt', {}, 'Multi-Region')); recKv.appendChild(el('dd', {}, String(p.recovery.multiRegion)));
    recKv.appendChild(el('dt', {}, 'Backup')); recKv.appendChild(el('dd', {}, p.recovery.backupStrategy));
    recKv.appendChild(el('dt', {}, 'Restore Testing')); recKv.appendChild(el('dd', {}, p.recovery.restoreTestingCadence));
    recKv.appendChild(el('dt', {}, 'Failover')); recKv.appendChild(el('dd', {}, p.recovery.failoverApproach));
    root.appendChild(card('recovery', 'Recovery Assessment', [
      recKv,
      el('h4', {}, 'Gaps'), bullets(p.recovery.gaps),
      el('h4', {}, 'Recommendations'), bullets(p.recovery.recommendations)
    ]));

    // Compliance
    root.appendChild(card('compliance', 'Compliance Mapping', [
      table(
        ['Framework', 'Control', 'Description', 'Coverage', 'NIST Controls'],
        p.complianceMappings.map(m => [m.framework, m.controlId, m.description, coverageBadge(m.coverage), m.satisfiedByControlIds.join(', ') || '—'])
      )
    ]));

    // WAF
    const wafDiv = el('div');
    for (const w of p.wellArchitected) {
      const c = el('div', { class: 'card' });
      c.appendChild(el('h4', { html: `${w.pillar}: <strong>${w.score}/100</strong>` }));
      const bar = el('div', { class: 'score-bar' });
      bar.appendChild(el('div', { class: 'fill', style: `width:${w.score}%` }));
      c.appendChild(bar);
      c.appendChild(el('h5', {}, 'Findings'));
      c.appendChild(bullets(w.findings));
      c.appendChild(el('h5', {}, 'Recommendations'));
      c.appendChild(bullets(w.recommendations));
      wafDiv.appendChild(c);
    }
    root.appendChild(card('waf', 'AWS Well-Architected Scoring', wafDiv));

    // Evidence
    root.appendChild(card('evidence', 'Evidence Requests', [
      table(
        ['Control', 'Artifact', 'Method', 'Responsible', 'Acceptance'],
        p.evidenceRequests.map(e => [e.controlId, e.artifact, e.collectionMethod, e.responsibleParty, e.acceptanceCriteria])
      )
    ]));

    // Risk
    root.appendChild(card('risk', 'Residual Risk Register', [
      table(
        ['ID', 'Source', 'Inherent', 'Residual', 'Treatment', 'Owner', 'Description'],
        p.residualRisks.map(r => [r.id, r.source, badge(r.inherentRisk), badge(r.residualRisk), r.treatment, r.owner, r.description])
      )
    ]));

    // Assumptions
    const ulA = el('ul');
    for (const s of p.assumptions) ulA.appendChild(el('li', { html: `${escapeHtml(s.text)} <br/><span class="muted">Basis: ${escapeHtml(s.basis)}</span>` }));
    root.appendChild(card('assumptions', 'Security Assumptions', ulA));

    // Clarifications
    if (p.clarifications.length) {
      const ulC = el('ul');
      for (const c of p.clarifications) ulC.appendChild(el('li', { html: `<strong>${escapeHtml(c.field)}:</strong> ${escapeHtml(c.question)} <br/><span class="muted">${escapeHtml(c.reason)}</span>` }));
      root.appendChild(card('clarifications', 'Clarification Questions', ulC));
    }

    // ---- New sections (M16-M22) ----

    // Diff
    if (p.diff) {
      root.appendChild(card('diff', `Changes Since v${p.diff.fromVersion} (now v${p.diff.toVersion})`, [
        bullets(p.diff.highlights),
        el('p', { class: 'muted' }, `Generated ${new Date(p.diff.fromGeneratedAt).toLocaleString()} → ${new Date(p.diff.toGeneratedAt).toLocaleString()}`)
      ]));
    } else {
      root.appendChild(card('diff', 'Changes Since Last Version', el('p', { class: 'muted' }, 'First version of this assessment — nothing to compare against.')));
    }

    // STRIDE per data flow
    root.appendChild(card('flowstride', `STRIDE per Data Flow (${p.flowThreatModel.length})`, table(
      ['Flow', 'From', 'To', 'Category', 'Inherent', 'Residual', 'Mitigations'],
      p.flowThreatModel.map(f => [f.flowLabel, f.fromComponentName, f.toComponentName, f.category, badge(f.inherentRisk), badge(f.residualRisk), f.mitigations.join(', ')])
    )));

    // MITRE
    root.appendChild(card('mitre', `MITRE ATT&CK Mapping (${p.mitreMappings.length})`, table(
      ['Tactic', 'Technique', 'Component', 'STRIDE'],
      p.mitreMappings.map(m => {
        const f = p.threatModel[m.strideFindingIndex] || {};
        return [`${m.attackTacticId} ${m.attackTacticName}`, `${m.attackTechniqueId} ${m.attackTechniqueName}`, f.componentName || '—', f.category || '—'];
      })
    )));

    // CAPEC
    root.appendChild(card('capec', `CAPEC Attack Patterns (${p.capecReferences.length})`, table(
      ['CAPEC', 'Name', 'STRIDE Categories', 'Components'],
      p.capecReferences.map(c => [c.capecId, c.name, c.strideCategories.join(', '), c.appliesToComponentIds.length])
    )));

    // LINDDUN
    if (p.linddunFindings.length) {
      root.appendChild(card('linddun', `LINDDUN Privacy Threats (${p.linddunFindings.length})`, table(
        ['Component', 'Category', 'Severity', 'Affected', 'Recommendation', 'Controls'],
        p.linddunFindings.map(l => [l.componentName, l.category, badge(l.severity === 'High' ? 'High' : l.severity === 'Medium' ? 'Medium' : 'Low'), l.affectedData.join(', '), l.recommendation, l.mitigationControls.join(', ')])
      )));
    } else {
      root.appendChild(card('linddun', 'LINDDUN Privacy Threats', el('p', { class: 'muted' }, 'Not emitted — no personal data declared in this assessment.')));
    }

    // DPIA
    if (p.dpia) {
      const kvD = el('dl', { class: 'kv' });
      kvD.appendChild(el('dt', {}, 'Conclusion')); kvD.appendChild(el('dd', {}, p.dpia.conclusion));
      kvD.appendChild(el('dt', {}, 'Subjects')); kvD.appendChild(el('dd', {}, p.dpia.dataSubjectCategories.join(', ')));
      root.appendChild(card('dpia', 'DPIA — GDPR Article 35', [
        kvD,
        el('h4', {}, 'Lawful bases'), bullets(p.dpia.lawfulBases),
        p.dpia.specialCategoryBases.length ? el('div', {}, el('h4', {}, 'Special category bases (Art. 9)'), bullets(p.dpia.specialCategoryBases)) : el('div'),
        el('h4', {}, 'Processing activities'),
        table(['Activity', 'Purpose', 'Lawful basis'], p.dpia.processingActivities.map(x => [x.activity, x.purpose, x.lawfulBasis])),
        el('h4', {}, 'Transfers'),
        table(['Destination', 'Mechanism', 'Safeguards'], p.dpia.dataTransfers.map(x => [x.destination, x.mechanism, x.safeguards])),
        el('h4', {}, 'Risks'),
        table(['Description', 'Likelihood', 'Severity', 'Mitigation'], p.dpia.risks.map(x => [x.description, x.likelihood, x.severity, x.mitigation])),
        el('h4', {}, 'Data subject rights'),
        table(['Right', 'Mechanism'], p.dpia.rightsHandling.map(x => [x.right, x.mechanism]))
      ]));
    } else {
      root.appendChild(card('dpia', 'DPIA — GDPR Article 35', el('p', { class: 'muted' }, 'Not emitted — GDPR/CCPA not in scope and no personal data declared.')));
    }

    // Cost
    root.appendChild(card('cost', `Cost Estimate — Tier ${p.costEstimate.tier}: $${p.costEstimate.monthlyLowUsd.toLocaleString()} – $${p.costEstimate.monthlyHighUsd.toLocaleString()} ${p.costEstimate.currency}/mo`, [
      table(['Driver', 'Low/mo', 'High/mo', 'Rationale'], p.costEstimate.drivers.map(d => [d.item, '$' + d.lowUsd.toLocaleString(), '$' + d.highUsd.toLocaleString(), d.rationale])),
      el('h4', {}, 'Notes'), bullets(p.costEstimate.notes)
    ]));

    // IaC
    if (p.iacReconciliation) {
      const ir = p.iacReconciliation;
      root.appendChild(card('iac', `IaC Reconciliation (${ir.format})`, [
        el('p', {}, ir.summary),
        el('h4', {}, `Matched (${ir.matched.length})`),
        table(['Expected', 'Observed type', 'Observed name'], ir.matched.map(m => [m.expectedId, m.observedType, m.observedName])),
        el('h4', {}, `Missing from IaC (${ir.missing.length})`),
        table(['Component', 'Layer'], ir.missing.map(m => [m.expectedName, m.layer])),
        el('h4', {}, `Unexpected in IaC (${ir.unexpected.length})`),
        table(['Type', 'Name'], ir.unexpected.map(u => [u.observedType, u.observedName])),
        ir.encryptionMismatches.length
          ? el('div', {}, el('h4', {}, 'Encryption mismatches'),
              table(['Component', 'Expected', 'Observed'], ir.encryptionMismatches.map(e => [e.component, e.expected, e.observed])))
          : el('div')
      ]));
    } else {
      root.appendChild(card('iac', 'IaC Reconciliation', el('p', { class: 'muted' }, 'No IaC attached. Upload Terraform plan / CloudFormation / CDK synth from the wizard.')));
    }

    // Approval — fetched live, since the request can change after generation
    const apvCard = card('approval', 'Approval Workflow', el('div', { class: 'muted' }, 'Loading…'));
    root.appendChild(apvCard);
    fetch(`/api/approval/${id}`).then(r => r.json()).then(j => {
      const body = el('div');
      const me = (window.__session || {});
      if (!j.approvalRequest) {
        body.appendChild(el('p', { class: 'muted' }, 'No approval request open. Owners can request sign-off below.'));
        const req = el('button', { onclick: async () => { await apiFetch(`/api/approval/${id}/request`, { method: 'POST', body: '{}' }); window.location.reload(); } }, 'Request Approval');
        body.appendChild(req);
      } else {
        const r = j.approvalRequest;
        body.appendChild(el('p', { html: `Requested by <strong>${escapeHtml(r.requestedBy)}</strong> at ${escapeHtml(r.requestedAt)} — status: <strong>${escapeHtml(r.status)}</strong>` }));
        body.appendChild(el('p', { class: 'muted', html: `Package hash signed: <code>${escapeHtml(r.packageHash).slice(0, 16)}…</code>` }));
        const tbl = table(['Role', 'Required', 'Decision', 'Signed by', 'At', 'Comment'],
          ['security', 'risk', 'architecture', 'compliance'].map(role => {
            const sig = r.approvals.find(s => s.role === role);
            return [role, r.requiredRoles.includes(role) ? 'yes' : 'no', sig ? sig.decision : '—', sig ? sig.displayName : '—', sig ? sig.signedAt : '—', sig?.comment || ''];
          }));
        body.appendChild(tbl);
        if (r.status === 'open' && me && me.session) {
          const myApproverRoles = me.session.roles.filter(x => x.startsWith('approver-')).map(x => x.replace('approver-', ''));
          for (const role of myApproverRoles) {
            const form = el('div', { style: 'margin-top:.5rem' });
            form.appendChild(el('label', {}, `Sign as ${role}: comment`));
            const txt = el('input', { type: 'text' });
            const ok = el('button', { onclick: async () => {
              await apiFetch(`/api/approval/${id}/sign`, { method: 'POST', body: JSON.stringify({ role, decision: 'approve', comment: txt.value }) });
              window.location.reload();
            } }, 'Approve');
            const no = el('button', { class: 'danger', onclick: async () => {
              await apiFetch(`/api/approval/${id}/sign`, { method: 'POST', body: JSON.stringify({ role, decision: 'reject', comment: txt.value }) });
              window.location.reload();
            } }, 'Reject');
            form.appendChild(txt); form.appendChild(ok); form.appendChild(no);
            body.appendChild(form);
          }
        }
      }
      apvCard.querySelector('div').replaceWith(body);
    }).catch(() => { apvCard.querySelector('div').textContent = 'Failed to load approval status.'; });
  }

  function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  load();
})();
