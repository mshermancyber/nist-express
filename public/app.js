// Wizard frontend. Builds the 8 sections + advanced overrides
// declaratively, syncs to /api/assessments, and routes to /view.html
// after a successful generation. No framework — keeps the bundle
// negligible and the codebase auditable.

(() => {
  const SECTIONS = [
    { id: 'business', title: '1. Business Overview' },
    { id: 'data', title: '2. Data Classification' },
    { id: 'impact', title: '3. Business Impact' },
    { id: 'recovery', title: '4. Recovery Requirements' },
    { id: 'population', title: '5. User Population' },
    { id: 'integrations', title: '6. Integrations' },
    { id: 'compliance', title: '7. Compliance' },
    { id: 'hosting', title: '8. Hosting Model' },
    { id: 'advanced', title: '+ Advanced (Technical)' }
  ];

  const ENUMS = {
    userTypes: ['Employees', 'Customers', 'Vendors', 'Partners', 'Public Users', 'Contractors', 'System-to-System'],
    dataCategories: ['Customer Information', 'Employee Information', 'Financial Data', 'Source Code', 'Intellectual Property', 'Operational Data', 'Public Information'],
    sensitive: ['PII', 'PCI', 'PHI', 'Trade Secrets', 'Regulated Data', 'Export Controlled Data'],
    rto: ['15 Minutes', '1 Hour', '4 Hours', '24 Hours', '72 Hours'],
    rpo: ['No Data Loss', '15 Minutes', '1 Hour', '24 Hours'],
    population: ['Under 100', '100-1000', '1000-10000', '10000+'],
    compliance: ['NIST 800-53', 'NIST 800-171', 'CMMC', 'NIST CSF 2.0', 'NIST AI RMF', 'EU AI Act', 'SOC2', 'ISO 27001', 'PCI DSS', 'HIPAA', 'HITRUST CSF', 'FedRAMP', 'GDPR', 'CCPA', 'DORA', 'FFIEC', 'IRS Pub 1075', 'Internal Policy Only'],
    hosting: ['AWS', 'Azure', 'GCP', 'Hybrid', 'On-Prem'],
    protocol: ['HTTPS', 'TLS', 'SFTP', 'gRPC', 'JDBC/ODBC', 'AMQP', 'Kafka', 'Other'],
    auth: ['OAuth2', 'SAML', 'API Key', 'mTLS', 'Service Account', 'Basic Auth', 'None'],
    direction: ['inbound', 'outbound', 'bidirectional']
  };

  // Default empty model — typed loosely; server-side zod is authoritative.
  function emptyModel() {
    return {
      business: { applicationName: '', businessArea: '', businessProblem: '', userTypes: [], userInteractionDescription: '' },
      data: { dataCategories: [], confidentialToCompany: false, sensitiveDataTags: [] },
      impact: { confidentialityWorstCase: '', integrityWorstCase: '', availabilityWorstCase: '' },
      recovery: { rto: '4 Hours', rpo: '1 Hour' },
      population: { userCount: 'Under 100', expectedGrowth: '' },
      integrations: [],
      compliance: { frameworks: [] },
      hosting: { model: 'AWS' },
      advanced: {}
    };
  }

  let currentSection = 0;
  let currentId = null;
  const model = emptyModel();

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else if (k === 'html') node.innerHTML = v;
      else if (v !== false && v != null) node.setAttribute(k, v);
    }
    for (const c of children) {
      if (c == null) continue;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return node;
  }

  function renderSteps() {
    const wrap = document.getElementById('steps');
    wrap.innerHTML = '';
    for (let i = 0; i < SECTIONS.length; i++) {
      const s = SECTIONS[i];
      const cls = i === currentSection ? 'active' : i < currentSection ? 'done' : '';
      const btn = el('button', { class: cls, type: 'button', onclick: () => { currentSection = i; renderAll(); } }, s.title);
      wrap.appendChild(btn);
    }
  }

  function checkboxGroup(values, current, onchange) {
    const wrap = el('div', { class: 'checkbox-group' });
    for (const v of values) {
      const id = 'cb_' + Math.random().toString(36).slice(2, 8);
      const cb = el('input', { type: 'checkbox', id, ...(current.includes(v) ? { checked: 'checked' } : {}) });
      cb.addEventListener('change', () => onchange(v, cb.checked));
      wrap.appendChild(el('label', { for: id }, cb, ' ' + v));
    }
    return wrap;
  }

  function selectInput(values, current, onchange) {
    const sel = el('select');
    for (const v of values) {
      const opt = el('option', { value: v }, v);
      if (v === current) opt.setAttribute('selected', 'selected');
      sel.appendChild(opt);
    }
    sel.addEventListener('change', () => onchange(sel.value));
    return sel;
  }

  function renderSection() {
    const form = document.getElementById('wizard');
    form.innerHTML = '';
    const s = SECTIONS[currentSection];
    const card = el('div', { class: 'card' });
    card.appendChild(el('h3', {}, s.title));

    if (s.id === 'business') {
      card.appendChild(el('label', {}, 'Application name'));
      const an = el('input', { type: 'text', value: model.business.applicationName, placeholder: 'e.g. Customer Onboarding Portal' });
      an.addEventListener('input', () => model.business.applicationName = an.value);
      card.appendChild(an);
      card.appendChild(el('label', {}, 'Which business area will this support?'));
      const ba = el('input', { type: 'text', value: model.business.businessArea || '', placeholder: 'e.g. Finance, HR, Customer Operations' });
      ba.addEventListener('input', () => model.business.businessArea = ba.value);
      card.appendChild(ba);
      card.appendChild(el('label', {}, 'What business problem does it solve?'));
      const bp = el('textarea', {}, model.business.businessProblem);
      bp.addEventListener('input', () => model.business.businessProblem = bp.value);
      card.appendChild(bp);
      card.appendChild(el('label', {}, 'Who will use the application? (select all that apply)'));
      card.appendChild(checkboxGroup(ENUMS.userTypes, model.business.userTypes, (v, c) => {
        if (c) model.business.userTypes.push(v);
        else model.business.userTypes = model.business.userTypes.filter(x => x !== v);
      }));
      card.appendChild(el('label', {}, 'Describe how users will interact with the application'));
      const ui = el('textarea', {}, model.business.userInteractionDescription);
      ui.addEventListener('input', () => model.business.userInteractionDescription = ui.value);
      card.appendChild(ui);
    } else if (s.id === 'data') {
      card.appendChild(el('label', {}, 'What information will be stored or processed?'));
      card.appendChild(checkboxGroup(ENUMS.dataCategories, model.data.dataCategories, (v, c) => {
        if (c) model.data.dataCategories.push(v);
        else model.data.dataCategories = model.data.dataCategories.filter(x => x !== v);
      }));
      card.appendChild(el('label', {}, 'Does the information need to remain confidential to the company?'));
      const conf = el('select');
      for (const opt of ['No', 'Yes']) {
        const o = el('option', { value: opt }, opt);
        if ((opt === 'Yes') === !!model.data.confidentialToCompany) o.setAttribute('selected', 'selected');
        conf.appendChild(o);
      }
      conf.addEventListener('change', () => model.data.confidentialToCompany = conf.value === 'Yes');
      card.appendChild(conf);
      card.appendChild(el('div', { class: 'alert info' }, 'If Yes, the platform automatically enforces MFA and recommends Okta integration.'));
      card.appendChild(el('label', {}, 'Does the information contain any of the following?'));
      card.appendChild(checkboxGroup(ENUMS.sensitive, model.data.sensitiveDataTags, (v, c) => {
        if (c) model.data.sensitiveDataTags.push(v);
        else model.data.sensitiveDataTags = model.data.sensitiveDataTags.filter(x => x !== v);
      }));
    } else if (s.id === 'impact') {
      const fields = [
        ['confidentialityWorstCase', 'If this information became public, what is the worst business outcome?'],
        ['integrityWorstCase', 'If information were modified or corrupted, what is the worst business outcome?'],
        ['availabilityWorstCase', 'If the application became unavailable, what is the worst business outcome?']
      ];
      for (const [k, q] of fields) {
        card.appendChild(el('label', {}, q));
        const ta = el('textarea', { placeholder: 'e.g. regulatory fine, financial loss, competitive disadvantage…' }, model.impact[k]);
        ta.addEventListener('input', () => model.impact[k] = ta.value);
        card.appendChild(ta);
      }
    } else if (s.id === 'recovery') {
      card.appendChild(el('label', {}, 'How long can the application be unavailable before serious business impact occurs? (RTO)'));
      card.appendChild(selectInput(ENUMS.rto, model.recovery.rto, v => model.recovery.rto = v));
      card.appendChild(el('label', {}, 'How much data loss is acceptable? (RPO)'));
      card.appendChild(selectInput(ENUMS.rpo, model.recovery.rpo, v => model.recovery.rpo = v));
    } else if (s.id === 'population') {
      card.appendChild(el('label', {}, 'Approximate user count'));
      card.appendChild(selectInput(ENUMS.population, model.population.userCount, v => model.population.userCount = v));
      card.appendChild(el('label', {}, 'Expected growth (free text)'));
      const eg = el('textarea', { placeholder: 'e.g. doubling year-over-year' }, model.population.expectedGrowth);
      eg.addEventListener('input', () => model.population.expectedGrowth = eg.value);
      card.appendChild(eg);
    } else if (s.id === 'integrations') {
      card.appendChild(el('p', { class: 'muted' }, 'List each integration. For each you must provide source, destination, protocol, and authentication method.'));
      const list = el('div');
      function rerender() {
        list.innerHTML = '';
        model.integrations.forEach((integ, i) => {
          const row = el('div', { class: 'integration-row' });
          const src = el('input', { type: 'text', value: integ.source, placeholder: 'Source' });
          src.addEventListener('input', () => integ.source = src.value);
          const dst = el('input', { type: 'text', value: integ.destination, placeholder: 'Destination' });
          dst.addEventListener('input', () => integ.destination = dst.value);
          const proto = selectInput(ENUMS.protocol, integ.protocol, v => integ.protocol = v);
          const auth = selectInput(ENUMS.auth, integ.authentication, v => integ.authentication = v);
          const dir = selectInput(ENUMS.direction, integ.dataDirection, v => integ.dataDirection = v);
          const rm = el('button', { class: 'remove', type: 'button', onclick: () => { model.integrations.splice(i, 1); rerender(); } }, '✕');
          row.append(src, dst, proto, auth, dir, rm);
          list.appendChild(row);
        });
      }
      card.appendChild(list);
      rerender();
      const add = el('button', { class: 'secondary', type: 'button', onclick: () => {
        model.integrations.push({ source: '', destination: '', protocol: 'HTTPS', authentication: 'OAuth2', dataDirection: 'outbound' });
        rerender();
      } }, '+ Add Integration');
      card.appendChild(add);
    } else if (s.id === 'compliance') {
      card.appendChild(el('label', {}, 'Select all compliance frameworks in scope'));
      card.appendChild(checkboxGroup(ENUMS.compliance, model.compliance.frameworks, (v, c) => {
        if (c) model.compliance.frameworks.push(v);
        else model.compliance.frameworks = model.compliance.frameworks.filter(x => x !== v);
      }));
    } else if (s.id === 'hosting') {
      card.appendChild(el('label', {}, 'Where will it be hosted?'));
      card.appendChild(selectInput(ENUMS.hosting, model.hosting.model, v => model.hosting.model = v));
      card.appendChild(el('div', { class: 'alert info' }, 'Default architecture is generated for AWS. Other clouds are accepted; controls inherit accordingly.'));
    } else if (s.id === 'advanced') {
      card.appendChild(el('p', { class: 'muted' }, 'Optional overrides for technical users.'));
      const grid = el('div', { class: 'grid-2' });
      const forceMfa = el('div');
      forceMfa.appendChild(el('label', {}, 'Force MFA (even without confidentiality flag)'));
      forceMfa.appendChild(selectInput(['no', 'yes'], model.advanced.forceMfa ? 'yes' : 'no', v => model.advanced.forceMfa = v === 'yes'));
      grid.appendChild(forceMfa);
      const forceOkta = el('div');
      forceOkta.appendChild(el('label', {}, 'Force Okta integration'));
      forceOkta.appendChild(selectInput(['no', 'yes'], model.advanced.forceOkta ? 'yes' : 'no', v => model.advanced.forceOkta = v === 'yes'));
      grid.appendChild(forceOkta);
      const region = el('div');
      region.appendChild(el('label', {}, 'Preferred AWS region'));
      const ri = el('input', { type: 'text', value: model.advanced.preferredAwsRegion || '', placeholder: 'us-east-1' });
      ri.addEventListener('input', () => model.advanced.preferredAwsRegion = ri.value);
      region.appendChild(ri);
      grid.appendChild(region);
      const multi = el('div');
      multi.appendChild(el('label', {}, 'Multi-region active-active'));
      multi.appendChild(selectInput(['no', 'yes'], model.advanced.multiRegion ? 'yes' : 'no', v => model.advanced.multiRegion = v === 'yes'));
      grid.appendChild(multi);
      const ret = el('div');
      ret.appendChild(el('label', {}, 'Logging retention (days)'));
      const rt = el('input', { type: 'number', min: '1', value: model.advanced.loggingRetentionDays || '' });
      rt.addEventListener('input', () => model.advanced.loggingRetentionDays = Number(rt.value) || undefined);
      ret.appendChild(rt);
      grid.appendChild(ret);
      const inc = el('div');
      inc.appendChild(el('label', {}, 'Custom controls to include (comma-separated IDs)'));
      const ic = el('input', { type: 'text', value: (model.advanced.customControlIds || []).join(', '), placeholder: 'SC-12, SI-7' });
      ic.addEventListener('input', () => model.advanced.customControlIds = ic.value.split(/[,\s]+/).filter(Boolean));
      inc.appendChild(ic);
      grid.appendChild(inc);
      const exc = el('div');
      exc.appendChild(el('label', {}, 'Controls to exclude (comma-separated IDs)'));
      const ec = el('input', { type: 'text', value: (model.advanced.excludeControlIds || []).join(', '), placeholder: '' });
      ec.addEventListener('input', () => model.advanced.excludeControlIds = ec.value.split(/[,\s]+/).filter(Boolean));
      exc.appendChild(ec);
      grid.appendChild(exc);
      card.appendChild(grid);
    }

    form.appendChild(card);

    // Navigation
    const nav = el('div', { class: 'btn-row' });
    if (currentSection > 0) nav.appendChild(el('button', { class: 'secondary', type: 'button', onclick: () => { currentSection--; renderAll(); } }, '← Back'));
    if (currentSection < SECTIONS.length - 1) nav.appendChild(el('button', { type: 'button', onclick: () => { currentSection++; renderAll(); } }, 'Next →'));
    form.appendChild(nav);
  }

  function renderAll() { renderSteps(); renderSection(); }

  async function saveDraft() {
    const status = document.getElementById('status-area');
    status.innerHTML = '';
    const url = currentId ? `/api/assessments/${currentId}` : '/api/assessments';
    const method = currentId ? 'PUT' : 'POST';
    try {
      const r = await apiFetch(url, { method, body: JSON.stringify(model) });
      if (!r.ok) throw new Error((await r.json()).error || ('HTTP ' + r.status));
      const saved = await r.json();
      currentId = saved.id;
      status.appendChild(el('div', { class: 'alert success' }, `Saved draft ${saved.id.slice(0, 8)}…`));
      await refreshSavedList();
    } catch (e) {
      status.appendChild(el('div', { class: 'alert error' }, 'Save failed: ' + e.message));
    }
  }

  async function refreshSavedList() {
    try {
      const r = await fetch('/api/assessments');
      const data = await r.json();
      const list = document.getElementById('saved-list');
      list.innerHTML = '';
      if (!data.assessments.length) {
        list.appendChild(el('span', { class: 'muted', style: 'font-size:.8rem;padding:.5rem .75rem;display:block' }, 'No saved assessments yet.'));
        return;
      }
      for (const a of data.assessments) {
        const row = el('div', { style: 'display:flex;align-items:center;gap:.25rem' });
        const link = el('a', {
          href: '#',
          style: 'flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap',
          onclick: (ev) => { ev.preventDefault(); loadAssessment(a.id); }
        }, a.business.applicationName || `(untitled ${a.id.slice(0, 8)})`);
        const del = el('button', {
          class: 'secondary',
          'aria-label': `Delete assessment ${a.business.applicationName || a.id}`,
          title: 'Delete this assessment',
          style: 'padding:.15rem .45rem;font-size:.85rem;line-height:1',
          onclick: async (ev) => {
            ev.preventDefault(); ev.stopPropagation();
            const name = a.business.applicationName || `(untitled ${a.id.slice(0, 8)})`;
            if (!confirm(`Delete "${name}"? This removes the saved draft and its generated package. This cannot be undone.`)) return;
            try {
              const r = await window.apiFetch(`/api/assessments/${encodeURIComponent(a.id)}`, { method: 'DELETE' });
              if (!r.ok) { alert('Delete failed: ' + r.status); return; }
              if (currentId === a.id) { currentId = null; }
              refreshSavedList();
            } catch (e) { alert('Delete failed: ' + e.message); }
          }
        }, '×');  // multiplication sign — small, unambiguous "delete"
        row.appendChild(link);
        row.appendChild(del);
        list.appendChild(row);
      }
    } catch { /* ignore */ }
  }

  async function loadAssessment(id) {
    try {
      const r = await fetch(`/api/assessments/${id}`);
      if (!r.ok) return;
      const a = await r.json();
      currentId = a.id;
      Object.assign(model, {
        business: a.business, data: a.data, impact: a.impact, recovery: a.recovery,
        population: a.population, integrations: a.integrations, compliance: a.compliance,
        hosting: a.hosting, advanced: a.advanced || {}
      });
      currentSection = 0;
      renderAll();
    } catch { /* ignore */ }
  }

  async function generatePackage() {
    const status = document.getElementById('status-area');
    status.innerHTML = '';
    await saveDraft();
    if (!currentId) return;
    status.appendChild(el('div', { class: 'alert info' }, 'Generating package — this includes categorization, architecture, threat models, SSP, compliance mappings, evidence requests, and the executive summary.'));
    try {
      const r = await apiFetch(`/api/generate/${currentId}`, { method: 'POST' });
      if (!r.ok) throw new Error((await r.json()).error || ('HTTP ' + r.status));
      window.location.href = `/view.html?id=${currentId}`;
    } catch (e) {
      status.appendChild(el('div', { class: 'alert error' }, 'Generation failed: ' + e.message));
    }
  }

  async function refreshAi() {
    try {
      const r = await fetch('/api/generate/ai-status');
      const s = await r.json();
      const pill = document.getElementById('ai-pill');
      pill.className = 'ai-pill ' + (s.configured ? 'on' : 'off');
      pill.textContent = s.configured ? `AI on · ${s.model}` : 'AI off (deterministic)';
      pill.title = s.note || '';
    } catch { /* ignore */ }
  }

  function slugify(name) {
    return (name || 'assessment').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'assessment';
  }

  function downloadJson() {
    const payload = JSON.stringify(model, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `assessment-${slugify(model.business.applicationName)}.json`;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }

  async function loadJsonFile(file) {
    const status = document.getElementById('status-area');
    status.innerHTML = '';
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      status.appendChild(el('div', { class: 'alert error' }, 'File too large (max 5 MB).'));
      return;
    }
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      // Strip id/timestamps if the file came from an exported assessment;
      // the server will treat this as a brand-new draft.
      const body = { ...parsed };
      delete body.id; delete body.createdAt; delete body.updatedAt; delete body.status;
      const r = await apiFetch('/api/assessments/import', { method: 'POST', body: JSON.stringify(body) });
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        throw new Error(err.error || ('HTTP ' + r.status));
      }
      const saved = await r.json();
      currentId = saved.id;
      Object.assign(model, {
        business: saved.business, data: saved.data, impact: saved.impact, recovery: saved.recovery,
        population: saved.population, integrations: saved.integrations, compliance: saved.compliance,
        hosting: saved.hosting, advanced: saved.advanced || {}
      });
      currentSection = 0;
      renderAll();
      await refreshSavedList();
      status.appendChild(el('div', { class: 'alert success' }, `Loaded ${file.name}. Saved as new draft ${saved.id.slice(0, 8)}…`));
    } catch (e) {
      status.appendChild(el('div', { class: 'alert error' }, 'Load failed: ' + e.message));
    }
  }

  function newAssessment() {
    currentId = null;
    Object.assign(model, emptyModel());
    currentSection = 0;
    renderAll();
    const status = document.getElementById('status-area');
    status.innerHTML = '';
    status.appendChild(el('div', { class: 'alert info' }, 'Started a fresh assessment.'));
  }

  async function refreshSession() {
    try {
      const me = await fetch('/api/auth/me').then(r => r.json());
      const el2 = document.getElementById('session-info');
      if (me.openMode) {
        el2.innerHTML = '<span style="color:var(--warning)">Open mode</span> · <a href="/login.html">Provision admin</a>';
      } else if (me.session) {
        el2.innerHTML = `${esc(me.session.displayName)} <span class="muted">(${esc(me.session.roles.join(', '))})</span><br/><a href="#" id="logout">Sign out</a>`;
        const lo = document.getElementById('logout');
        if (lo) lo.addEventListener('click', async (e) => { e.preventDefault(); await apiFetch('/api/auth/logout', { method: 'POST' }); window.location.href = '/login.html'; });
        // Reveal the Users admin link only for admin role. Server-side
        // /api/auth/users enforces the same gate regardless — this is
        // UX, not a security boundary.
        const navUsers = document.getElementById('nav-users');
        if (navUsers && me.session.roles && me.session.roles.includes('admin')) navUsers.style.display = '';
      } else {
        el2.innerHTML = '<a href="/login.html">Sign in</a>';
      }
    } catch { /* ignore */ }
  }

  // Show IaC section once an assessment id exists.
  function updateIacVisibility() {
    document.getElementById('iac-section').style.display = currentId ? 'block' : 'none';
  }
  const origSaveDraft = saveDraft;
  saveDraft = async function() { await origSaveDraft(); updateIacVisibility(); };

  document.getElementById('iac-file').addEventListener('change', async (ev) => {
    if (!currentId) { document.getElementById('iac-status').textContent = 'Save the draft first.'; return; }
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    const fd = new FormData(); fd.append('file', file);
    const r = await apiFetch(`/api/iac/${currentId}/upload`, { method: 'POST', body: fd });
    if (!r.ok) { const j = await r.json().catch(() => ({})); document.getElementById('iac-status').innerHTML = `<span style="color:var(--danger)">${esc(j.error || 'upload failed')}</span>`; return; }
    const j = await r.json();
    document.getElementById('iac-status').innerHTML = `<span style="color:var(--success)">Uploaded ${esc(file.name)} — ${esc(j.summary)}</span>`;
    ev.target.value = '';
  });

  document.getElementById('save-draft').addEventListener('click', saveDraft);
  document.getElementById('generate-btn').addEventListener('click', generatePackage);
  document.getElementById('download-json').addEventListener('click', downloadJson);
  document.getElementById('new-assessment').addEventListener('click', newAssessment);
  document.getElementById('load-json-btn').addEventListener('click', () => document.getElementById('load-json-input').click());
  document.getElementById('load-json-input').addEventListener('change', ev => {
    const file = ev.target.files && ev.target.files[0];
    loadJsonFile(file);
    ev.target.value = '';
  });

  renderAll();
  refreshSavedList();
  refreshAi();
  refreshSession();
  updateIacVisibility();
})();
