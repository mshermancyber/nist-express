// Portfolio dashboard. Aggregates every generated package and
// renders an analyst/PO/risk-officer view: posture summary, risk
// heat map, control coverage, compliance gaps.

(() => {
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
    const cls = level === 'Critical' || level === 'High' ? 'crit' : level === 'Elevated' ? 'high' : level === 'Medium' || level === 'Moderate' ? 'med' : 'low';
    return el('span', { class: 'badge ' + cls }, level);
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
    t.appendChild(tb); return t;
  }
  function card(title, body) {
    const c = el('section', { class: 'card' });
    c.appendChild(el('h3', {}, title));
    if (Array.isArray(body)) for (const b of body) c.appendChild(b); else c.appendChild(body);
    return c;
  }

  // Reveal the admin-only Users link in the sidebar for users with the
  // admin role. Mirrors the same logic in app.js. Server-side
  // /api/auth/users enforces the real gate.
  fetch('/api/auth/me').then(r => r.json()).then(me => {
    if (me && me.session && me.session.roles && me.session.roles.includes('admin')) {
      const navUsers = document.getElementById('nav-users');
      if (navUsers) navUsers.style.display = '';
    }
  }).catch(() => {});

  async function load() {
    const [pr, ar, auditR] = await Promise.all([
      fetch('/api/generate/'),
      fetch('/api/assessments/'),
      fetch('/api/audit?limit=50').catch(() => null)
    ]);
    const pkgs = (await pr.json()).packages;
    const assess = (await ar.json()).assessments;
    const idx = new Map(assess.map(a => [a.id, a]));
    let audit = null;
    if (auditR && auditR.ok) audit = (await auditR.json()).entries;
    render(pkgs, idx, audit);
  }

  function render(pkgs, idx, audit) {
    const root = document.getElementById('content');
    root.innerHTML = '';
    if (!pkgs.length) {
      root.appendChild(card('No packages yet', el('p', { class: 'muted' }, 'Generate your first ARB package from the wizard.')));
      return;
    }

    // Summary tiles
    const totals = {
      criticals: 0, highs: 0, mediums: 0,
      gaps: 0, fullCov: 0, partialCov: 0,
      packages: pkgs.length,
      sspControls: 0,
      threats: 0
    };
    for (const p of pkgs) {
      for (const r of p.residualRisks) {
        if (r.residualRisk === 'Critical') totals.criticals++;
        else if (r.residualRisk === 'High') totals.highs++;
        else if (r.residualRisk === 'Medium') totals.mediums++;
      }
      for (const m of p.complianceMappings) {
        if (m.coverage === 'Gap') totals.gaps++;
        else if (m.coverage === 'Partial') totals.partialCov++;
        else if (m.coverage === 'Full') totals.fullCov++;
      }
      totals.sspControls += p.ssp.length;
      totals.threats += p.threatModel.length;
    }
    const grid = el('div', { class: 'grid-4' });
    for (const [k, v] of [
      ['Packages', totals.packages], ['SSP Controls', totals.sspControls], ['STRIDE Findings', totals.threats], ['Critical residual risks', totals.criticals]
    ]) {
      const c = el('div', { class: 'card' });
      c.appendChild(el('h3', {}, k));
      c.appendChild(el('p', { style: 'font-size:2rem;margin:0;color:var(--accent)' }, String(v)));
      grid.appendChild(c);
    }
    root.appendChild(grid);

    // Portfolio table
    const rows = pkgs.map(p => {
      const a = idx.get(p.assessmentId);
      const name = (a && a.business.applicationName) || p.assessmentId.slice(0, 8);
      const sec = p.wellArchitected.find(w => w.pillar === 'Security')?.score ?? 0;
      const rel = p.wellArchitected.find(w => w.pillar === 'Reliability')?.score ?? 0;
      const ops = p.wellArchitected.find(w => w.pillar === 'Operational Excellence')?.score ?? 0;
      const open = el('a', { href: `/view.html?id=${p.assessmentId}` }, 'Open');
      return [name, p.categorization.overallCategorization, badge(p.executiveSummary.riskPosture),
              `${sec}/${rel}/${ops}`, p.executiveSummary.goNoGoAdvice, new Date(p.generatedAt).toLocaleString(), open];
    });
    root.appendChild(card('Portfolio', table(['Application', 'Category', 'Posture', 'WAF (S/R/O)', 'Recommendation', 'Generated', ''], rows)));

    // Risk heat map (aggregated)
    const counts = {};
    for (const p of pkgs) for (const t of p.threatModel) {
      const k = t.likelihood + ':' + t.impact;
      counts[k] = (counts[k] || 0) + 1;
    }
    const hm = el('div', { class: 'heatmap' });
    hm.appendChild(el('div', { class: 'axis' }, ''));
    for (const imp of ['Low', 'Medium', 'High']) hm.appendChild(el('div', { class: 'axis', style: 'text-align:center;' }, 'I: ' + imp));
    for (const lik of ['High', 'Medium', 'Low']) {
      hm.appendChild(el('div', { class: 'axis' }, 'L: ' + lik));
      for (const imp of ['Low', 'Medium', 'High']) {
        const cls = lik[0] + imp[0];
        hm.appendChild(el('div', { class: 'cell ' + cls }, String(counts[lik + ':' + imp] || 0)));
      }
    }
    root.appendChild(card('STRIDE Heat Map (Likelihood × Impact)', hm));

    // Compliance coverage
    const covMap = { Full: totals.fullCov, Partial: totals.partialCov, Gap: totals.gaps };
    const covDiv = el('div', { class: 'grid-3' });
    for (const [k, v] of Object.entries(covMap)) {
      const c = el('div', { class: 'card' });
      c.appendChild(el('h3', {}, k));
      c.appendChild(el('p', { style: 'font-size:2rem;margin:0;color:' + (k === 'Gap' ? 'var(--danger)' : k === 'Partial' ? 'var(--warning)' : 'var(--success)') }, String(v)));
      covDiv.appendChild(c);
    }
    root.appendChild(card('Compliance Coverage', covDiv));

    // Top residual risks across portfolio
    const allRisks = pkgs.flatMap(p => p.residualRisks.map(r => ({ ...r, app: (idx.get(p.assessmentId) || {}).business?.applicationName || p.assessmentId.slice(0, 8) })))
      .filter(r => r.residualRisk === 'Critical' || r.residualRisk === 'High')
      .slice(0, 50);
    root.appendChild(card('Top Residual Risks (portfolio)',
      table(['App', 'ID', 'Source', 'Inherent', 'Residual', 'Treatment', 'Description'],
        allRisks.map(r => [r.app, r.id, r.source, badge(r.inherentRisk), badge(r.residualRisk), r.treatment, r.description]))));

    // Portfolio cost summary
    const costRows = pkgs.map(p => {
      const a = idx.get(p.assessmentId);
      const name = (a && a.business.applicationName) || p.assessmentId.slice(0, 8);
      return [name, p.costEstimate.tier, `$${p.costEstimate.monthlyLowUsd.toLocaleString()}`, `$${p.costEstimate.monthlyHighUsd.toLocaleString()}`];
    });
    const lowSum = pkgs.reduce((s, p) => s + p.costEstimate.monthlyLowUsd, 0);
    const highSum = pkgs.reduce((s, p) => s + p.costEstimate.monthlyHighUsd, 0);
    costRows.push(['PORTFOLIO TOTAL', '—', `$${lowSum.toLocaleString()}`, `$${highSum.toLocaleString()}`]);
    root.appendChild(card('Portfolio Cost Estimate (USD/month)', table(['Application', 'Tier', 'Low', 'High'], costRows)));

    // Recent activity (audit log) — only if reachable
    if (audit) {
      root.appendChild(card('Recent Platform Activity',
        table(['When', 'Actor', 'Action', 'Target', 'Details'],
          audit.slice(0, 30).map(e => [
            new Date(e.ts).toLocaleString(),
            e.actor,
            e.action,
            e.target.slice(0, 12) + (e.target.length > 12 ? '…' : ''),
            JSON.stringify(e.details || {}).slice(0, 80)
          ]))));
    }
  }

  load();
})();
