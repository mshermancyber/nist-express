// Side-by-side diff viewer between two package versions.

(() => {
  const params = new URLSearchParams(window.location.search);
  const id = params.get('id');
  if (!id) { document.getElementById('title').textContent = 'Missing assessment id'; return; }
  const fromVer = Number(params.get('from') || 1);
  const toVer = Number(params.get('to') || 0);

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k === 'html') node.innerHTML = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) node.setAttribute(k, v);
    }
    for (const c of children) if (c) node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    return node;
  }

  function table(headers, rows) {
    const t = el('table'), thead = el('thead'), tr = el('tr');
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

  async function load() {
    const v = await fetch(`/api/generate/${id}/versions`).then(r => r.json());
    const versions = v.versions || [];
    const list = document.getElementById('version-list');
    list.innerHTML = '';
    if (!versions.length) { list.textContent = 'No versions.'; return; }

    const latest = versions[0].version;
    const target = toVer || latest;
    const prev = fromVer || (versions[1] ? versions[1].version : 1);

    for (const ver of versions) {
      const linkPrev = el('a', { href: `/diff.html?id=${id}&from=${ver.version}&to=${target}` }, `v${ver.version}`);
      const linkNext = el('a', { href: `/diff.html?id=${id}&from=${prev}&to=${ver.version}`, style: 'margin-left:.5rem' }, '(as target)');
      const wrap = el('div', { style: 'padding:.25rem .75rem' }, linkPrev, ' ', linkNext);
      list.appendChild(wrap);
    }

    const [a, b, diff] = await Promise.all([
      fetch(`/api/generate/${id}/v/${prev}`).then(r => r.json()),
      fetch(`/api/generate/${id}/v/${target}`).then(r => r.json()),
      fetch(`/api/generate/${id}/diff/${prev}/${target}`).then(r => r.json())
    ]);

    document.getElementById('title').textContent = `v${prev} → v${target}`;
    document.getElementById('subtitle').textContent = `${new Date(a.generatedAt).toLocaleString()} ↔ ${new Date(b.generatedAt).toLocaleString()}`;
    document.getElementById('export-row').appendChild(el('a', { class: 'btn secondary', href: `/api/export/${id}.diff.csv` }, 'Diff CSV'));
    document.getElementById('export-row').appendChild(el('a', { class: 'btn', href: `/view.html?id=${id}` }, 'Open viewer'));

    const root = document.getElementById('content');
    root.innerHTML = '';

    const summary = el('section', { class: 'card' });
    summary.appendChild(el('h3', {}, 'Decision-relevant changes'));
    if (!diff || !diff.highlights || !diff.highlights.length) summary.appendChild(el('p', { class: 'muted' }, 'No decision-relevant changes.'));
    else { const ul = el('ul'); for (const h of diff.highlights) ul.appendChild(el('li', {}, h)); summary.appendChild(ul); }
    root.appendChild(summary);

    const sxs = el('section', { class: 'card' });
    sxs.appendChild(el('h3', {}, 'Side-by-side metrics'));
    sxs.appendChild(table(
      ['Metric', `v${prev}`, `v${target}`],
      [
        ['Posture', a.executiveSummary.riskPosture, b.executiveSummary.riskPosture],
        ['Recommendation', a.executiveSummary.goNoGoAdvice, b.executiveSummary.goNoGoAdvice],
        ['Category', a.categorization.overallCategorization, b.categorization.overallCategorization],
        ['Recovery tier', a.recovery.availabilityTier, b.recovery.availabilityTier],
        ['SSP controls', a.ssp.length, b.ssp.length],
        ['STRIDE findings', a.threatModel.length, b.threatModel.length],
        ['Residual risks', a.residualRisks.length, b.residualRisks.length],
        ['Cost low / high (USD)', `$${a.costEstimate.monthlyLowUsd.toLocaleString()} – $${a.costEstimate.monthlyHighUsd.toLocaleString()}`,
                                  `$${b.costEstimate.monthlyLowUsd.toLocaleString()} – $${b.costEstimate.monthlyHighUsd.toLocaleString()}`],
        ['Portfolio ALE p50', a.fair ? '$' + a.fair.portfolio.aleP50.toLocaleString() : '—', b.fair ? '$' + b.fair.portfolio.aleP50.toLocaleString() : '—']
      ]
    ));
    root.appendChild(sxs);

    const changes = el('section', { class: 'card' });
    changes.appendChild(el('h3', {}, 'Control & component churn'));
    changes.appendChild(table(
      ['Set', 'Added', 'Removed'],
      [
        ['SSP controls', diff.controlsAdded.join(', ') || '—', diff.controlsRemoved.join(', ') || '—'],
        ['Components', diff.componentsAdded.join(', ') || '—', diff.componentsRemoved.join(', ') || '—']
      ]
    ));
    root.appendChild(changes);
  }
  load();
})();
