// User Administration page. Talks to /api/auth/users + the sudo flow.
// All state-changing requests funnel through apiFetch (CSRF) and
// re-prompt for sudo whenever the API returns 403/sudo-required.

(() => {
  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') n.className = v;
      else if (k === 'html') n.innerHTML = v;
      else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) n.setAttribute(k, v);
    }
    for (const c of kids) if (c != null) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    return n;
  };
  const esc = window.esc;
  const status = document.getElementById('status-area');
  function flash(kind, message) {
    status.innerHTML = '';
    status.appendChild(el('div', { class: 'alert ' + kind }, message));
    setTimeout(() => { status.innerHTML = ''; }, 6000);
  }

  // ---- Sudo dialog ---------------------------------------------------
  const sudoDlg = document.getElementById('sudo-dialog');
  function promptSudo() {
    return new Promise((resolve) => {
      document.getElementById('sudo-pwd').value = '';
      document.getElementById('sudo-totp').value = '';
      document.getElementById('sudo-error').style.display = 'none';
      sudoDlg.showModal();
      document.getElementById('sudo-cancel').onclick = () => { sudoDlg.close(); resolve(false); };
      document.getElementById('sudo-submit').onclick = async () => {
        const password = document.getElementById('sudo-pwd').value;
        const totp = document.getElementById('sudo-totp').value;
        const body = totp ? { password, totp } : { password };
        const r = await window.apiFetch('/api/auth/sudo', { method: 'POST', body: JSON.stringify(body) });
        if (r.ok) { sudoDlg.close(); resolve(true); return; }
        const j = await r.json().catch(() => ({}));
        const err = document.getElementById('sudo-error');
        err.textContent = j.error || 'Sudo failed';
        err.style.display = 'block';
      };
    });
  }

  // Wrap a state-changing request and re-issue once with sudo if the
  // server replies 403 + sudo-required.
  async function withSudoRetry(doFetch) {
    let r = await doFetch();
    if (r.status === 403) {
      const j = await r.clone().json().catch(() => ({}));
      if (j.sudo === false) {
        const ok = await promptSudo();
        if (!ok) return r;
        r = await doFetch();
      }
    }
    return r;
  }

  // ---- Session badge --------------------------------------------------
  async function loadSession() {
    try {
      const r = await fetch('/api/auth/me');
      const j = await r.json();
      const info = document.getElementById('session-info');
      if (j.session) {
        info.innerHTML = `Signed in as <strong>${esc(j.session.displayName || j.session.username)}</strong> (${j.session.roles.join(', ')})`;
      } else if (j.openMode) {
        info.textContent = 'Open mode — no users provisioned';
      } else {
        info.innerHTML = '<a href="/login.html">Sign in</a>';
      }
    } catch { /* ignore */ }
  }

  // ---- User list ------------------------------------------------------
  let allUsers = [];
  let lockouts = [];
  let lockoutsTruncated = false;
  let lockoutsTotal = 0;
  let sortKey = 'username';
  let sortDir = 1;        // 1 asc, -1 desc
  let pageIndex = 0;

  // Render a load-error alert. Accepts a SAFE HTML fragment — every
  // caller must pass either a string literal or a value built from
  // trusted sources only. Never pass `error.message`, response bodies,
  // or any value derived from server-side data. Hostile content here
  // would XSS the admin page.
  function showLoadErrorHtml(safeHtml) {
    document.getElementById('users-table-wrap').innerHTML = `<div class="alert error">${safeHtml}</div>`;
    document.getElementById('security-card').style.display = 'none';
    const m = document.getElementById('metrics-grid');
    if (m) m.innerHTML = '<span class="muted">—</span>';
  }
  // Render an error alert from arbitrary text (text-only, escaped via
  // textContent — never injects HTML).
  function showLoadErrorText(text) {
    const wrap = document.getElementById('users-table-wrap');
    wrap.innerHTML = '';
    const div = document.createElement('div');
    div.className = 'alert error';
    div.textContent = String(text);
    wrap.appendChild(div);
    document.getElementById('security-card').style.display = 'none';
    const m = document.getElementById('metrics-grid');
    if (m) m.innerHTML = '<span class="muted">—</span>';
  }

  async function loadAll() {
    try {
      const [usersR, lockoutsR] = await Promise.all([
        fetch('/api/auth/users'),
        fetch('/api/auth/lockouts').catch(() => null)
      ]);
      if (usersR.status === 401) {
        // The only HTML-bearing call site — passes a string literal.
        showLoadErrorHtml('You must <a href="/login.html">sign in</a> to view this page.');
        return;
      }
      if (usersR.status === 403) {
        showLoadErrorText('You must be an admin to view this page.');
        return;
      }
      if (!usersR.ok) {
        // Status code is numeric per HTTP spec but be defensive — use
        // the text-only renderer so a hostile reverse-proxy can't
        // smuggle HTML into our error display.
        showLoadErrorText(`Failed to load users (HTTP ${usersR.status}).`);
        return;
      }
      const data = await usersR.json();
      allUsers = data.users || [];
      if (lockoutsR && lockoutsR.ok) {
        const lj = await lockoutsR.json();
        lockouts = lj.lockouts || [];
        lockoutsTruncated = !!lj.truncated;
        lockoutsTotal = typeof lj.totalActive === 'number' ? lj.totalActive : lockouts.length;
      } else {
        lockouts = []; lockoutsTruncated = false; lockoutsTotal = 0;
      }
      renderMetrics();
      renderTable();
      loadSecurityPanels();
    } catch (e) {
      flash('error', 'Failed to load users: ' + e.message);
    }
  }
  const loadUsers = loadAll;  // keep the old name working for inline handlers

  function renderMetrics() {
    const total = allUsers.length;
    const active = allUsers.filter(u => !u.disabled && !u.deletedAt).length;
    const disabled = allUsers.filter(u => u.disabled && !u.deletedAt).length;
    const admins = allUsers.filter(u => u.roles.includes('admin') && !u.deletedAt).length;
    const mfa = allUsers.filter(u => u.totpEnabled).length;
    const deleted = allUsers.filter(u => u.deletedAt).length;
    // Use the server-reported total (covers the case where lockouts
    // were truncated for response-size safety).
    const locked = lockoutsTruncated
      ? lockoutsTotal  // already counts both kinds; show full pressure
      : lockouts.filter(l => l.kind === 'user').length;
    const grid = document.getElementById('metrics-grid');
    grid.innerHTML = '';
    const tile = (label, value, accent) => el('div', { style: 'padding:.5rem' },
      el('div', { class: 'muted', style: 'font-size:.75rem;text-transform:uppercase;letter-spacing:.08em' }, label),
      el('div', { style: `font-size:1.8rem;font-weight:600;color:${accent || 'var(--accent)'}` }, String(value)));
    grid.appendChild(tile('Total', total));
    grid.appendChild(tile('Active', active));
    grid.appendChild(tile('Disabled', disabled, disabled > 0 ? 'var(--warning)' : undefined));
    grid.appendChild(tile('Admins', admins));
    grid.appendChild(tile('MFA enrolled', mfa));
    grid.appendChild(tile('Locked', locked, locked > 0 ? 'var(--danger)' : undefined));
    grid.appendChild(tile('Soft-deleted', deleted));
  }

  // Column spec: key (used for sort + cell text), label (header).
  // `sortable: false` for columns that don't make sense to sort.
  const COLUMNS = [
    { key: 'username',    label: 'Username',     sortable: true },
    { key: 'displayName', label: 'Display name', sortable: true },
    { key: 'email',       label: 'Email',        sortable: true },
    { key: 'roles',       label: 'Roles',        sortable: true },
    { key: 'status',      label: 'Status',       sortable: true },
    { key: 'lastLoginAt', label: 'Last login',   sortable: true },
    { key: 'createdAt',   label: 'Created',      sortable: true },
    { key: 'updatedAt',   label: 'Modified',     sortable: true },
    { key: 'actions',     label: 'Actions',      sortable: false }
  ];

  function userStatusRank(u) {
    if (u.deletedAt) return 4;
    if (lockouts.some(l => l.kind === 'user' && l.key === u.username)) return 3;
    if (u.disabled) return 2;
    return 1;  // active
  }

  function compareUsers(a, b, key) {
    if (key === 'roles') return (a.roles || []).join(',').localeCompare((b.roles || []).join(','));
    if (key === 'status') return userStatusRank(a) - userStatusRank(b);
    const av = a[key] ?? '';
    const bv = b[key] ?? '';
    if (key === 'lastLoginAt' || key === 'createdAt' || key === 'updatedAt') {
      // Date strings — empty sorts last in asc.
      if (!av && !bv) return 0;
      if (!av) return 1;
      if (!bv) return -1;
      return new Date(av).getTime() - new Date(bv).getTime();
    }
    return String(av).localeCompare(String(bv));
  }

  function setSort(key) {
    if (sortKey === key) { sortDir = -sortDir; }
    else { sortKey = key; sortDir = 1; }
    pageIndex = 0;
    renderTable();
  }

  function renderTable() {
    const wrap = document.getElementById('users-table-wrap');
    const filterText = document.getElementById('filter').value.toLowerCase().trim();
    const showDeleted = document.getElementById('show-deleted').checked;
    const pageSize = Number(document.getElementById('page-size').value) || 50;
    let rows = allUsers.filter(u => {
      if (!showDeleted && u.deletedAt) return false;
      if (!filterText) return true;
      const hay = [u.username, u.displayName, u.email, u.firstName, u.lastName, u.department, u.jobTitle, (u.roles || []).join(' ')].filter(Boolean).join(' ').toLowerCase();
      return hay.includes(filterText);
    });
    rows.sort((a, b) => compareUsers(a, b, sortKey) * sortDir);
    const total = rows.length;
    const maxPage = Math.max(0, Math.ceil(total / pageSize) - 1);
    if (pageIndex > maxPage) pageIndex = maxPage;
    const start = pageIndex * pageSize;
    const slice = rows.slice(start, start + pageSize);
    if (!total) {
      wrap.innerHTML = '<div class="muted" style="padding:.5rem 0">No users match.</div>';
      renderPager(0, 0, 0);
      return;
    }
    const t = el('table');
    const headRow = el('tr');
    for (const col of COLUMNS) {
      if (!col.sortable) { headRow.appendChild(el('th', {}, col.label)); continue; }
      const marker = sortKey === col.key ? (sortDir === 1 ? ' ▲' : ' ▼') : '';
      const th = el('th', {
        role: 'button',
        'aria-sort': sortKey === col.key ? (sortDir === 1 ? 'ascending' : 'descending') : 'none',
        title: `Sort by ${col.label}`,
        style: 'cursor:pointer;user-select:none',
        onclick: () => setSort(col.key)
      }, col.label + marker);
      headRow.appendChild(th);
    }
    t.appendChild(el('thead', {}, headRow));
    const tb = el('tbody');
    for (const u of slice) {
      const statusBadges = [];
      const isLocked = lockouts.some(l => l.kind === 'user' && l.key === u.username);
      if (u.deletedAt) statusBadges.push(el('span', { class: 'badge crit' }, 'deleted'));
      else if (isLocked) statusBadges.push(el('span', { class: 'badge crit' }, 'locked'));
      else if (u.disabled) statusBadges.push(el('span', { class: 'badge high' }, 'disabled'));
      else statusBadges.push(el('span', { class: 'badge low' }, 'active'));
      if (u.forcePasswordChange) statusBadges.push(el('span', { class: 'badge med' }, 'pwd reset due'));
      if (u.roles && u.roles.includes('admin')) statusBadges.push(el('span', { class: 'badge info' }, 'admin'));

      const actions = el('div', { class: 'btn-row' });
      if (!u.deletedAt) {
        actions.appendChild(el('button', { class: 'secondary', style: 'padding:.2rem .5rem;font-size:.8rem', onclick: () => openEdit(u) }, 'Edit'));
        if (u.disabled) {
          actions.appendChild(el('button', { class: 'secondary', style: 'padding:.2rem .5rem;font-size:.8rem', onclick: () => enableUser(u) }, 'Enable'));
        } else {
          actions.appendChild(el('button', { class: 'secondary', style: 'padding:.2rem .5rem;font-size:.8rem', onclick: () => disableUser(u) }, 'Disable'));
        }
        actions.appendChild(el('button', { class: 'secondary', style: 'padding:.2rem .5rem;font-size:.8rem', onclick: () => forcePwdReset(u) }, 'Force pwd reset'));
        // Wire Shift+click for hard delete so the prompt isn't lying
        // about modifier behaviour. Without Shift, it's a soft delete.
        actions.appendChild(el('button', {
          class: 'danger', style: 'padding:.2rem .5rem;font-size:.8rem',
          title: 'Click to soft-delete (reversible). Shift+Click for irreversible hard-delete.',
          onclick: (ev) => deleteUserAction(u, ev.shiftKey)
        }, 'Delete'));
      }

      const fmtDate = (s) => s ? new Date(s).toLocaleString() : '—';
      tb.appendChild(el('tr', {},
        el('td', {}, u.username),
        el('td', {}, u.displayName || ''),
        el('td', {}, u.email || ''),
        el('td', {}, (u.roles || []).join(', ')),
        el('td', {}, ...statusBadges),
        el('td', {}, fmtDate(u.lastLoginAt)),
        el('td', {}, fmtDate(u.createdAt)),
        el('td', {}, fmtDate(u.updatedAt)),
        el('td', {}, actions),
      ));
    }
    t.appendChild(tb);
    wrap.innerHTML = '';
    wrap.appendChild(t);
    renderPager(start, slice.length, total);
  }

  function renderPager(start, shown, total) {
    const pager = document.getElementById('pager');
    pager.innerHTML = '';
    if (!total) return;
    const pageSize = Number(document.getElementById('page-size').value) || 50;
    const lastPage = Math.max(0, Math.ceil(total / pageSize) - 1);
    const summary = el('span', { class: 'muted', style: 'margin-right:auto' },
      shown ? `${start + 1}–${start + shown} of ${total}` : `0 of ${total}`);
    pager.appendChild(summary);
    const btn = (label, disabled, onclick) => el('button', {
      class: 'secondary', disabled: disabled ? 'disabled' : false,
      style: 'padding:.2rem .55rem;font-size:.85rem',
      onclick
    }, label);
    pager.appendChild(btn('« First', pageIndex === 0, () => { pageIndex = 0; renderTable(); }));
    pager.appendChild(btn('‹ Prev', pageIndex === 0, () => { pageIndex--; renderTable(); }));
    pager.appendChild(el('span', { class: 'muted', style: 'padding:0 .5rem' }, `Page ${pageIndex + 1} / ${lastPage + 1}`));
    pager.appendChild(btn('Next ›', pageIndex >= lastPage, () => { pageIndex++; renderTable(); }));
    pager.appendChild(btn('Last »', pageIndex >= lastPage, () => { pageIndex = lastPage; renderTable(); }));
  }

  // ---- Security panels ----------------------------------------------
  async function loadSecurityPanels() {
    // Lockouts panel uses the data we already fetched in loadAll.
    renderLockoutsPanel();
    // Audit-driven panels: pull each in parallel.
    const fail   = '/api/audit?limit=8&actions=auth.login.fail,auth.login.locked,auth.login.disabled,auth.totp.fail,auth.sudo.fail,auth.sudo.totp.fail';
    const pwd    = '/api/audit?limit=8&actions=user.password.reset.issue,user.password.reset.redeem,user.change_password.ok,user.change_password.fail,user.force_password_change';
    const admin  = '/api/audit?limit=8&actions=user.create,user.update,user.enable,user.disable,user.soft_delete,user.hard_delete,apikey.create,apikey.revoke,totp.enable,totp.disable,auth.rotate-secret,auth.lockout.clear';
    const [f, p, a] = await Promise.all([
      fetch(fail).then(r => r.ok ? r.json() : { entries: [] }).catch(() => ({ entries: [] })),
      fetch(pwd).then(r => r.ok ? r.json() : { entries: [] }).catch(() => ({ entries: [] })),
      fetch(admin).then(r => r.ok ? r.json() : { entries: [] }).catch(() => ({ entries: [] }))
    ]);
    renderAuditPanel('fail-panel', f.entries, 'No recent failed logins.');
    renderAuditPanel('pwd-panel',  p.entries, 'No recent password events.');
    renderAuditPanel('admin-panel', a.entries, 'No recent admin actions.');
  }

  function renderLockoutsPanel() {
    const panel = document.getElementById('lockouts-panel');
    panel.innerHTML = '';
    if (!lockouts.length) {
      // Defensive: getLockouts() should never report truncated:true
      // with an empty list (it slices AFTER sorting), but if a future
      // refactor regresses that, surface the inconsistency loudly
      // rather than silently say "no lockouts."
      if (lockoutsTruncated && lockoutsTotal > 0) {
        panel.appendChild(el('div', { class: 'alert error' },
          `${lockoutsTotal} active lockouts exist but none returned (server reported truncated set). Check server logs.`));
      } else {
        panel.appendChild(el('div', { class: 'muted' }, 'No active lockouts.'));
      }
      return;
    }
    if (lockoutsTruncated) {
      panel.appendChild(el('div', { class: 'alert warn', style: 'margin-bottom:.5rem' },
        `Showing ${lockouts.length} of ${lockoutsTotal} active lockouts (response capped). Investigate possible credential-stuffing attack.`));
    }
    const t = el('table');
    t.appendChild(el('thead', {}, el('tr', {},
      el('th', {}, 'Kind'), el('th', {}, 'Key'), el('th', {}, 'Fails'), el('th', {}, 'Cooldown'), el('th', {}, '')
    )));
    const tb = el('tbody');
    for (const lo of lockouts) {
      const clearBtn = el('button', {
        class: 'secondary',
        style: 'padding:.15rem .5rem;font-size:.8rem',
        onclick: () => clearLockout(lo)
      }, 'Clear');
      tb.appendChild(el('tr', {},
        el('td', {}, lo.kind),
        el('td', {}, lo.key),
        el('td', {}, String(lo.failuresInWindow)),
        el('td', {}, fmtSecondsShort(lo.cooldownSecondsRemaining)),
        el('td', {}, clearBtn),
      ));
    }
    t.appendChild(tb);
    panel.appendChild(t);
  }

  function fmtSecondsShort(s) {
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60); const r = s % 60;
    return r ? `${m}m ${r}s` : `${m}m`;
  }

  function renderAuditPanel(id, entries, emptyMsg) {
    const panel = document.getElementById(id);
    panel.innerHTML = '';
    if (!entries || !entries.length) {
      panel.appendChild(el('div', { class: 'muted' }, emptyMsg));
      return;
    }
    const usernameById = new Map(allUsers.map(u => [u.id, u.username]));
    const list = el('div', { style: 'display:flex;flex-direction:column;gap:.35rem' });
    for (const e of entries) {
      const when = e.ts ? new Date(e.ts).toLocaleString() : '?';
      const actor = e.actor ? (usernameById.get(e.actor) || e.actor) : '—';
      const target = e.target ? (usernameById.get(e.target) || e.target) : '';
      list.appendChild(el('div', { style: 'font-size:.85rem;line-height:1.35' },
        el('span', { class: 'badge info' }, e.action),
        document.createTextNode(' '),
        el('span', { class: 'muted' }, when),
        document.createTextNode(' — '),
        document.createTextNode(actor + (target && target !== actor ? ' → ' + target : ''))
      ));
    }
    panel.appendChild(list);
  }

  async function clearLockout(lo) {
    if (!confirm(`Clear lockout for ${lo.kind}:${lo.key}? This undoes the credential-stuffing defence for that target.`)) return;
    const body = lo.kind === 'user' ? { username: lo.key } : { ip: lo.key };
    const r = await withSudoRetry(() => window.apiFetch('/api/auth/lockouts/clear', { method: 'POST', body: JSON.stringify(body) }));
    if (r.ok) { flash('success', `Lockout cleared for ${lo.key}.`); loadAll(); }
    else { const j = await r.json().catch(() => ({})); flash('error', j.error || 'Clear failed'); }
  }

  // ---- Actions --------------------------------------------------------
  async function disableUser(u) {
    const reason = prompt(`Disable "${u.username}"? Reason (optional):`);
    if (reason === null) return;
    const r = await withSudoRetry(() => window.apiFetch(`/api/auth/users/${encodeURIComponent(u.id)}/disable`, {
      method: 'POST', body: JSON.stringify({ reason })
    }));
    if (r.ok) { flash('success', `${u.username} disabled.`); loadUsers(); }
    else { const j = await r.json().catch(() => ({})); flash('error', j.error || 'Disable failed'); }
  }

  async function enableUser(u) {
    const r = await withSudoRetry(() => window.apiFetch(`/api/auth/users/${encodeURIComponent(u.id)}/enable`, { method: 'POST' }));
    if (r.ok) { flash('success', `${u.username} enabled.`); loadUsers(); }
    else { const j = await r.json().catch(() => ({})); flash('error', j.error || 'Enable failed'); }
  }

  async function forcePwdReset(u) {
    if (!confirm(`Require ${u.username} to set a new password on their next login?`)) return;
    const r = await withSudoRetry(() => window.apiFetch(`/api/auth/users/${encodeURIComponent(u.id)}/force-password-change`, { method: 'POST' }));
    if (r.ok) { flash('success', `${u.username} will be required to set a new password.`); loadUsers(); }
    else { const j = await r.json().catch(() => ({})); flash('error', j.error || 'Failed'); }
  }

  async function deleteUserAction(u, hard) {
    const verb = hard ? 'HARD delete (irreversible)' : 'soft-delete (reversible)';
    if (!confirm(`${verb} "${u.username}"?`)) return;
    if (hard && !confirm(`Last chance — "${u.username}" will be permanently erased. Continue?`)) return;
    const url = `/api/auth/users/${encodeURIComponent(u.id)}` + (hard ? '?hard=1' : '');
    const r = await withSudoRetry(() => window.apiFetch(url, { method: 'DELETE' }));
    if (r.ok) { flash('success', `${u.username} ${hard ? 'permanently erased' : 'soft-deleted'}.`); loadUsers(); }
    else { const j = await r.json().catch(() => ({})); flash('error', j.error || 'Delete failed'); }
  }

  // ---- Edit dialog ----------------------------------------------------
  // Reuses the add-dialog form, hides password+username fields, prefills.
  function openEdit(u) {
    const dlg = document.getElementById('add-dialog');
    dlg.querySelector('h3').textContent = `Edit ${u.username}`;
    document.getElementById('f-username').value = u.username;
    document.getElementById('f-username').readOnly = true;
    document.getElementById('f-firstName').value = u.firstName || '';
    document.getElementById('f-lastName').value = u.lastName || '';
    document.getElementById('f-displayName').value = u.displayName || '';
    document.getElementById('f-email').value = u.email || '';
    document.getElementById('f-department').value = u.department || '';
    document.getElementById('f-jobTitle').value = u.jobTitle || '';
    document.getElementById('f-phone').value = u.phone || '';
    document.getElementById('f-timezone').value = u.timezone || '';
    // Hide via the stable wrapper divs (the password label is a sibling
    // of the input, not its ancestor — closest('label') would return
    // null for f-password and throw).
    document.getElementById('f-password-row').style.display = 'none';
    document.getElementById('f-password').required = false;
    document.getElementById('f-force-pwd-row').style.display = 'none';
    const cbs = document.querySelectorAll('#f-roles input[type=checkbox]');
    for (const cb of cbs) cb.checked = (u.roles || []).includes(cb.value);
    document.getElementById('add-submit').textContent = 'Save changes';
    document.getElementById('add-submit').dataset.mode = 'edit';
    document.getElementById('add-submit').dataset.id = u.id;
    document.getElementById('add-error').style.display = 'none';
    dlg.showModal();
  }

  function openAdd() {
    const dlg = document.getElementById('add-dialog');
    dlg.querySelector('h3').textContent = 'Add user';
    for (const id of ['f-username','f-firstName','f-lastName','f-displayName','f-email','f-department','f-jobTitle','f-phone','f-timezone','f-password']) {
      document.getElementById(id).value = '';
    }
    document.getElementById('f-username').readOnly = false;
    document.getElementById('f-password-row').style.display = '';
    document.getElementById('f-password').required = true;
    document.getElementById('f-force-pwd-row').style.display = '';
    document.getElementById('f-force-pwd').checked = false;
    const cbs = document.querySelectorAll('#f-roles input[type=checkbox]');
    for (const cb of cbs) cb.checked = cb.value === 'architect';
    document.getElementById('add-submit').textContent = 'Create';
    document.getElementById('add-submit').dataset.mode = 'add';
    document.getElementById('add-error').style.display = 'none';
    dlg.showModal();
  }

  async function submitDialog() {
    const mode = document.getElementById('add-submit').dataset.mode;
    const id = document.getElementById('add-submit').dataset.id;
    const roles = Array.from(document.querySelectorAll('#f-roles input:checked')).map(cb => cb.value);
    if (!roles.length) { document.getElementById('add-error').textContent = 'Select at least one role.'; document.getElementById('add-error').style.display = 'block'; return; }
    const payload = {
      displayName: document.getElementById('f-displayName').value.trim(),
      email: document.getElementById('f-email').value.trim() || undefined,
      firstName: document.getElementById('f-firstName').value.trim() || undefined,
      lastName: document.getElementById('f-lastName').value.trim() || undefined,
      department: document.getElementById('f-department').value.trim() || undefined,
      jobTitle: document.getElementById('f-jobTitle').value.trim() || undefined,
      phone: document.getElementById('f-phone').value.trim() || undefined,
      timezone: document.getElementById('f-timezone').value.trim() || undefined,
      roles
    };
    let r;
    let forcePwdWarning = '';
    if (mode === 'add') {
      payload.username = document.getElementById('f-username').value.trim();
      payload.password = document.getElementById('f-password').value;
      r = await withSudoRetry(() => window.apiFetch('/api/auth/users', { method: 'POST', body: JSON.stringify(payload) }));
      if (r.ok && document.getElementById('f-force-pwd').checked) {
        const newUser = await r.clone().json();
        const fpr = await withSudoRetry(() => window.apiFetch(`/api/auth/users/${encodeURIComponent(newUser.id)}/force-password-change`, { method: 'POST' }));
        if (!fpr.ok) {
          // User exists, but the force-password-change flag couldn't be
          // set. Surface that explicitly — silent failure would hide
          // the admin's stated intent.
          const j = await fpr.json().catch(() => ({}));
          forcePwdWarning = ` (warning: failed to set force-password-change — ${j.error || 'unknown error'})`;
        }
      }
    } else {
      r = await withSudoRetry(() => window.apiFetch(`/api/auth/users/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(payload) }));
    }
    if (r.ok) {
      document.getElementById('add-dialog').close();
      flash(forcePwdWarning ? 'warn' : 'success', (mode === 'add' ? 'User created.' : 'User updated.') + forcePwdWarning);
      loadUsers();
    } else {
      const j = await r.json().catch(() => ({}));
      const err = document.getElementById('add-error');
      err.textContent = j.error || (j.issues ? 'Validation failed' : 'Request failed');
      err.style.display = 'block';
    }
  }

  // ---- Wire events ----------------------------------------------------
  document.getElementById('refresh-btn').addEventListener('click', loadAll);
  document.getElementById('add-user-btn').addEventListener('click', openAdd);
  // Reset to page 0 on filter / deleted-toggle / page-size change so
  // the user isn't stranded past the last page of the filtered set.
  document.getElementById('filter').addEventListener('input', () => { pageIndex = 0; renderTable(); });
  document.getElementById('show-deleted').addEventListener('change', () => { pageIndex = 0; renderTable(); });
  document.getElementById('page-size').addEventListener('change', () => { pageIndex = 0; renderTable(); });
  document.getElementById('add-cancel').addEventListener('click', () => document.getElementById('add-dialog').close());
  document.getElementById('add-submit').addEventListener('click', submitDialog);

  loadSession();
  loadAll();
})();
