// Shared fetch wrapper that handles CSRF transparently. All
// state-changing requests go through apiFetch(); GETs may use plain
// fetch since the server exempts safe methods.
//
// The CSRF token is fetched once and cached. If a request returns 403
// with a csrf-related error body, we refresh the token and retry once.

(function () {
  let csrfToken = null;
  let csrfPromise = null;

  async function fetchCsrf() {
    if (csrfPromise) return csrfPromise;
    csrfPromise = fetch('/api/csrf', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(j => { csrfToken = j?.token ?? null; csrfPromise = null; return csrfToken; })
      .catch(() => { csrfPromise = null; return null; });
    return csrfPromise;
  }

  async function apiFetch(url, opts = {}) {
    const method = (opts.method || 'GET').toUpperCase();
    const stateChanging = !['GET', 'HEAD', 'OPTIONS'].includes(method);
    const headers = new Headers(opts.headers || {});
    if (opts.body && !headers.has('content-type') && !(opts.body instanceof FormData)) {
      headers.set('content-type', 'application/json');
    }
    if (stateChanging) {
      if (!csrfToken) await fetchCsrf();
      if (csrfToken) headers.set('x-csrf-token', csrfToken);
    }
    let r = await fetch(url, { ...opts, headers, credentials: 'same-origin' });
    if (r.status === 403 && stateChanging) {
      const body = await r.clone().json().catch(() => ({}));
      if ((body.error || '').toLowerCase().includes('csrf')) {
        // Refresh token once and retry.
        csrfToken = null;
        await fetchCsrf();
        if (csrfToken) headers.set('x-csrf-token', csrfToken);
        r = await fetch(url, { ...opts, headers, credentials: 'same-origin' });
      }
    }
    return r;
  }

  // Shared HTML escaper. Frontend used to concatenate raw values
  // (displayName, file.name, server error strings) into innerHTML,
  // which is a DOM-XSS vector. Every page now uses esc() before
  // interpolating user/server data.
  window.esc = function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  };

  window.apiFetch = apiFetch;
  // Prime the token on load so the first state-changing call doesn't pay the round-trip.
  fetchCsrf();

  // Mobile sidebar: inject hamburger toggle + scrim. CSS hides the
  // button above 768px; mobile shows it as a fixed pill.
  document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.querySelector('aside.sidebar');
    if (!sidebar || document.querySelector('.menu-toggle')) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'menu-toggle';
    btn.setAttribute('aria-label', 'Toggle navigation');
    btn.setAttribute('aria-expanded', 'false');
    btn.setAttribute('aria-controls', sidebar.id || (sidebar.id = 'arb-sidebar'));
    btn.textContent = '☰';
    document.body.appendChild(btn);
    const scrim = document.createElement('div');
    scrim.className = 'sidebar-scrim';
    document.body.appendChild(scrim);
    function setOpen(open) {
      sidebar.classList.toggle('is-open', open);
      scrim.classList.toggle('is-open', open);
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    btn.addEventListener('click', () => setOpen(!sidebar.classList.contains('is-open')));
    scrim.addEventListener('click', () => setOpen(false));
    document.addEventListener('keydown', e => { if (e.key === 'Escape') setOpen(false); });
    sidebar.addEventListener('click', e => { if (e.target.closest && e.target.closest('a')) setOpen(false); });
  });
})();
