# Contributing to nist-express

Thanks for your interest. This is a security-sensitive codebase, so a
few rules:

## Licence

This project is licensed under the **GNU General Public License v3.0
(GPL-3.0-only)**. By submitting a contribution you agree it can be
distributed under that licence. See [`LICENSE`](LICENSE).

## Reporting a vulnerability

**Do not file public issues for security bugs.** Email the maintainers
listed in [`CODEOWNERS`](CODEOWNERS) instead. If a public report is
your only option, mark the issue title `SECURITY:` and we will move
the conversation private within 24h.

## Local development

```bash
# install Node 22 first (Ubuntu: see docs/INSTALL.md § 2a)
npm ci                    # installs dev + runtime deps
npm run build             # tsc → dist/
PORT=8080 node dist/server.js   # or `npm run dev` for auto-reload
npm test                  # all tests must pass
```

For a containerised dev loop:

```bash
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml logs -f
docker compose -f deploy/docker-compose.yml down
```

Style:

- TypeScript strict mode.
- One module per concern. Avoid sprawling files.
- Comments explain **why** (not what). Keep them short.
- Test new code in `tests/`. Aim for the engine to be 100% deterministic
  so the test suite is fast.

## Pull-request checklist

- [ ] `npm test` is green.
- [ ] `npx tsc --noEmit` is clean.
- [ ] New routes carry `requireAccess` if assessment-scoped, and the
  right role guard if admin-scoped. Sensitive ops require sudo mode.
- [ ] Logging respects the levels in `src/obs/logger.ts`. No
  `console.log`.
- [ ] No secrets / personal data committed.
- [ ] Documentation in `docs/` updated when behaviour changes.
- [ ] If a new compliance framework is added, the OSCAL + CSV
  exporters round-trip it cleanly.

## Bumping the OWASP ASVS report

When a code change satisfies a previously PARTIAL/GAP item in
`src/engine/asvs.ts`, update the status **and** the `evidence`
field to point to the file:line that proves it. The point of the
self-attestation is that someone can verify it without trust.
