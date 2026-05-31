// FIPS 140-2/140-3 attestation. Node.js can run in FIPS mode when
// the OpenSSL build supports it; the platform exposes this state so
// operators can prove the crypto in use is FIPS-validated.
//
// To run in FIPS mode:
//   - Build / use a FIPS-enabled Node (e.g. via @anthropic-fips or
//     RHEL/UBI base images with FIPS-validated OpenSSL).
//   - Start the process with --enable-fips or --force-fips, or set
//     NODE_OPTIONS="--enable-fips" before exec.
//   - The platform also accepts FORCE_FIPS=1 to call
//     crypto.setFips(true) at startup.

import crypto from 'crypto';

export interface FipsStatus {
  fipsEnabled: boolean;
  mode: string;
  verifiedAt: string;
  opensslVersion?: string;
}

let cached: FipsStatus | null = null;
let lastChecked = 0;

export function fipsStatus(): FipsStatus {
  // Refresh at most once per minute (it never changes at runtime in practice).
  const now = Date.now();
  if (cached && now - lastChecked < 60_000) return cached;
  let enabled = false;
  try { enabled = !!crypto.getFips?.(); } catch { enabled = false; }
  const mode = enabled
    ? 'FIPS-enabled OpenSSL — crypto operations restricted to FIPS-validated algorithms'
    : process.env.FORCE_FIPS === '1'
      ? 'FORCE_FIPS=1 requested but Node was not built with FIPS support — falling back to non-FIPS'
      : 'Standard OpenSSL — not FIPS mode';
  cached = {
    fipsEnabled: enabled,
    mode,
    verifiedAt: new Date(now).toISOString(),
    opensslVersion: process.versions.openssl
  };
  lastChecked = now;
  return cached;
}

// Optionally attempt to enable FIPS at startup. Safe to call even on
// non-FIPS Node — it logs and continues.
export function tryEnableFips(): void {
  if (process.env.FORCE_FIPS === '1') {
    try {
      crypto.setFips?.(true);
    } catch {
      // OpenSSL build lacks FIPS — surface in /api/fips-status
    }
  }
}
