#!/bin/sh
# Mirrors sechubdocker/frontend/docker-entrypoint.sh.
# Generates a self-signed cert if /app/.data/cert.pem + key.pem are
# missing so the HTTPS listener can boot without manual setup. Mount
# your own certs at /app/.data/cert.pem + /app/.data/key.pem to
# override.
set -eu

# Whitelist CERT_DIR so a hostile env can't redirect the cert write
# elsewhere or smuggle shell metacharacters through the script.
CERT_DIR="${CERT_DIR:-/app/.data}"
case "$CERT_DIR" in
    /app/.data|/etc/nist/certs|/tmp/nist-certs) ;;
    *) echo "[nist-tls] refusing unrecognised CERT_DIR: $CERT_DIR" >&2; exit 1 ;;
esac
CERT="$CERT_DIR/cert.pem"
KEY="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR"

# Serialize cert generation across simultaneous container starts that
# share this bind mount. flock holds an exclusive advisory lock on the
# lockfile for the duration of the subshell; the second starter waits.
# (alpine's util-linux ships flock; if missing, fall back to a noop —
# the worst case there is the existing race, not a regression.)
LOCK="$CERT_DIR/.tls.lock"
( touch "$LOCK" 2>/dev/null || true )

generate_cert() {
    if [ -s "$CERT" ] && [ -s "$KEY" ]; then
        echo "[nist-tls] Using existing cert at $CERT."
        return
    fi
    echo "[nist-tls] No cert found — generating self-signed (CN=nist.local, 365d valid)."
    # Stage to temp paths and atomically rename so concurrent readers
    # never observe a half-written cert / key pair.
    TMPCERT="$CERT_DIR/.cert.pem.$$"
    TMPKEY="$CERT_DIR/.key.pem.$$"
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -subj "/CN=nist.local" \
        -addext "subjectAltName=DNS:localhost,DNS:nist.local,IP:127.0.0.1" \
        -keyout "$TMPKEY" -out "$TMPCERT" 2>/dev/null
    chmod 600 "$TMPKEY"
    chmod 644 "$TMPCERT"
    mv "$TMPCERT" "$CERT"
    mv "$TMPKEY"  "$KEY"
    echo "[nist-tls] Self-signed cert ready. Replace $CERT / $KEY for production."
}

(
    # Open the lockfile on fd 200 inside the subshell, then flock takes
    # an exclusive hold on that fd until the subshell exits. On systems
    # without flock (very old busybox builds), this degrades to an
    # unsynchronised generate — same risk as the prior implementation.
    if command -v flock >/dev/null 2>&1; then
        flock -x 200
    fi
    generate_cert
) 200>"$LOCK"

exec "$@"
