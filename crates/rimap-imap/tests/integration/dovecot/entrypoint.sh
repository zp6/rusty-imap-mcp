#!/bin/sh
set -eu

# Progress markers — every line below is meant to appear in
# `podman compose logs` so a stuck startup points at a specific stage.
log() { printf '[entrypoint] %s\n' "$*" >&2; }

log "start"

# Clean up any stale dovecot runtime state. When case_11 recreates the
# container via `docker compose up -d --force-recreate`, this dir starts
# empty — but the recursive rm is still a safety net for any future change
# that moves to a stop/start flow where the container fs persists.
rm -rf /var/run/dovecot 2>/dev/null || true
mkdir -p /var/run/dovecot

# Delete the readiness markers from any previous boot. /shared is a
# named volume that survives container recreation, so without this the
# host harness would see the old markers and proceed before dovecot in
# the new container has actually bound port 993 — exactly the TLS
# handshake EOF race we hit on CI. /shared/cert.pem and /shared/key.pem
# are NOT deleted: they're load-bearing for fingerprint persistence
# across the recreate that case_11 uses.
rm -f /shared/ready /shared/fingerprint.hex

# Generate the self-signed cert ON THE SHARED VOLUME (not in the
# container's own filesystem) so it survives container recreation.
# case_11 uses `docker compose up -d --force-recreate dovecot` to
# deterministically break cached client TCP sessions, and the test
# relies on the SAME pinned fingerprint surviving across the recreate
# so the post-disconnect reconnect succeeds.
if [ ! -f /shared/cert.pem ]; then
    log "generating self-signed cert"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /shared/key.pem \
        -out /shared/cert.pem \
        -days 1 \
        -subj "/CN=rimap-test-dovecot" >/dev/null 2>&1
    log "cert generated"
else
    log "reusing cached cert"
fi
# Place the cert where dovecot.conf expects it. Copy (not symlink) so a
# change in shared-volume semantics doesn't break dovecot's open().
cp /shared/cert.pem /etc/dovecot/cert.pem
cp /shared/key.pem /etc/dovecot/key.pem
chmod 0600 /etc/dovecot/key.pem

# Compute the SHA-256 fingerprint of the leaf cert (DER form, lowercase
# hex, no separators). We write it out AFTER dovecot is actually listening
# below so the host harness's read_fingerprint probe doubles as a readiness
# signal — otherwise the fingerprint appears before dovecot binds 993 and
# the host connects too early (TLS handshake EOF / connection reset).
fingerprint=$(openssl x509 -in /etc/dovecot/cert.pem -outform DER |
    openssl dgst -sha256 -hex |
    awk '{print $2}')

# Seed mailboxes for the test user.
mkdir -p /var/mail/rimap-test/Maildir/cur \
    /var/mail/rimap-test/Maildir/new \
    /var/mail/rimap-test/Maildir/tmp \
    "/var/mail/rimap-test/Maildir/.Archive/cur" \
    "/var/mail/rimap-test/Maildir/.Archive/new" \
    "/var/mail/rimap-test/Maildir/.Archive/tmp" \
    "/var/mail/rimap-test/Maildir/.INBOX.Subfolder/cur" \
    "/var/mail/rimap-test/Maildir/.INBOX.Subfolder/new" \
    "/var/mail/rimap-test/Maildir/.INBOX.Subfolder/tmp"

# Drop fixture .eml files into INBOX/new — Dovecot will move them to cur on
# next read.
i=0
for fixture in /fixtures/*.eml; do
    i=$((i + 1))
    cp "$fixture" "/var/mail/rimap-test/Maildir/new/${i}.fixture"
done

log "seeding maildir + fixtures (${i:-0} eml files copied)"

chown -R 1000:1000 /var/mail/rimap-test
chmod -R u+rwX /var/mail/rimap-test

log "starting dovecot in foreground"
# Start dovecot in the background so we can wait for it to bind port 993
# before publishing the readiness signals.
dovecot -F &
dovecot_pid=$!
log "dovecot pid=$dovecot_pid, waiting for LISTEN on 993"

# Wait for dovecot to enter LISTEN state on TCP port 993 (hex 03E1).
# Parse /proc/net/tcp and /proc/net/tcp6 directly — no extra tools needed.
# State 0A == TCP_LISTEN. 60s cap at 0.25s intervals == 240 attempts.
i=0
while [ $i -lt 240 ]; do
    if grep -Eq ' [0-9A-F]+:03E1 [0-9A-F]+:[0-9A-F]+ 0A ' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
        break
    fi
    # If dovecot exited before binding, fail fast.
    if ! kill -0 "$dovecot_pid" 2>/dev/null; then
        echo "dovecot exited before binding port 993" >&2
        exit 1
    fi
    i=$((i + 1))
    sleep 0.25
done

if [ $i -ge 240 ]; then
    echo "timed out waiting for dovecot to bind port 993" >&2
    kill "$dovecot_pid" 2>/dev/null || true
    exit 1
fi

log "dovecot bound 993, publishing ready marker"
# Now publish the fingerprint and ready marker — the host harness polls
# for fingerprint.hex and only proceeds once it can read it.
printf '%s\n' "$fingerprint" >/shared/fingerprint.hex
touch /shared/ready
log "ready"

# Hand off: wait on dovecot, propagating its exit code.
wait "$dovecot_pid"
exit $?
