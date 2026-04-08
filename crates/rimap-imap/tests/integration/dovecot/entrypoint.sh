#!/bin/sh
set -eu

# Generate a self-signed cert at container start so each test run gets a
# fresh fingerprint. Skip if a cert already exists — `docker compose
# restart` (used by case_11 to break the client TCP) re-runs the
# entrypoint, and the test relies on the SAME pinned fingerprint surviving
# across the restart so the post-disconnect reconnect succeeds.
if [ ! -f /etc/dovecot/cert.pem ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /etc/dovecot/key.pem \
        -out /etc/dovecot/cert.pem \
        -days 1 \
        -subj "/CN=rimap-test-dovecot" >/dev/null 2>&1
fi

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

chown -R 1000:1000 /var/mail/rimap-test
chmod -R u+rwX /var/mail/rimap-test

# Start dovecot in the background so we can wait for it to bind port 993
# before publishing the readiness signals.
dovecot -F &
dovecot_pid=$!

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

# Now publish the fingerprint and ready marker — the host harness polls
# for fingerprint.hex and only proceeds once it can read it.
printf '%s\n' "$fingerprint" >/shared/fingerprint.hex
touch /shared/ready

# Hand off: wait on dovecot, propagating its exit code.
wait "$dovecot_pid"
