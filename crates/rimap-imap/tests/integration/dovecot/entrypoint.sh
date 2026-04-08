#!/bin/sh
set -eu

# Generate a self-signed cert at container start so each test run gets a
# fresh fingerprint.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/dovecot/key.pem \
    -out /etc/dovecot/cert.pem \
    -days 1 \
    -subj "/CN=rimap-test-dovecot" >/dev/null 2>&1

# Compute and publish the SHA-256 fingerprint of the leaf cert (DER form,
# lowercase hex, no separators) so the host harness can read it.
openssl x509 -in /etc/dovecot/cert.pem -outform DER |
    openssl dgst -sha256 -hex |
    awk '{print $2}' \
        >/shared/fingerprint.hex

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

# Mark ready so the host harness's healthcheck passes.
touch /shared/ready

# Hand off to dovecot.
exec dovecot -F
