# Proton Bridge integration tests (local only)

These tests connect to a running Proton Bridge instance and exercise the
real IMAP login flow against a real mailbox. They never run in CI — they
require credentials in environment variables and a Bridge instance the
test machine has logged into.

## Prerequisites

1. Install [Proton Mail Bridge](https://proton.me/mail/bridge) and log in.
2. Open Bridge → Settings → IMAP/SMTP and note the IMAP host (default
   `127.0.0.1`) and port (default `1143`).
3. Extract Bridge's TLS fingerprint with the openssl one-liner below — Bridge
   uses a per-installation self-signed cert that the system trust store
   does not know about, so the test must pin it.

## Extracting the fingerprint

```sh
echo | openssl s_client -connect 127.0.0.1:1143 -starttls imap 2>/dev/null \
    | openssl x509 -outform DER \
    | openssl dgst -sha256 -hex \
    | awk '{print $2}'
```

The output is a 64-character lowercase hex string. Set it as
`PROTON_BRIDGE_FINGERPRINT` (see below).

## Required environment variables

| Variable | Description |
|---|---|
| `PROTON_BRIDGE_TEST` | Set to any non-empty value to enable the tests. |
| `PROTON_BRIDGE_HOST` | Bridge IMAP host. Default `127.0.0.1`. |
| `PROTON_BRIDGE_PORT` | Bridge IMAP port. Default `1143`. |
| `PROTON_BRIDGE_USER` | Bridge IMAP username (your Proton email). |
| `PROTON_BRIDGE_PASS` | Bridge IMAP password (the per-app password Bridge generates, NOT your Proton account password). |
| `PROTON_BRIDGE_FINGERPRINT` | The 64-char hex fingerprint extracted above. |

Proton Bridge's default IMAP connection mode is **STARTTLS on port 1143**. This test harness connects with `encryption = "starttls"`.

## Running

```sh
PROTON_BRIDGE_TEST=1 \
  PROTON_BRIDGE_USER=alice@proton.me \
  PROTON_BRIDGE_PASS=xxxx-xxxx-xxxx-xxxx \
  PROTON_BRIDGE_FINGERPRINT=abc... \
  cargo test -p rimap-imap --test proton
```

Without `PROTON_BRIDGE_TEST=1` the tests skip silently and pass.

## Security notes

- Putting Bridge passwords in environment variables means they end up in
  shell history, process listings, and (on shared dev machines) other
  users' view of `/proc/<pid>/environ`. Run this on a personal workstation
  only.
- The test connects to a real mailbox and READS messages. It does not
  modify, delete, or send anything. Sprint 3 has no write operations.
- Bridge's TLS fingerprint changes if you reinstall Bridge or rotate its
  cert; you must re-extract and re-set the env var when this happens.
