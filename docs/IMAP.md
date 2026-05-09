# IMAP server (basic)

Mailpit ships an optional IMAP4rev1 server so that real mail clients
(Thunderbird, K-9, Apple Mail, mutt, neomutt, evolution, the `curl`
IMAP scheme, etc.) can connect, browse captured messages, and receive
new-mail push notifications via the `IDLE` extension.

## Scope

The IMAP server is intentionally minimal — it exists for ergonomics
during development and integration testing, **not** as a general-purpose
mailbox.

| Feature                       | Supported?                                |
| ----------------------------- | ----------------------------------------- |
| Folder hierarchy              | No — single `INBOX` only                  |
| `IDLE` push notifications     | Yes (RFC 2177)                            |
| `\Seen` flag                  | Yes — mapped to Mailpit's `Read` field    |
| `\Deleted` + `EXPUNGE`        | Yes — calls `storage.DeleteMessages`      |
| Other IMAP flags              | Accepted but not persisted                |
| `APPEND` (upload via IMAP)    | Yes (LITERAL+ supported)                  |
| `COPY <set> INBOX`            | Yes (no-op since same mailbox)            |
| `MOVE`, `COPY` to other dest  | No                                        |
| `STARTTLS`                    | No — use implicit TLS (see below)         |
| `SEARCH`                      | `ALL`, `UNSEEN`, `SEEN`, `NEW`, `RECENT`, `UID <set>` |
| `UIDVALIDITY` persistence     | No — changes every Mailpit restart        |

Anything outside that list is rejected with `BAD` or `NO` so clients
fall back gracefully rather than hanging.

> **Why no folders?** Mailpit's storage model is a flat mailbox. Folders
> would require schema changes and a sync layer that isn't worth the
> complexity for a development tool. If you need folder semantics,
> consider [GreenMail](http://www.icegreen.com/greenmail/) or
> [Dovecot](https://www.dovecot.org/) running against Mailpit's SMTP.

## Configuration

The IMAP server is **disabled by default**. It enables itself when both
of the following are true:

1. A POP3 auth file is configured (IMAP shares POP3 credentials, so a
   single `htpasswd`-style file unlocks both protocols).
2. `IMAPListen` is non-empty (it defaults to `[::]:1143` so this is
   already the case unless you've explicitly cleared it).

### CLI flags

| Flag              | Default       | Description                              |
| ----------------- | ------------- | ---------------------------------------- |
| `--imap`          | `[::]:1143`   | IMAP bind interface and port             |
| `--imap-tls-cert` | _(unset)_     | TLS certificate (requires `--imap-tls-key`) |
| `--imap-tls-key`  | _(unset)_     | TLS key (requires `--imap-tls-cert`)     |

### Environment variables

| Variable             | Equivalent flag      |
| -------------------- | -------------------- |
| `MP_IMAP_BIND_ADDR`  | `--imap`             |
| `MP_IMAP_TLS_CERT`   | `--imap-tls-cert`    |
| `MP_IMAP_TLS_KEY`    | `--imap-tls-key`     |

To **disable** the IMAP server, set the bind address to an empty string:

```sh
mailpit --imap ""
```

### Authentication

IMAP shares the POP3 credentials. Set up an htpasswd file once and both
protocols accept the same logins:

```sh
htpasswd -B -c /etc/mailpit/auth dev
mailpit \
  --pop3-auth-file /etc/mailpit/auth \
  --imap 127.0.0.1:1143
```

`go-htpasswd`'s default systems are supported (bcrypt, sha, md5-crypt,
plain). Bcrypt is recommended.

### TLS

Implicit TLS only — point a cert/key pair at `--imap-tls-cert` and
`--imap-tls-key` and the listener wraps in TLS at accept time. There is
no `STARTTLS`. For self-signed certs in development:

```sh
mailpit \
  --imap-tls-cert "sans:127.0.0.1,localhost" \
  --imap-tls-key  "sans:127.0.0.1,localhost"
```

The `sans:` prefix triggers Mailpit's built-in self-signed certificate
generator (same convention as the SMTP and POP3 servers).

## Quickstart — Thunderbird

1. **Start Mailpit** with IMAP and a credentials file:

   ```sh
   echo 'dev:$2y$05$<bcrypt-hash>' > /tmp/mp.auth
   mailpit --pop3-auth-file /tmp/mp.auth --imap 127.0.0.1:1143
   ```

2. In Thunderbird → **Account Settings → Add Mail Account**:

   | Field            | Value                                    |
   | ---------------- | ---------------------------------------- |
   | Server hostname  | `127.0.0.1`                              |
   | Port             | `1143`                                   |
   | Connection sec.  | None (or SSL/TLS if you set certs above) |
   | Auth method      | Normal password                          |
   | Username         | `dev`                                    |

3. Send a test message via SMTP — Thunderbird shows it in INBOX
   immediately, courtesy of `IDLE`.

## Quickstart — `curl`

`curl` understands the `imap://` scheme:

```sh
# List INBOX
curl --user dev:devpass imap://127.0.0.1:1143/INBOX

# Search for unseen
curl --user dev:devpass 'imap://127.0.0.1:1143/INBOX?UNSEEN'

# Fetch UID 1
curl --user dev:devpass 'imap://127.0.0.1:1143/INBOX;UID=1'
```

## Quickstart — `mutt` / `neomutt`

In `~/.muttrc`:

```muttrc
set imap_user = "dev"
set imap_pass = "devpass"
set folder    = "imap://127.0.0.1:1143"
set spoolfile = "+INBOX"
set imap_idle = yes
mailboxes     = "+INBOX"
```

`set imap_idle = yes` enables `IDLE` so new mail appears in the index
without polling.

## How `IDLE` works in Mailpit

When a client issues `IDLE`, the server subscribes to the in-process
event bus that Mailpit's storage layer publishes to. Any subsequent
`storage.Store(...)` (i.e., a new SMTP delivery, an API ingest, or an
IMAP `APPEND`) emits a `"new"` event, which the IDLE session translates
into an untagged `* N EXISTS` response on the IMAP socket. Same for
deletions (`* M EXPUNGE`).

There is no polling. Latency from delivery to client notification is a
single goroutine hop — typically sub-millisecond on localhost.

The server enforces a 30-minute IDLE ceiling per RFC 2177
recommendations; clients should re-issue `IDLE` every ~29 minutes to
avoid the timeout `* BYE`.

## UID semantics

IMAP requires every message to have a stable, unique 32-bit `UID`.
Mailpit assigns these in-memory at first encounter and never reuses
them within a process lifetime.

`UIDVALIDITY` is set to `uint32(time.Now().Unix())` at process start.
**A Mailpit restart bumps `UIDVALIDITY`**, which tells IMAP clients to
discard their UID cache and resync — exactly the right semantics for a
dev tool whose state isn't durable across restarts.

If your test workflow expects long-term UID stability across server
restarts, IMAP isn't the right tool. Use the [REST API](https://mailpit.axllent.org/docs/api-v1/)
instead.

## Limitations & caveats

- **No persistence of IMAP state.** `\Seen` round-trips through
  Mailpit's `Read` field (so the web UI sees it), but other flags
  (`\Flagged`, custom labels, `$Forwarded`, etc.) are accepted-but-
  forgotten.
- **No `STARTTLS`.** Use implicit TLS or terminate at a reverse proxy.
- **No `SORT` / `THREAD`.** Common in real clients but not implemented.
- **Sequence numbers reset per `SELECT`.** `IDLE` updates the
  view live; explicit `NOOP` reconciles between commands.
- **Single mailbox.** `LIST "" "*"` returns just `INBOX`. Don't expect
  `Sent`, `Drafts`, or `Trash` to be browsable — they don't exist in
  Mailpit's storage model.

## Reporting bugs

The IMAP implementation lives in [`internal/imap/`](../internal/imap/).
Run the test suite with `go test ./internal/imap/...` — the tests
include an end-to-end `IDLE` push-notification scenario.
