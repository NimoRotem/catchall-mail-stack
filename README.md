# catchall-mail-stack

A self-hosted catch-all mail server with a clean web inbox, in a single Python file.

One process, one DB, one DKIM key per domain. It

- accepts inbound SMTP for every address `*@yourdomain.com` (catch-all),
- stores every message in PostgreSQL with attachments,
- forwards a copy to a personal Gmail mailbox,
- lets you read / search / star / delete / reply through a web UI at `/mail`,
- composes outbound mail with DKIM signing and direct-to-MX delivery (no relay),
- exposes a public `POST /api/contact` you can wire to your website's contact form.

The same `app.py` can run multiple times on one VM (one tenant per domain) by
chaining a small SMTP relay between the instance bound to public port 25 and the
others. See [Multi-tenant on one VM](#multi-tenant-on-one-vm).

## Architecture

```
                       internet
                          |
                          | TCP 25
                          v
        +-----------------------------------+
        |  iptables: 25 -> 2525  (REDIRECT) |
        +-----------------------------------+
                          |
                          v
   +-------------------------------------------+
   |  app.py  (FastAPI + aiosmtpd, one process)|
   |                                           |
   |  aiosmtpd  :2525  -- inbound SMTP         |
   |     |                                     |
   |     v                                     |
   |  Postgres `emails` + `attachments`        |
   |     |                                     |
   |     +-> forward via smtplib to Gmail      |
   |                                           |
   |  uvicorn   :8517  -- web UI + JSON API    |
   |     |                                     |
   |     +-> nginx /mail/ -> 127.0.0.1:8517    |
   +-------------------------------------------+
```

A single Python file (`app.py`) embeds everything: the SMTP receiver, the
PostgreSQL data layer, DKIM signing, the contact-form endpoint, the JSON API,
and the (vanilla, dependency-free) HTML/CSS/JS web client.

## Why this exists

Postfix + Dovecot + OpenDKIM + Roundcube is a lot of moving parts to give one
domain a usable inbox. This stack is the opposite trade-off: one Python file,
one Postgres database, one DKIM key. It runs in a few hundred MB of RAM and is
easy to read end-to-end.

## Features

- **Catch-all reception** — any `*@yourdomain.com` address is accepted and
  stored. No mailbox provisioning, no aliases to maintain.
- **Web inbox** — folders for Inbox / Sent / All Mail, search, star, bulk
  delete, threaded reply, per-message HTML rendering in a sandboxed iframe,
  attachment download.
- **Outbound DKIM signing** with the configured selector + private key.
- **Direct-to-MX delivery** with retry on temporary 4xx failures.
- **Auto-forward** every inbound message to a personal Gmail address (envelope
  From rewritten so SPF passes on the forward).
- **Public contact-form endpoint** (`POST /api/contact`) that stores the
  message in the inbox and forwards it. Useful for the marketing site.
- **Cookie auth** with a single configured user / password — sufficient for a
  one-person mailbox; swap in OAuth or HTTP basic if you need more.
- **Multi-tenant** — one VM, one public IP, multiple domains, one app instance
  each. The instance bound to public port 25 SMTP-relays inbound mail for the
  other domains to their internal SMTP listeners.

## Quickstart

```bash
# 1. Install deps
sudo apt install python3-venv postgresql nginx supervisor
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt

# 2. Create the DB + schema
sudo -u postgres createuser mailuser
sudo -u postgres createdb -O mailuser examplemail
psql -d examplemail -f schema.sql

# 3. Generate a DKIM keypair (prints the TXT record to publish)
./examples/dkim-setup.sh example.com mail

# 4. Configure DNS (see DNS section below)

# 5. Open port 25 and add the iptables redirect
sudo ./examples/iptables-port25.sh

# 6. Put the supervisor file in place and start
sudo cp examples/supervisor.conf /etc/supervisor/conf.d/example-mail.conf
# ... edit the placeholders ...
sudo supervisorctl reread && sudo supervisorctl update

# 7. Add the nginx site + TLS
sudo cp examples/nginx.conf /etc/nginx/sites-available/example.com
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/
sudo certbot --nginx -d example.com -d www.example.com
```

Then visit `https://example.com/mail/` and sign in with `MAIL_USER` / `MAIL_PASS`.

## Configuration

All configuration is environment variables — there is no config file. Set them
in your supervisor / systemd unit.

| Variable | Default | Purpose |
|----------|---------|---------|
| `MAIL_DOMAIN` | `nebula-bio.com` | The domain this instance owns. Mail to `*@MAIL_DOMAIN` is stored locally. |
| `MAIL_HOSTNAME` | `mail.<domain>` | HELO/EHLO hostname. Should resolve back to the VM's public IP. |
| `MAIL_BRAND` | `Nebula Mail` | Display name in HTML titles and the sidebar logo. |
| `MAIL_COOKIE` | `nebula_mail_auth` | Auth cookie name. Use a unique value per tenant. |
| `MAIL_DB_DSN` | `postgresql://nimrod_rotem@/nebulamail` | PostgreSQL DSN. |
| `MAIL_FORWARD_TO` | _(empty)_ | If set, inbound mail is also forwarded here (e.g. your Gmail). |
| `MAIL_DEFAULT_FROM` | `info@<domain>` | Pre-filled From address in the compose modal. |
| `MAIL_USER` / `MAIL_PASS` | `admin` / _(empty)_ | The single login credential. Empty `MAIL_PASS` disables auth — don't do that in production. |
| `MAIL_SECRET` | random | HMAC secret for the auth cookie. Set to a long random hex string. |
| `MAIL_PORT` | `8507` | HTTP port the FastAPI app binds to (loopback). |
| `MAIL_ROOT_PATH` | `/mail` | URL prefix the app is mounted under. |
| `SMTP_PORT` | `2525` | Port aiosmtpd binds to. Public port 25 should redirect here via iptables. |
| `SMTP_HOST` | `0.0.0.0` | Interface aiosmtpd binds to. Use `127.0.0.1` for non-public secondary tenants. |
| `DKIM_KEY` | `./dkim_private.key` | Path to the DKIM private key. |
| `DKIM_SELECTOR` | `mail` | DKIM selector. Public key is published at `<selector>._domainkey.<domain>`. |
| `MAIL_RELAY_DOMAINS` | _(empty)_ | Multi-tenant: comma-separated `domain=host:port` map. Inbound for those domains is SMTP-relayed instead of stored. |

## DNS setup

This is the single hardest part of running your own mail. Get every record
right or your outbound mail lands in spam (and your inbound never arrives).

### Records you need

```
A     @                       <vm-ip>          ; for the website
A     mail                    <vm-ip>          ; HELO/EHLO target
MX    @                       mail.<domain>    ; priority 10
TXT   @                       v=spf1 ip4:<vm-ip> ~all
TXT   mail._domainkey         v=DKIM1;k=rsa;p=<base64-of-public-key>
TXT   _dmarc                  v=DMARC1; p=none; rua=mailto:dmarc@<domain>
PTR   <vm-ip>  ->  mail.<domain>      ; set this with your hosting provider
```

`./examples/dkim-setup.sh <domain>` generates the keypair and prints the exact
DKIM TXT value to publish.

### The full deliverability checklist

| Setting | Required record / action |
|---------|--------------------------|
| **MX** | `@ MX 10 mail.<domain>` |
| **SPF** | `@ TXT "v=spf1 ip4:<vm-ip> ~all"` (use `include:` if you also send through a third party). |
| **DKIM** | `mail._domainkey TXT "v=DKIM1;k=rsa;p=..."` — the public half of the keypair generated by `dkim-setup.sh`. |
| **DMARC** | `_dmarc TXT "v=DMARC1; p=none; rua=mailto:dmarc@<domain>; adkim=s; aspf=s"` to start. |
| **rDNS / PTR** | `<vm-ip>` must reverse-resolve to `mail.<domain>`. Set this in your hosting provider's reverse-DNS settings. |
| **Forward DNS** | `mail.<domain>` must resolve back to the same IP — which is already covered by the `A mail` record. |
| **HELO/EHLO** | The app sets `MAIL_HOSTNAME` (default `mail.<domain>`). Don't leave it as the random VPS hostname. |
| **STARTTLS** | The outbound delivery path attempts STARTTLS opportunistically. Inbound STARTTLS support is planned — most major receivers will still accept plaintext. |
| **ARC** | Useful when you forward, but optional. Not implemented here. |
| **List-Unsubscribe** | Use the `list_unsubscribe` field on `POST /api/send` for any bulk/marketing mail. The app sets `List-Unsubscribe-Post: List-Unsubscribe=One-Click`. |
| **Dedicated sending subdomain** | Optional. Use `send.<domain>` if you want to isolate marketing reputation from transactional. |
| **No open relay** | The SMTP receiver only accepts `RCPT TO:` for `MAIL_DOMAIN` (or domains listed in `MAIL_RELAY_DOMAINS`). Outbound `/api/send` requires the auth cookie and rejects `From` outside `MAIL_DOMAIN`. |
| **Clean IP reputation** | New IPs need warm-up — start with low volume. |

### DMARC tightening schedule

Start with `p=none` so you can see what's failing without bouncing real mail.

```
v=DMARC1; p=none;       rua=mailto:dmarc@<domain>; adkim=s; aspf=s
```

After 1–2 weeks of clean reports, tighten to:

```
v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>; adkim=s; aspf=s
```

Then later:

```
v=DMARC1; p=reject;     rua=mailto:dmarc@<domain>; adkim=s; aspf=s
```

## Multi-tenant on one VM

Only one process can bind public port 25 (one IP -> one PTR -> one HELO host).
You can still serve N domains from N copies of `app.py`:

1. Run instance **A** (the gateway) for `domain-a.com` with `SMTP_HOST=0.0.0.0`,
   `SMTP_PORT=2525`, and the iptables 25->2525 redirect.
2. Run instance **B** for `domain-b.com` with `SMTP_HOST=127.0.0.1`,
   `SMTP_PORT=2526`, its own DB, its own DKIM key.
3. On instance A, set:

   ```
   MAIL_RELAY_DOMAINS="domain-b.com=127.0.0.1:2526"
   ```

A's `RCPT TO:` handler now also accepts `*@domain-b.com` and SMTP-relays the
message to B over loopback. Each tenant has its own DB, web UI, login,
DKIM key, and forward target. The PTR for the shared IP can only point to one
host, but that doesn't prevent SPF/DKIM/DMARC from passing for both — it does
mean strict reverse-DNS checks may slightly reduce reputation on the secondary
domain.

This is exactly how `nebula-bio.com` (gateway) and `rotem.cc` (relayed)
co-habit on one IP in this repo's reference deployment.

## API

The web UI uses these endpoints; you can hit them yourself with the auth cookie.

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/login` | Form-encoded `username`/`password`. Sets the auth cookie. |
| `GET`  | `/api/emails?folder=inbox\|sent\|all&page=1&per_page=50&search=` | List emails with paging + search. |
| `GET`  | `/api/emails/{id}` | Fetch one email + attachments metadata. Marks it read. |
| `POST` | `/api/emails/{id}/star` | Toggle star. |
| `POST` | `/api/emails/bulk-delete` | `{ "ids": [1,2,3] }` |
| `DELETE` | `/api/emails/{id}` | Delete one. |
| `GET`  | `/api/attachment/{id}` | Download an attachment. |
| `POST` | `/api/send` | Compose and send (DKIM-signed, direct-to-MX). |
| `GET`  | `/api/stats` | `{unread, total_inbox, total_sent}` |
| `POST` | `/api/contact` | **Public** — no auth. Used by your marketing site's contact form. |

## Operational notes

- The app deliberately does not implement IMAP, POP3, or inbound STARTTLS.
  Inbound runs as plaintext SMTP on the loopback side; nginx terminates TLS for
  the web UI.
- Mail body and attachments are stored as `TEXT` and `BYTEA` respectively.
  Postgres handles this fine for small mailboxes; if you expect millions of
  messages, move attachments to object storage.
- Forwarding rewrites `MAIL FROM:` to `forward@<domain>` so SPF passes on
  Gmail's side. Gmail will display the original `From:` header normally.
- The auth model is a single user with an HMAC-signed cookie. Good enough for a
  one-person mailbox. For multiple users, replace `auth_middleware` with your
  IdP of choice.
- Hooks into legitimate spam scoring (rspamd, SpamAssassin) are intentionally
  absent — the assumption is you're running a low-volume mailbox where you're
  comfortable manually triaging junk in the web UI.

## License

MIT — see `LICENSE`.

## Inbound spam filtering

A catchall mailbox accepts **all** mail for its domain and forwards it onward
(`MAIL_FORWARD_TO`, or sibling tenants). If that inbound is spam, forwarding it
re-sends it **from your own domain** (aligned DKIM) — which makes your domain
look like a spammer to Gmail and poisons the sending reputation you rely on for
real mail. `spamfilter.py` scores inbound mail and **refuses to forward the
spam** (a copy is still kept, flagged `is_spam`, so nothing is lost).

**Signals (dependency-light — dnspython + dkimpy only):**
- IP blocklists (Spamhaus ZEN, Barracuda, SpamCop) on the connecting IP
- DKIM verification + a best-effort SPF check
- Content heuristics (sextortion / crypto-extortion / lottery / phishing /
  pharma / SEO), shouty subjects, brand-name display spoofing, URL shorteners,
  risky attachments, suspicious TLDs

**Fail-open by design:** any scoring error classifies the message as *ham*, so a
bug can never drop a legitimate email.

**Config (env):**

| Var | Default | Meaning |
|-----|---------|---------|
| `SPAM_FILTER` | `1` | master on/off |
| `SPAM_THRESHOLD` | `6` | score at/above which mail is spam |
| `SPAM_DNSBL` | `1` | enable IP blocklist lookups |
| `SPAM_ALLOW_DOMAINS` | *(your own domains)* | never-spam sender domains |
| `SPAM_BLOCK_DOMAINS` | *(empty)* | always-spam sender domains |
| `MAIL_OWN_DOMAINS` | *(empty)* | your domains (allowlisted + used for spoof detection) |

Spam is hidden from the inbox and viewable at `?folder=spam`. The DB gains
`is_spam` / `spam_score` / `spam_reasons` columns (auto-migrated on startup).
