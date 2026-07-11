"""
Nebula Bio Mail — Catchall email server + web client for nebula-bio.com
Single-file FastAPI + aiosmtpd application.
"""
from __future__ import annotations

import asyncio
import base64
import email
import email.message
import email.policy
import email.utils
import hashlib
import hmac
import json
import logging
import os
import secrets
import smtplib
import ssl
import time
import traceback
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

import asyncpg
import dkim
import dns.resolver
import uvicorn
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer, Envelope, Session
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PORT = int(os.environ.get("MAIL_PORT", "8507"))
SMTP_PORT = int(os.environ.get("SMTP_PORT", "2525"))
SMTP_HOST = os.environ.get("SMTP_HOST", "0.0.0.0")
DOMAIN = os.environ.get("MAIL_DOMAIN", "nebula-bio.com")
HOSTNAME = os.environ.get("MAIL_HOSTNAME", f"mail.{DOMAIN}")
BRAND = os.environ.get("MAIL_BRAND", "Nebula Mail")
COOKIE_NAME = os.environ.get("MAIL_COOKIE", "nebula_mail_auth")
DB_DSN = os.environ.get("MAIL_DB_DSN", "postgresql://nimrod_rotem@/nebulamail")
FORWARD_TO = os.environ.get("MAIL_FORWARD_TO", "")
try:
    import spamfilter as _spamfilter
except Exception:
    _spamfilter = None
SPAM_FILTER_ENABLED = os.environ.get("SPAM_FILTER", "1") != "0" and _spamfilter is not None
SPAM_THRESHOLD = float(os.environ.get("SPAM_THRESHOLD", "6") or 6)
SPAM_USE_DNSBL = os.environ.get("SPAM_DNSBL", "1") != "0"
SPAM_ALLOW_DOMAINS = {d.strip().lower() for d in os.environ.get("SPAM_ALLOW_DOMAINS",
    "grabo.com,nemopowertools.com,grabo.cc,lisa.my,alphabell.com,rotem.ai,rotem.cc,nebula-bio.com").split(",") if d.strip()}
SPAM_BLOCK_DOMAINS = {d.strip().lower() for d in os.environ.get("SPAM_BLOCK_DOMAINS", "").split(",") if d.strip()}
SPAM_OWN_DOMAINS = {DOMAIN.lower()} | {d.strip().lower() for d in os.environ.get("MAIL_OWN_DOMAINS", "").split(",") if d.strip()}

DKIM_SELECTOR = os.environ.get("DKIM_SELECTOR", "mail")
DKIM_KEY_PATH = Path(os.environ.get("DKIM_KEY", str(Path(__file__).parent / "dkim_private.key")))

AUTH_USER = os.environ.get("MAIL_USER", "admin")
AUTH_PASS = os.environ.get("MAIL_PASS", "")
AUTH_SECRET = os.environ.get("MAIL_SECRET", secrets.token_hex(32))

ROOT_PATH = os.environ.get("MAIL_ROOT_PATH", "/mail")
DEFAULT_FROM = os.environ.get("MAIL_DEFAULT_FROM", f"info@{DOMAIN}")
# Map of domain -> "host:port" SMTP relay targets, e.g. "rotem.cc=127.0.0.1:2526"
# Comma-separated. Inbound mail to those domains gets relayed via SMTP, not stored locally.
RELAY_DOMAINS_RAW = os.environ.get("MAIL_RELAY_DOMAINS", "")
RELAY_DOMAINS = {}
for _entry in RELAY_DOMAINS_RAW.split(","):
    _entry = _entry.strip()
    if "=" in _entry:
        _d, _hp = _entry.split("=", 1)
        _h, _, _p = _hp.partition(":")
        RELAY_DOMAINS[_d.strip().lower()] = (_h.strip(), int(_p) if _p else 25)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(BRAND.lower().replace(" ", ""))

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
pool: Optional[asyncpg.Pool] = None


async def init_db():
    global pool
    pool = await asyncpg.create_pool(dsn=DB_DSN, min_size=2, max_size=10)
    log.info("Database pool initialized")
    try:
        async with pool.acquire() as _c:
            await _c.execute("ALTER TABLE emails ADD COLUMN IF NOT EXISTS is_spam BOOLEAN DEFAULT FALSE")
            await _c.execute("ALTER TABLE emails ADD COLUMN IF NOT EXISTS spam_score REAL")
            await _c.execute("ALTER TABLE emails ADD COLUMN IF NOT EXISTS spam_reasons TEXT")
            await _c.execute("CREATE INDEX IF NOT EXISTS idx_emails_spam ON emails(is_spam)")
    except Exception as _e:
        log.warning(f"spam migration skipped: {_e}")


async def store_email(direction, envelope_from, envelope_to, raw_bytes):
    """Parse and store an email, return its id."""
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    subject = msg.get("Subject", "(no subject)") or "(no subject)"
    from_header = msg.get("From", envelope_from) or envelope_from or ""
    to_header = msg.get("To", envelope_to) or envelope_to or ""
    cc_header = msg.get("Cc", "") or ""
    reply_to = msg.get("Reply-To", "") or ""
    message_id = msg.get("Message-ID", "") or ""
    in_reply_to = msg.get("In-Reply-To", "") or ""
    references = msg.get("References", "") or ""

    body_text = ""
    body_html = ""
    has_attachments = False
    attachment_list = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                has_attachments = True
                payload = part.get_payload(decode=True)
                if payload:
                    attachment_list.append({
                        "filename": part.get_filename() or "unnamed",
                        "content_type": ctype,
                        "content": payload,
                    })
            elif ctype == "text/plain" and not body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text = payload.decode("utf-8", errors="replace")
            elif ctype == "text/html" and not body_html:
                payload = part.get_payload(decode=True)
                if payload:
                    body_html = payload.decode("utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                body_html = text
            else:
                body_text = text

    raw_source = raw_bytes.decode("utf-8", errors="replace")

    async with pool.acquire() as conn:
        email_id = await conn.fetchval("""
            INSERT INTO emails (message_id, direction, envelope_from, envelope_to,
                from_header, to_header, cc_header, reply_to_header, subject,
                body_text, body_html, raw_source, has_attachments,
                in_reply_to, references_hdr)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            RETURNING id
        """, message_id, direction, envelope_from or "", envelope_to or "",
            from_header, to_header, cc_header, reply_to,
            subject, body_text, body_html, raw_source, has_attachments,
            in_reply_to, references)

        for att in attachment_list:
            await conn.execute("""
                INSERT INTO attachments (email_id, filename, content_type, size_bytes, content)
                VALUES ($1, $2, $3, $4, $5)
            """, email_id, att["filename"], att["content_type"],
                len(att["content"]), att["content"])

    log.info(f"Stored {direction} email id={email_id} from={from_header} to={to_header} subj={subject[:60]}")
    return email_id


# ---------------------------------------------------------------------------
# MX Resolution & Direct SMTP Delivery
# ---------------------------------------------------------------------------
def resolve_mx(domain: str) -> str:
    """Resolve MX record for a domain, return lowest-priority host."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = sorted(answers, key=lambda r: r.preference)
        return str(mx_records[0].exchange).rstrip(".")
    except Exception:
        return domain


def _extract_email(addr: str) -> str:
    """Extract bare email from 'Name <email>' or plain 'email' format."""
    _, parsed = email.utils.parseaddr(addr)
    return parsed or addr


def smtp_deliver(from_addr: str, to_addrs: list, raw_bytes: bytes,
                 retries: int = 3, backoff: float = 30):
    """Deliver email directly to the recipient's MX server on port 25.
    Retries on 4xx temporary failures with exponential backoff."""
    sender = _extract_email(from_addr)
    for to_addr in to_addrs:
        bare = _extract_email(to_addr)
        domain = bare.split("@")[1]
        mx_host = resolve_mx(domain)
        last_err = None
        for attempt in range(retries):
            log.info(f"Delivering to {bare} via MX {mx_host} (attempt {attempt+1}/{retries})")
            try:
                with smtplib.SMTP(mx_host, 25, timeout=30) as smtp:
                    smtp.ehlo(HOSTNAME)
                    try:
                        smtp.starttls()
                        smtp.ehlo(HOSTNAME)
                    except Exception:
                        pass
                    smtp.sendmail(sender, [bare], raw_bytes)
                log.info(f"Delivered to {bare}")
                last_err = None
                break
            except smtplib.SMTPRecipientsRefused as e:
                code = list(e.recipients.values())[0][0] if e.recipients else 500
                last_err = e
                if 400 <= code < 500 and attempt < retries - 1:
                    wait = backoff * (2 ** attempt)
                    log.warning(f"Temp failure {code} for {bare}, retrying in {wait}s")
                    time.sleep(wait)
                    continue
                break
            except smtplib.SMTPResponseException as e:
                last_err = e
                if 400 <= e.smtp_code < 500 and attempt < retries - 1:
                    wait = backoff * (2 ** attempt)
                    log.warning(f"Temp failure {e.smtp_code} for {bare}, retrying in {wait}s")
                    time.sleep(wait)
                    continue
                break
            except Exception as e:
                last_err = e
                break
        if last_err:
            log.error(f"Failed to deliver to {bare}: {last_err}")
            raise last_err


def dkim_sign_message(raw_bytes: bytes) -> bytes:
    """Sign message with DKIM. Returns signed message bytes."""
    try:
        key_data = DKIM_KEY_PATH.read_bytes()
        sig = dkim.sign(
            message=raw_bytes,
            selector=DKIM_SELECTOR.encode(),
            domain=DOMAIN.encode(),
            privkey=key_data,
            include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
        )
        return sig + raw_bytes
    except Exception as e:
        log.warning(f"DKIM signing failed: {e}")
        return raw_bytes


# ---------------------------------------------------------------------------
# Email Forwarding
# ---------------------------------------------------------------------------
async def forward_to_gmail(email_id: int, raw_bytes: bytes):
    """Forward received email to Gmail by direct SMTP delivery."""
    try:
        # Rewrite envelope-from to our domain so SPF passes
        envelope_from = f"forward@{DOMAIN}"
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, smtp_deliver, envelope_from, [FORWARD_TO], raw_bytes)
        async with pool.acquire() as conn:
            await conn.execute("UPDATE emails SET forwarded=TRUE WHERE id=$1", email_id)
        log.info(f"Forwarded email {email_id} to {FORWARD_TO}")
    except Exception as e:
        log.error(f"Forward failed for email {email_id}: {e}")
        async with pool.acquire() as conn:
            await conn.execute("UPDATE emails SET forward_error=$1 WHERE id=$2", str(e), email_id)


# ---------------------------------------------------------------------------
# SMTP Receiver (aiosmtpd)
# ---------------------------------------------------------------------------
# aiosmtpd Controller runs in a separate thread with its own event loop.
# We need to bridge calls back to the main FastAPI event loop for DB access.
main_loop: Optional[asyncio.AbstractEventLoop] = None


class CatchallHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        domain = address.split("@", 1)[-1].lower() if "@" in address else ""
        if domain == DOMAIN.lower() or domain in RELAY_DOMAINS:
            envelope.rcpt_tos.append(address)
            return "250 OK"
        return f"550 We do not relay for {address}"

    async def handle_DATA(self, server, session, envelope):
        try:
            raw = envelope.content if isinstance(envelope.content, bytes) else envelope.content.encode()
            # Group recipients by tenant: local-store vs relay-to-host
            local_rcpts = []
            relay_groups = {}  # (host,port) -> [rcpts]
            for rcpt in envelope.rcpt_tos:
                d = rcpt.split("@", 1)[-1].lower()
                if d in RELAY_DOMAINS:
                    relay_groups.setdefault(RELAY_DOMAINS[d], []).append(rcpt)
                else:
                    local_rcpts.append(rcpt)

            # Relay non-local domains via SMTP to their internal listener
            for (host, port), rcpts in relay_groups.items():
                try:
                    with smtplib.SMTP(host, port, timeout=15) as s:
                        s.ehlo(HOSTNAME)
                        s.sendmail(envelope.mail_from, rcpts, raw)
                    log.info(f"Relayed inbound to {host}:{port} for {rcpts}")
                except Exception as e:
                    log.error(f"Relay to {host}:{port} failed: {e}")
                    return "451 Temporary error, please retry"

            # Locally store mail for our own domain
            if local_rcpts:
                future = asyncio.run_coroutine_threadsafe(
                    _process_inbound(raw, envelope.mail_from, local_rcpts[0],
                        peer_ip=(session.peer[0] if getattr(session, "peer", None) else None)), main_loop
                )
                future.result(timeout=30)

            return "250 Message accepted for delivery"
        except Exception as e:
            log.error(f"handle_DATA error: {e}\n{traceback.format_exc()}")
            return "451 Temporary error, please retry"


async def _process_inbound(raw: bytes, mail_from: str, to_addr: str, peer_ip: str = None):
    """Process inbound email on the main event loop."""
    _spam = None
    if SPAM_FILTER_ENABLED:
        try:
            _loop = asyncio.get_running_loop()
            _spam = await _loop.run_in_executor(None, lambda: _spamfilter.score_message(
                raw, mail_from=mail_from or "", peer_ip=peer_ip,
                our_domains=SPAM_OWN_DOMAINS, allow_domains=SPAM_ALLOW_DOMAINS,
                block_domains=SPAM_BLOCK_DOMAINS, threshold=SPAM_THRESHOLD,
                use_dnsbl=SPAM_USE_DNSBL))
        except Exception as _e:
            log.warning(f"spam scoring failed (fail-open): {_e}")
    _is_spam = bool(_spam and _spam.is_spam)
    email_id = await store_email("inbound", mail_from, to_addr, raw)
    if _is_spam:
        try:
            async with pool.acquire() as _c:
                await _c.execute("UPDATE emails SET is_spam=TRUE, spam_score=$1, spam_reasons=$2 WHERE id=$3",
                                 float(_spam.score), (",".join(_spam.reasons))[:500], email_id)
        except Exception as _e:
            log.warning(f"spam flag update failed: {_e}")
        log.info(f"SPAM inbound from={mail_from} ip={peer_ip} score={_spam.score} reasons={_spam.reasons} — stored, NOT forwarding")
    else:
        asyncio.create_task(forward_to_gmail(email_id, raw))


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI(root_path=ROOT_PATH, docs_url=None, redoc_url=None)


# --- Auth ---
def _make_token(username: str) -> str:
    sig = hmac.new(AUTH_SECRET.encode(), username.encode(), hashlib.sha256).hexdigest()[:24]
    return f"{username}:{sig}"


def _check_token(token: str) -> bool:
    if not token or ":" not in token:
        return False
    username, sig = token.split(":", 1)
    expected = hmac.new(AUTH_SECRET.encode(), username.encode(), hashlib.sha256).hexdigest()[:24]
    return hmac.compare_digest(sig, expected)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if not AUTH_PASS:
        return await call_next(request)
    path = request.url.path
    if path in ("/login", "/login/", "/api/contact"):
        return await call_next(request)
    token = request.cookies.get(COOKIE_NAME)
    if not _check_token(token):
        if path.startswith("/api/"):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return HTMLResponse(LOGIN_PAGE)
    return await call_next(request)


@app.post("/login")
async def do_login(request: Request):
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")
    if username == AUTH_USER and password == AUTH_PASS:
        token = _make_token(username)
        rp = request.scope.get("root_path", "")
        resp = RedirectResponse(url=rp + "/", status_code=303)
        resp.set_cookie(COOKIE_NAME, token, max_age=86400 * 30,
                        httponly=True, samesite="lax")
        return resp
    rp = request.scope.get("root_path", "")
    return RedirectResponse(url=rp + "/login?err=1", status_code=303)


# --- API Routes ---
@app.get("/api/emails")
async def list_emails(request: Request, folder: str = "inbox", page: int = 1,
                      per_page: int = 50, search: str = ""):
    direction = "inbound" if folder == "inbox" else "outbound" if folder == "sent" else None
    offset = (page - 1) * per_page

    async with pool.acquire() as conn:
        if search:
            search_param = f"%{search}%"
            if direction:
                search_filter = "AND (subject ILIKE $4 OR from_header ILIKE $4 OR to_header ILIKE $4)"
                rows = await conn.fetch(f"""
                    SELECT id, direction, from_header, to_header, subject, body_text,
                           is_read, is_starred, has_attachments, created_at, envelope_to
                    FROM emails WHERE direction=$1 {search_filter}
                    ORDER BY created_at DESC LIMIT $2 OFFSET $3
                """, direction, per_page, offset, search_param)
                total = await conn.fetchval("""
                    SELECT COUNT(*) FROM emails WHERE direction=$1
                    AND (subject ILIKE $2 OR from_header ILIKE $2 OR to_header ILIKE $2)
                """, direction, search_param)
            else:
                search_filter = "WHERE (subject ILIKE $3 OR from_header ILIKE $3 OR to_header ILIKE $3)"
                rows = await conn.fetch(f"""
                    SELECT id, direction, from_header, to_header, subject, body_text,
                           is_read, is_starred, has_attachments, created_at, envelope_to
                    FROM emails {search_filter}
                    ORDER BY created_at DESC LIMIT $1 OFFSET $2
                """, per_page, offset, search_param)
                total = await conn.fetchval("""
                    SELECT COUNT(*) FROM emails
                    WHERE (subject ILIKE $1 OR from_header ILIKE $1 OR to_header ILIKE $1)
                """, search_param)
        else:
            if direction:
                rows = await conn.fetch("""
                    SELECT id, direction, from_header, to_header, subject, body_text,
                           is_read, is_starred, has_attachments, created_at, envelope_to
                    FROM emails WHERE direction=$1
                    ORDER BY created_at DESC LIMIT $2 OFFSET $3
                """, direction, per_page, offset)
                total = await conn.fetchval(
                    "SELECT COUNT(*) FROM emails WHERE direction=$1", direction)
            else:
                rows = await conn.fetch("""
                    SELECT id, direction, from_header, to_header, subject, body_text,
                           is_read, is_starred, has_attachments, created_at, envelope_to
                    FROM emails ORDER BY created_at DESC LIMIT $1 OFFSET $2
                """, per_page, offset)
                total = await conn.fetchval("SELECT COUNT(*) FROM emails")

        unread = await conn.fetchval(
            "SELECT COUNT(*) FROM emails WHERE direction='inbound' AND NOT is_read")

    return {
        "emails": [
            {
                "id": r["id"],
                "direction": r["direction"],
                "from": r["from_header"],
                "to": r["to_header"],
                "subject": r["subject"],
                "preview": (r["body_text"] or "")[:150],
                "is_read": r["is_read"],
                "is_starred": r["is_starred"],
                "has_attachments": r["has_attachments"],
                "date": r["created_at"].isoformat(),
                "envelope_to": r["envelope_to"],
            }
            for r in rows
        ],
        "total": total,
        "unread": unread,
        "page": page,
        "per_page": per_page,
    }


@app.get("/api/emails/{email_id}")
async def get_email(email_id: int):
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM emails WHERE id=$1", email_id)
        if not row:
            return JSONResponse({"error": "not found"}, status_code=404)
        # Mark as read
        if not row["is_read"]:
            await conn.execute("UPDATE emails SET is_read=TRUE WHERE id=$1", email_id)
        # Get attachments
        atts = await conn.fetch(
            "SELECT id, filename, content_type, size_bytes FROM attachments WHERE email_id=$1",
            email_id)

    return {
        "id": row["id"],
        "message_id": row["message_id"],
        "direction": row["direction"],
        "from": row["from_header"],
        "to": row["to_header"],
        "cc": row["cc_header"],
        "reply_to": row["reply_to_header"],
        "subject": row["subject"],
        "body_text": row["body_text"],
        "body_html": row["body_html"],
        "is_read": True,
        "is_starred": row["is_starred"],
        "has_attachments": row["has_attachments"],
        "forwarded": row["forwarded"],
        "forward_error": row["forward_error"],
        "in_reply_to": row["in_reply_to"],
        "references": row["references_hdr"],
        "date": row["created_at"].isoformat(),
        "envelope_from": row["envelope_from"],
        "envelope_to": row["envelope_to"],
        "attachments": [
            {"id": a["id"], "filename": a["filename"],
             "content_type": a["content_type"], "size": a["size_bytes"]}
            for a in atts
        ],
    }


@app.post("/api/emails/{email_id}/read")
async def mark_read(email_id: int):
    async with pool.acquire() as conn:
        await conn.execute("UPDATE emails SET is_read=TRUE WHERE id=$1", email_id)
    return {"ok": True}


@app.post("/api/emails/{email_id}/star")
async def toggle_star(email_id: int):
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE emails SET is_starred = NOT is_starred WHERE id=$1", email_id)
        row = await conn.fetchrow("SELECT is_starred FROM emails WHERE id=$1", email_id)
    return {"ok": True, "is_starred": row["is_starred"] if row else False}


@app.get("/api/attachment/{att_id}")
async def download_attachment(att_id: int):
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT filename, content_type, content FROM attachments WHERE id=$1", att_id)
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    return Response(
        content=bytes(row["content"]),
        media_type=row["content_type"],
        headers={"Content-Disposition": f'attachment; filename="{row["filename"]}"'},
    )


class SendRequest(BaseModel):
    from_addr: str
    to_addr: str
    subject: str
    body_text: str
    body_html: str = ""
    in_reply_to: str = ""
    references: str = ""
    reply_to: str = ""
    list_unsubscribe: str = ""


@app.post("/api/send")
async def send_email_route(req: SendRequest):
    """Compose and send an email."""
    if not req.from_addr.endswith(f"@{DOMAIN}"):
        return JSONResponse({"error": f"From address must be @{DOMAIN}"}, status_code=400)
    if not req.to_addr or "@" not in req.to_addr:
        return JSONResponse({"error": "Invalid To address"}, status_code=400)

    # Build message
    msg = MIMEMultipart("alternative") if req.body_html else MIMEText(req.body_text)
    if req.body_html:
        msg.attach(MIMEText(req.body_text, "plain"))
        msg.attach(MIMEText(req.body_html, "html"))

    msg["From"] = req.from_addr
    msg["To"] = req.to_addr
    msg["Subject"] = req.subject
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=DOMAIN)

    if req.reply_to:
        msg["Reply-To"] = req.reply_to
    if req.list_unsubscribe:
        # Gmail recommends List-Unsubscribe on transactional/automated
        # mail.  Format: <mailto:unsub@...>, <https://...>
        msg["List-Unsubscribe"] = req.list_unsubscribe
        msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"

    if req.in_reply_to:
        msg["In-Reply-To"] = req.in_reply_to
    if req.references:
        msg["References"] = req.references

    raw = msg.as_bytes()
    raw = dkim_sign_message(raw)

    # Deliver
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, smtp_deliver, req.from_addr, [req.to_addr], raw)
    except Exception as e:
        log.error(f"Send failed: {e}")
        return JSONResponse({"error": f"Delivery failed: {e}"}, status_code=500)

    # Store as sent
    email_id = await store_email("outbound", req.from_addr, req.to_addr, raw)
    return {"ok": True, "id": email_id}


@app.get("/api/stats")
async def stats():
    async with pool.acquire() as conn:
        unread = await conn.fetchval(
            "SELECT COUNT(*) FROM emails WHERE direction='inbound' AND NOT is_read")
        total_inbox = await conn.fetchval(
            "SELECT COUNT(*) FROM emails WHERE direction='inbound'")
        total_sent = await conn.fetchval(
            "SELECT COUNT(*) FROM emails WHERE direction='outbound'")
    return {"unread": unread, "total_inbox": total_inbox, "total_sent": total_sent}


@app.delete("/api/emails/{email_id}")
async def delete_email(email_id: int):
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM emails WHERE id=$1", email_id)
    return {"ok": True}


class BulkDeleteRequest(BaseModel):
    ids: list[int]


@app.post("/api/emails/bulk-delete")
async def bulk_delete_emails(req: BulkDeleteRequest):
    if not req.ids:
        return {"ok": True, "deleted": 0}
    async with pool.acquire() as conn:
        deleted = await conn.execute(
            "DELETE FROM emails WHERE id = ANY($1::int[])", req.ids)
    count = int(deleted.split()[-1])
    return {"ok": True, "deleted": count}


# --- Public Contact Form Endpoint (no auth required) ---
class ContactRequest(BaseModel):
    name: str
    email: str
    subject: str
    message: str


@app.post("/api/contact")
async def contact_form(req: ContactRequest):
    """Public endpoint for website contact form. Sends email to info@nebula-bio.com."""
    # Validate
    if not req.name or not req.email or not req.message:
        return JSONResponse({"error": "All fields are required"}, status_code=400)
    if "@" not in req.email:
        return JSONResponse({"error": "Invalid email address"}, status_code=400)
    if len(req.message) > 10000:
        return JSONResponse({"error": "Message too long"}, status_code=400)

    subj_map = {
        "collaboration": "Research Collaboration",
        "consulting": "Consulting Inquiry",
        "partnership": "Partnership Inquiry",
        "general": "General Inquiry",
    }
    subject_line = f"[Website] {subj_map.get(req.subject, req.subject)} from {req.name}"

    body = f"Name: {req.name}\nEmail: {req.email}\nSubject: {subj_map.get(req.subject, req.subject)}\n\n{req.message}"

    # Build the email
    msg = MIMEText(body)
    msg["From"] = f"{req.name} <contact-form@{DOMAIN}>"
    msg["To"] = f"info@{DOMAIN}"
    msg["Reply-To"] = req.email
    msg["Subject"] = subject_line
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=DOMAIN)

    raw = msg.as_bytes()

    # Store in our inbox
    try:
        await store_email("inbound", f"contact-form@{DOMAIN}", f"info@{DOMAIN}", raw)
    except Exception as e:
        log.error(f"Contact form store error: {e}")

    # Forward to Gmail
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, smtp_deliver, f"contact-form@{DOMAIN}", [FORWARD_TO], dkim_sign_message(raw))
    except Exception as e:
        log.error(f"Contact form forward error: {e}")

    return {"ok": True}


# --- Serve UI ---
@app.get("/login")
async def login_page():
    return HTMLResponse(LOGIN_PAGE)


@app.get("/")
async def index():
    return HTMLResponse(MAIN_PAGE)


# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------
smtp_controller = None


@app.on_event("startup")
async def startup():
    global smtp_controller, main_loop
    main_loop = asyncio.get_event_loop()
    await init_db()

    handler = CatchallHandler()
    smtp_controller = Controller(
        handler,
        hostname=SMTP_HOST,
        port=SMTP_PORT,
        ident=f"{HOSTNAME} {BRAND}",
        data_size_limit=10 * 1024 * 1024,  # 10MB
    )
    smtp_controller.start()
    log.info(f"SMTP server listening on port {SMTP_PORT}")
    log.info(f"Web UI on port {PORT} at {ROOT_PATH}")


@app.on_event("shutdown")
async def shutdown():
    if smtp_controller:
        smtp_controller.stop()
    if pool:
        await pool.close()


# ---------------------------------------------------------------------------
# HTML Templates (embedded)
# ---------------------------------------------------------------------------
LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>__BRAND__ — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:#0a0c10;color:#e4e8f1;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:#12151c;border:1px solid #1e2330;border-radius:14px;padding:2rem;width:360px}
.box h2{font-size:1.3rem;margin-bottom:.5rem}
.box p{color:#8892a8;font-size:.85rem;margin-bottom:1.5rem}
.field{margin-bottom:1rem}
.field label{display:block;font-size:.8rem;color:#8892a8;margin-bottom:.35rem}
.field input{width:100%;background:#0a0c10;border:1px solid #1e2330;border-radius:8px;color:#e4e8f1;padding:.65rem .9rem;font-size:.9rem;outline:none}
.field input:focus{border-color:#6c5ce7}
.err{color:#ff6b6b;font-size:.82rem;margin-bottom:.75rem;display:none}
.btn{width:100%;background:#6c5ce7;color:#fff;border:none;padding:.7rem;border-radius:8px;cursor:pointer;font-size:.92rem;font-weight:600}
.btn:hover{background:#5b4bd6}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
</head><body>
<form class="box" method="POST" action="login">
  <h2>__BRAND__</h2>
  <p>Sign in to access your inbox.</p>
  <div class="err" id="err">Invalid credentials.</div>
  <div class="field"><label>Username</label><input name="username" autocomplete="username" autofocus></div>
  <div class="field"><label>Password</label><input name="password" type="password" autocomplete="current-password"></div>
  <button class="btn" type="submit">Sign In</button>
</form>
<script>if(location.search.includes('err=1'))document.getElementById('err').style.display='block'</script>
</body></html>"""

MAIN_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>__BRAND__</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0c10;--bg2:#12151c;--bg3:#181c26;--text:#e4e8f1;--muted:#8892a8;
  --accent:#6c5ce7;--accent-l:#a29bfe;--teal:#00cec9;--border:#1e2330;
  --red:#ff6b6b;--green:#51cf66;
}
html,body{height:100%;font-family:'Inter',sans-serif;background:var(--bg);color:var(--text)}
a{color:var(--accent-l);text-decoration:none}

/* Layout */
.app{display:flex;height:100vh;overflow:hidden}
.sidebar{width:220px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0}
.sidebar-header{padding:1.2rem 1rem .8rem;border-bottom:1px solid var(--border)}
.sidebar-header h1{font-size:1.1rem;font-weight:700}
.sidebar-header h1 span{color:var(--accent-l)}
.folder-list{flex:1;padding:.5rem 0}
.folder{display:flex;align-items:center;gap:.6rem;padding:.55rem 1rem;cursor:pointer;font-size:.88rem;color:var(--muted);transition:all .15s;border-left:3px solid transparent}
.folder:hover{background:var(--bg3);color:var(--text)}
.folder.active{color:var(--text);border-left-color:var(--accent);background:rgba(108,92,231,.08)}
.folder .badge{margin-left:auto;background:var(--accent);color:#fff;font-size:.7rem;padding:.1rem .45rem;border-radius:10px;font-weight:600;min-width:20px;text-align:center}
.sidebar-footer{padding:.8rem 1rem;border-top:1px solid var(--border)}
.btn-compose{width:100%;background:var(--accent);color:#fff;border:none;padding:.6rem;border-radius:8px;font-size:.88rem;font-weight:600;cursor:pointer;transition:background .15s}
.btn-compose:hover{background:#5b4bd6}

/* Main area */
.main{flex:1;display:flex;flex-direction:column;min-width:0}
.toolbar{display:flex;align-items:center;gap:.75rem;padding:.6rem 1rem;border-bottom:1px solid var(--border);background:var(--bg2)}
.search-box{flex:1;max-width:400px;position:relative}
.search-box input{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:.5rem .75rem .5rem 2rem;font-size:.85rem;outline:none}
.search-box input:focus{border-color:var(--accent)}
.search-box svg{position:absolute;left:.6rem;top:50%;transform:translateY(-50%);color:var(--muted)}
.toolbar .refresh-btn{background:none;border:1px solid var(--border);color:var(--muted);padding:.4rem .6rem;border-radius:6px;cursor:pointer;font-size:.8rem;display:flex;align-items:center;gap:.3rem}
.toolbar .refresh-btn:hover{border-color:var(--accent);color:var(--text)}

/* Email list */
.email-list{flex:1;overflow-y:auto}
.email-row{display:flex;align-items:center;gap:.75rem;padding:.7rem 1rem;border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s}
.email-row:hover{background:var(--bg3)}
.email-row.unread{background:rgba(108,92,231,.04)}
.email-row.unread .email-from,.email-row.unread .email-subject{font-weight:600}
.email-row.active{background:rgba(108,92,231,.1)}
.email-row.selected{background:rgba(108,92,231,.12)}
.row-check{width:16px;height:16px;accent-color:var(--accent);cursor:pointer;flex-shrink:0;margin:0}
.unread-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.unread-dot.on{background:var(--accent)}
/* Bulk action bar */
.bulk-bar{display:none;align-items:center;gap:.75rem;padding:.45rem 1rem;border-bottom:1px solid var(--border);background:var(--bg3);font-size:.84rem}
.bulk-bar.show{display:flex}
.bulk-bar .bulk-count{color:var(--accent-l);font-weight:600}
.bulk-bar button{background:none;border:1px solid var(--border);color:var(--text);padding:.3rem .7rem;border-radius:6px;cursor:pointer;font-size:.8rem}
.bulk-bar button:hover{border-color:var(--accent);color:var(--accent-l)}
.bulk-bar .bulk-delete{color:var(--red)}
.bulk-bar .bulk-delete:hover{border-color:var(--red);color:var(--red)}
.email-from{font-size:.85rem;width:180px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.email-subject{font-size:.85rem;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.email-preview{color:var(--muted);font-weight:400!important}
.email-date{font-size:.78rem;color:var(--muted);flex-shrink:0;white-space:nowrap}
.email-attachment{color:var(--muted);flex-shrink:0;font-size:.8rem}

.empty-state{flex:1;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:.95rem}

/* Detail pane */
.detail-pane{display:none;flex-direction:column;width:50%;border-left:1px solid var(--border);background:var(--bg2)}
.detail-pane.open{display:flex}
.detail-header{padding:1rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:flex-start;gap:1rem}
.detail-header h2{font-size:1.1rem;font-weight:600;line-height:1.4}
.detail-meta{padding:.75rem 1rem;border-bottom:1px solid var(--border);font-size:.82rem;color:var(--muted);display:flex;flex-direction:column;gap:.25rem}
.detail-meta strong{color:var(--text);font-weight:500}
.detail-body{flex:1;overflow-y:auto;padding:1rem;min-height:0;position:relative;z-index:1}
.detail-body-text{white-space:pre-wrap;font-size:.9rem;line-height:1.65;color:var(--text)}
.detail-body iframe{width:100%;border:none;min-height:300px;background:#fff;border-radius:6px}
.detail-actions{padding:.75rem 1rem;border-top:1px solid var(--border);display:flex;gap:.5rem;position:relative;z-index:2}
.btn-action{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:.45rem .9rem;border-radius:6px;cursor:pointer;font-size:.82rem;font-weight:500;transition:all .15s}
.btn-action:hover{border-color:var(--accent);color:var(--accent-l)}
.btn-action.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn-action.primary:hover{background:#5b4bd6}
.btn-action.danger{color:var(--red)}
.btn-action.danger:hover{border-color:var(--red)}
.close-btn{background:none;border:none;color:var(--muted);cursor:pointer;font-size:1.3rem;padding:.2rem}
.close-btn:hover{color:var(--text)}

/* Compose modal */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border);border-radius:14px;width:640px;max-width:95vw;max-height:90vh;display:flex;flex-direction:column}
.modal-header{display:flex;align-items:center;justify-content:space-between;padding:1rem 1.2rem;border-bottom:1px solid var(--border)}
.modal-header h3{font-size:1rem;font-weight:600}
.modal-body{flex:1;overflow-y:auto;padding:1rem 1.2rem}
.modal-body .field{margin-bottom:.8rem}
.modal-body .field label{display:block;font-size:.78rem;color:var(--muted);margin-bottom:.3rem;font-weight:500}
.modal-body .field input,.modal-body .field textarea{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:.5rem .7rem;font-size:.88rem;outline:none;font-family:inherit}
.modal-body .field input:focus,.modal-body .field textarea:focus{border-color:var(--accent)}
.modal-body .field textarea{min-height:180px;resize:vertical;line-height:1.6}
.modal-footer{padding:.75rem 1.2rem;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:.5rem}

/* Status bar */
.status-bar{padding:.3rem 1rem;border-top:1px solid var(--border);font-size:.75rem;color:var(--muted);background:var(--bg2);display:flex;justify-content:space-between}

/* Pagination */
.pagination{display:flex;align-items:center;justify-content:center;gap:.5rem;padding:.6rem;border-top:1px solid var(--border)}
.pagination button{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:.3rem .7rem;border-radius:6px;cursor:pointer;font-size:.8rem}
.pagination button:hover{border-color:var(--accent)}
.pagination button:disabled{opacity:.4;cursor:default}
.pagination span{font-size:.8rem;color:var(--muted)}

/* Loading */
.loading{display:flex;align-items:center;justify-content:center;padding:2rem;color:var(--muted)}
.spinner{width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;margin-right:.5rem}
@keyframes spin{to{transform:rotate(360deg)}}

/* Toast */
.toast{position:fixed;bottom:1.5rem;right:1.5rem;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:.6rem 1rem;font-size:.85rem;z-index:2000;opacity:0;transform:translateY(10px);transition:all .3s;pointer-events:none}
.toast.show{opacity:1;transform:translateY(0);pointer-events:auto}
.toast.error{border-color:var(--red);color:var(--red)}
.toast.success{border-color:var(--green);color:var(--green)}

/* Responsive */
@media(max-width:768px){
  .sidebar{width:60px}.sidebar-header h1 span,.folder span,.folder .badge{display:none}
  .detail-pane.open{position:absolute;inset:0;width:100%;z-index:10}
  .email-from{width:100px}
}
</style>
</head>
<body>
<div class="app">
  <div class="sidebar">
    <div class="sidebar-header"><h1><span>__BRAND_FIRST__</span> __BRAND_REST__</h1></div>
    <div class="folder-list">
      <div class="folder active" data-folder="inbox" onclick="switchFolder('inbox')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-6l-2 3H10l-2-3H2"/><path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z"/></svg>
        <span>Inbox</span>
        <span class="badge" id="unreadBadge" style="display:none">0</span>
      </div>
      <div class="folder" data-folder="sent" onclick="switchFolder('sent')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        <span>Sent</span>
      </div>
      <div class="folder" data-folder="all" onclick="switchFolder('all')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
        <span>All Mail</span>
      </div>
    </div>
    <div class="sidebar-footer">
      <button class="btn-compose" onclick="openCompose()">Compose</button>
    </div>
  </div>

  <div class="main">
    <div class="toolbar">
      <div class="search-box">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input type="text" id="searchInput" placeholder="Search emails..." onkeydown="if(event.key==='Enter'){currentPage=1;loadEmails()}">
      </div>
      <button class="refresh-btn" onclick="loadEmails()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
        Refresh
      </button>
    </div>

    <div class="bulk-bar" id="bulkBar">
      <input type="checkbox" class="row-check" id="selectAll" onchange="toggleSelectAll(this.checked)" title="Select all">
      <span class="bulk-count" id="bulkCount">0 selected</span>
      <button class="bulk-delete" onclick="bulkDelete()">Delete</button>
      <button onclick="clearSelection()">Cancel</button>
    </div>
    <div id="emailList" class="email-list"></div>
    <div id="pagination" class="pagination" style="display:none"></div>
    <div class="status-bar">
      <span id="statusText">Loading...</span>
      <span id="statusTime"></span>
    </div>
  </div>

  <div class="detail-pane" id="detailPane">
    <div class="detail-header">
      <h2 id="detailSubject"></h2>
      <button class="close-btn" onclick="closeDetail()">&times;</button>
    </div>
    <div class="detail-meta" id="detailMeta"></div>
    <div class="detail-body" id="detailBody"></div>
    <div class="detail-actions" id="detailActions"></div>
  </div>
</div>

<!-- Compose Modal -->
<div class="modal-overlay" id="composeModal">
  <div class="modal">
    <div class="modal-header">
      <h3 id="composeTitle">New Message</h3>
      <button class="close-btn" onclick="closeCompose()">&times;</button>
    </div>
    <div class="modal-body">
      <div class="field"><label>From</label><input id="compFrom" placeholder="__DEFAULT_FROM__" value="__DEFAULT_FROM__"></div>
      <div class="field"><label>To</label><input id="compTo" placeholder="recipient@example.com"></div>
      <div class="field"><label>Subject</label><input id="compSubject" placeholder="Subject"></div>
      <div class="field"><label>Message</label><textarea id="compBody" placeholder="Write your message..."></textarea></div>
    </div>
    <div class="modal-footer">
      <button class="btn-action" onclick="closeCompose()">Cancel</button>
      <button class="btn-action primary" onclick="sendEmail()" id="sendBtn">Send</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const API = (location.pathname.replace(/\/+$/, '') || '');  // auto-detect base path
let currentFolder = 'inbox';
let currentPage = 1;
let selectedId = null;
let replyMeta = {};  // in_reply_to, references for reply
let selectedIds = new Set();

function onRowClick(e, id) {
  if (e.target.classList.contains('row-check')) return;
  openEmail(id);
}

function onCheckClick(e, id) {
  e.stopPropagation();
  if (e.target.checked) selectedIds.add(id);
  else selectedIds.delete(id);
  e.target.closest('.email-row').classList.toggle('selected', e.target.checked);
  updateBulkBar();
}

function toggleSelectAll(checked) {
  document.querySelectorAll('.row-check[data-eid]').forEach(cb => {
    cb.checked = checked;
    const id = parseInt(cb.dataset.eid);
    if (checked) selectedIds.add(id); else selectedIds.delete(id);
    cb.closest('.email-row').classList.toggle('selected', checked);
  });
  updateBulkBar();
}

function updateBulkBar() {
  const bar = document.getElementById('bulkBar');
  const n = selectedIds.size;
  if (n > 0) {
    bar.classList.add('show');
    document.getElementById('bulkCount').textContent = n + ' selected';
  } else {
    bar.classList.remove('show');
    document.getElementById('selectAll').checked = false;
  }
}

function clearSelection() {
  selectedIds.clear();
  document.querySelectorAll('.row-check').forEach(cb => { cb.checked = false; });
  document.querySelectorAll('.email-row.selected').forEach(el => el.classList.remove('selected'));
  updateBulkBar();
}

async function bulkDelete() {
  const ids = [...selectedIds];
  if (!ids.length) return;
  if (!confirm(`Delete ${ids.length} email${ids.length>1?'s':''}?`)) return;
  try {
    const r = await fetch(API + '/api/emails/bulk-delete', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ids})
    });
    const data = await r.json();
    if (data.ok) {
      toast(`Deleted ${data.deleted} email${data.deleted!==1?'s':''}`);
      if (selectedIds.has(selectedId)) closeDetail();
      selectedIds.clear();
      loadEmails();
    } else toast(data.error || 'Failed to delete', 'error');
  } catch(e) { toast('Network error', 'error'); }
}

function toast(msg, type='success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + type;
  setTimeout(() => t.className = 'toast', 3000);
}

function fmtDate(iso) {
  const d = new Date(iso);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  if (now - d < 7*86400000) return d.toLocaleDateString([], {weekday:'short'});
  return d.toLocaleDateString([], {month:'short',day:'numeric'});
}

function extractName(header) {
  if (!header) return '';
  const m = header.match(/^"?([^"<]+)"?\s*</);
  if (m) return m[1].trim();
  return header.split('@')[0];
}

function escHtml(s) { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

async function loadEmails() {
  const search = document.getElementById('searchInput').value;
  const params = new URLSearchParams({folder:currentFolder, page:currentPage, per_page:50});
  if (search) params.set('search', search);

  const list = document.getElementById('emailList');
  list.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';

  try {
    const r = await fetch(API + '/api/emails?' + params);
    if (r.status === 401) { location.reload(); return; }
    const data = await r.json();

    // Update badge
    const badge = document.getElementById('unreadBadge');
    if (data.unread > 0) { badge.textContent = data.unread; badge.style.display = ''; }
    else { badge.style.display = 'none'; }

    if (data.emails.length === 0) {
      list.innerHTML = '<div class="empty-state">No emails found</div>';
    } else {
      list.innerHTML = data.emails.map(e => `
        <div class="email-row ${e.is_read?'':'unread'} ${e.id===selectedId?'active':''}" data-id="${e.id}" onclick="onRowClick(event,${e.id})">
          <input type="checkbox" class="row-check" data-eid="${e.id}" onclick="onCheckClick(event,${e.id})" ${selectedIds.has(e.id)?'checked':''}>
          <div class="unread-dot ${e.is_read?'':'on'}"></div>
          <div class="email-from">${escHtml(currentFolder==='sent'?extractName(e.to):extractName(e.from))}</div>
          <div class="email-subject">
            ${escHtml(e.subject)}
            <span class="email-preview"> — ${escHtml(e.preview)}</span>
          </div>
          ${e.has_attachments?'<span class="email-attachment" title="Has attachments">&#128206;</span>':''}
          <div class="email-date">${fmtDate(e.date)}</div>
        </div>
      `).join('');
      updateBulkBar();
    }

    // Pagination
    const totalPages = Math.ceil(data.total / data.per_page);
    const pag = document.getElementById('pagination');
    if (totalPages > 1) {
      pag.style.display = 'flex';
      pag.innerHTML = `
        <button onclick="currentPage--;loadEmails()" ${currentPage<=1?'disabled':''}>Prev</button>
        <span>Page ${currentPage} of ${totalPages}</span>
        <button onclick="currentPage++;loadEmails()" ${currentPage>=totalPages?'disabled':''}>Next</button>
      `;
    } else { pag.style.display = 'none'; }

    document.getElementById('statusText').textContent =
      `${data.total} email${data.total!==1?'s':''} in ${currentFolder}`;
    document.getElementById('statusTime').textContent =
      'Last updated: ' + new Date().toLocaleTimeString();
  } catch(e) {
    list.innerHTML = '<div class="empty-state">Failed to load emails</div>';
    toast('Failed to load emails', 'error');
  }
}

function switchFolder(f) {
  currentFolder = f;
  currentPage = 1;
  selectedId = null;
  selectedIds.clear();
  closeDetail();
  document.querySelectorAll('.folder').forEach(el => el.classList.toggle('active', el.dataset.folder===f));
  loadEmails();
}

async function openEmail(id) {
  selectedId = id;
  document.querySelectorAll('.email-row').forEach(el => el.classList.remove('active'));
  event.currentTarget.classList.add('active');
  event.currentTarget.classList.remove('unread');
  const dot = event.currentTarget.querySelector('.unread-dot');
  if (dot) dot.classList.remove('on');

  const pane = document.getElementById('detailPane');
  pane.classList.add('open');
  document.getElementById('detailBody').innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';

  try {
    const r = await fetch(API + '/api/emails/' + id);
    const e = await r.json();

    document.getElementById('detailSubject').textContent = e.subject;
    document.getElementById('detailMeta').innerHTML = `
      <div><strong>From:</strong> ${escHtml(e.from)}</div>
      <div><strong>To:</strong> ${escHtml(e.to)}</div>
      ${e.cc?`<div><strong>Cc:</strong> ${escHtml(e.cc)}</div>`:''}
      <div><strong>Date:</strong> ${new Date(e.date).toLocaleString()}</div>
      ${e.envelope_to&&e.direction==='inbound'?`<div><strong>Delivered to:</strong> ${escHtml(e.envelope_to)}</div>`:''}
      ${e.forwarded?'<div style="color:var(--green)">Forwarded to Gmail</div>':''}
      ${e.forward_error?`<div style="color:var(--red)">Forward error: ${escHtml(e.forward_error)}</div>`:''}
    `;

    if (e.body_html) {
      const iframe = document.createElement('iframe');
      iframe.sandbox = 'allow-same-origin';
      iframe.style.cssText = 'width:100%;border:none;min-height:300px;background:#fff;border-radius:6px';
      document.getElementById('detailBody').innerHTML = '';
      document.getElementById('detailBody').appendChild(iframe);
      iframe.contentDocument.open();
      iframe.contentDocument.write(e.body_html);
      iframe.contentDocument.close();
      // Auto-resize iframe
      setTimeout(() => {
        try { iframe.style.height = iframe.contentDocument.body.scrollHeight + 20 + 'px'; } catch(x){}
      }, 200);
    } else {
      document.getElementById('detailBody').innerHTML =
        `<div class="detail-body-text">${escHtml(e.body_text||'(empty)')}</div>`;
    }

    // Attachments
    let attHtml = '';
    if (e.attachments && e.attachments.length) {
      attHtml = e.attachments.map(a =>
        `<a href="${API}/api/attachment/${a.id}" class="btn-action" style="text-decoration:none" download="${escHtml(a.filename)}">
          &#128206; ${escHtml(a.filename)} (${(a.size/1024).toFixed(1)}KB)
        </a>`
      ).join(' ');
    }

    // Actions — store reply data in a variable to avoid inline JSON escaping issues
    const replyFrom = e.direction==='inbound' ? (e.envelope_to || e.to) : e.from;
    const replyTo = e.direction==='inbound' ? e.from : e.to;
    window._replyData = {
      from: replyFrom,
      to: replyTo,
      subject: e.subject,
      in_reply_to: e.message_id||"",
      references: ((e.references||"")+" "+(e.message_id||"")).trim(),
      body_text: e.body_text||""
    };
    document.getElementById('detailActions').innerHTML = `
      ${attHtml}
      <div style="flex:1"></div>
      <button class="btn-action primary" onclick="openReply(window._replyData)">Reply</button>
      <button class="btn-action danger" onclick="deleteEmail(${e.id})">Delete</button>
    `;

    // Refresh unread count
    const sr = await fetch(API + '/api/stats');
    const stats = await sr.json();
    const badge = document.getElementById('unreadBadge');
    if (stats.unread > 0) { badge.textContent = stats.unread; badge.style.display = ''; }
    else { badge.style.display = 'none'; }

  } catch(e) {
    document.getElementById('detailBody').innerHTML = '<div class="empty-state">Failed to load email</div>';
  }
}

function closeDetail() {
  document.getElementById('detailPane').classList.remove('open');
  selectedId = null;
}

function openCompose() {
  replyMeta = {};
  document.getElementById('composeTitle').textContent = 'New Message';
  document.getElementById('compFrom').value = '__DEFAULT_FROM__';
  document.getElementById('compTo').value = '';
  document.getElementById('compSubject').value = '';
  document.getElementById('compBody').value = '';
  document.getElementById('composeModal').classList.add('open');
  document.getElementById('compTo').focus();
}

function openReply(meta) {
  replyMeta = meta;
  document.getElementById('composeTitle').textContent = 'Reply';
  // Extract just the email address from the from field
  let fromAddr = meta.from;
  const emailMatch = fromAddr.match(/<([^>]+)>/);
  if (emailMatch) fromAddr = emailMatch[1];
  if (!fromAddr.includes('@')) fromAddr = '__DEFAULT_FROM__';
  document.getElementById('compFrom').value = fromAddr;
  document.getElementById('compTo').value = meta.to;
  document.getElementById('compSubject').value = meta.subject.startsWith('Re:')?meta.subject:'Re: '+meta.subject;
  document.getElementById('compBody').value = '\n\n--- Original Message ---\n' + (meta.body_text||'').substring(0,2000);
  document.getElementById('composeModal').classList.add('open');
  document.getElementById('compBody').focus();
  document.getElementById('compBody').setSelectionRange(0,0);
}

function closeCompose() {
  document.getElementById('composeModal').classList.remove('open');
}

async function sendEmail() {
  const btn = document.getElementById('sendBtn');
  btn.disabled = true;
  btn.textContent = 'Sending...';

  const payload = {
    from_addr: document.getElementById('compFrom').value.trim(),
    to_addr: document.getElementById('compTo').value.trim(),
    subject: document.getElementById('compSubject').value.trim(),
    body_text: document.getElementById('compBody').value,
    in_reply_to: replyMeta.in_reply_to || '',
    references: replyMeta.references || '',
  };

  try {
    const r = await fetch(API + '/api/send', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const data = await r.json();
    if (data.ok) {
      toast('Email sent successfully');
      closeCompose();
      loadEmails();
    } else {
      toast(data.error || 'Failed to send', 'error');
    }
  } catch(e) {
    toast('Network error', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send';
  }
}

async function deleteEmail(id) {
  if (!confirm('Delete this email?')) return;
  try {
    await fetch(API + '/api/emails/' + id, {method:'DELETE'});
    closeDetail();
    loadEmails();
    toast('Email deleted');
  } catch(e) {
    toast('Failed to delete', 'error');
  }
}

// Initial load + auto-refresh
loadEmails();
setInterval(loadEmails, 30000);
</script>
</body></html>"""

# Apply runtime branding/template substitution
_brand_parts = BRAND.split(" ", 1)
_brand_first = _brand_parts[0]
_brand_rest = _brand_parts[1] if len(_brand_parts) > 1 else ""
for _placeholder, _value in (
    ("__BRAND__", BRAND),
    ("__BRAND_FIRST__", _brand_first),
    ("__BRAND_REST__", _brand_rest),
    ("__DEFAULT_FROM__", DEFAULT_FROM),
):
    LOGIN_PAGE = LOGIN_PAGE.replace(_placeholder, _value)
    MAIN_PAGE = MAIN_PAGE.replace(_placeholder, _value)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
