"""spamfilter.py — inbound spam scoring for the catchall mail stack.

Why this exists: the catchall mailboxes accept ALL mail for a domain, and the
app forwards inbound mail onward (to a Gmail, or to sibling tenants). When the
inbound is spam, forwarding it re-sends it *from our own domain* (aligned DKIM),
which makes our domain look like a spammer to Gmail and poisons our sending
reputation — so legitimate mail we send later lands in spam. The fix is to score
inbound mail and refuse to forward the spam (we still keep a copy in a Spam
folder for auditing).

Design:
  * Dependency-light — only dnspython + dkimpy, both already required by app.py.
  * Pure & testable — score_message() takes raw bytes + envelope + peer IP and
    returns a Verdict. No DB, no globals, no network side effects beyond DNS reads.
  * FAIL-OPEN — any internal error scores the message as *ham* so we never drop
    or misclassify legitimate mail on a bug. Spam that slips through is cheap;
    a lost customer email is not.
  * Layered signals — IP blocklists (DNSBL) + DKIM verification + a best-effort
    SPF check + content/heuristic rules, summed into a score vs a threshold.
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import ipaddress
import logging
import re
from dataclasses import dataclass, field

log = logging.getLogger("spamfilter")

try:
    import dns.resolver
    import dns.reversename
    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False

try:
    import dkim as _dkim
    _HAVE_DKIM = True
except Exception:  # pragma: no cover
    _HAVE_DKIM = False

# IP-reputation blocklists. Spamhaus ZEN is the gold standard but refuses
# queries from big shared resolvers (it answers 127.255.255.x for "blocked");
# we detect and ignore that. Barracuda + SpamCop are open alternates.
DNSBLS = ("zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net")

# (name, compiled-regex, weight). Tuned for the sextortion / crypto / phishing /
# pharma / lottery junk that actually floods catchall boxes.
_P = re.compile
SPAM_PATTERNS = [
    ("sextortion", _P(r"\b(i\s+recorded\s+you|your\s+webcam|i\s+have\s+access\s+to\s+your|"
                      r"you\s+pervert|adult\s+(site|video)|i\s+know\s+your\s+password|"
                      r"pleasuring\s+yourself|masturbat)", re.I), 6.0),
    ("crypto-extortion", _P(r"\b(bitcoin|btc|usdt|wallet\s+address|send\s+\$?\d+\s*(in\s+)?(btc|bitcoin)|"
                            r"pay\s+the\s+ransom)\b", re.I), 3.0),
    ("lottery", _P(r"\b(you'?ve?\s+won|lottery\s+winner|claim\s+your\s+prize|beneficiary\s+of|"
                   r"unclaimed\s+(funds|inheritance)|million\s+(dollars|usd|euro))\b", re.I), 4.0),
    ("pharma", _P(r"\b(viagra|cialis|pharmacy|prescription\s+meds|weight\s*loss\s+pills|cbd\s+gummies)\b", re.I), 3.0),
    ("phish-verify", _P(r"\b(verify\s+your\s+account|account\s+(suspended|locked|will\s+be\s+closed)|"
                        r"unusual\s+(sign[- ]?in|activity)|confirm\s+your\s+(identity|password)|"
                        r"click\s+here\s+to\s+(verify|reactivate|unlock))\b", re.I), 3.0),
    ("urgent-money", _P(r"\b(wire\s+transfer|urgent\s+payment|overdue\s+invoice|gift\s+cards?\b.*\burgent|"
                        r"are\s+you\s+available\??\s*$)", re.I), 2.0),
    ("seo-spam", _P(r"\b(rank\s+your\s+website|first\s+page\s+of\s+google|buy\s+backlinks|"
                    r"boost\s+your\s+(traffic|sales)|guest\s+post\s+opportunit)\b", re.I), 2.0),
]

SHORTENERS = _P(r"//(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|ow\.ly|rb\.gy|shorturl)", re.I)
RISKY_ATTACH = _P(r"\.(exe|scr|js|jar|vbs|bat|cmd|com|pif|iso|lnk|html?|zip|rar|7z|ace)$", re.I)
SUSP_TLD = _P(r"\.(zip|mov|xyz|top|club|work|click|link|gq|cf|tk|ml|ga|country|kim|loan|men|date|racing)$", re.I)


@dataclass
class Verdict:
    is_spam: bool
    score: float
    reasons: list = field(default_factory=list)

    def as_dict(self):
        return {"is_spam": self.is_spam, "score": self.score, "reasons": self.reasons}


def _is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast)
    except Exception:
        return False


def _resolver(timeout: float):
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _dnsbl_hits(ip: str, timeout: float) -> list:
    """Return the DNSBLs that list `ip`. IPv4 only. Ignores 'query blocked'
    (127.255.255.x) sentinels that Spamhaus returns to public resolvers."""
    hits = []
    try:
        octets = ip.split(".")
        if len(octets) != 4:
            return hits  # skip IPv6 for now
        rev = ".".join(reversed(octets))
    except Exception:
        return hits
    res = _resolver(timeout)
    for bl in DNSBLS:
        try:
            answers = res.resolve(f"{rev}.{bl}", "A")
            codes = {a.address for a in answers}
            if any(c.startswith("127.255.255.") for c in codes):
                continue  # resolver-blocked sentinel, not a real listing
            if codes:
                hits.append(bl.split(".")[0])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # not listed
        except Exception:
            pass  # timeout / servfail — ignore (fail-open per-BL)
    return hits


def _spf_lite(domain: str, ip: str, timeout: float, depth: int = 0) -> str:
    """Best-effort SPF: parse the domain's TXT SPF and test ip4/ip6 + one level
    of include/a/mx. Returns pass|fail|softfail|neutral|none. Intentionally
    simple — a full RFC7208 evaluator is out of scope; this only catches blatant
    forgeries and never hard-fails legit mail (unknown → neutral)."""
    if depth > 2 or not _HAVE_DNS:
        return "neutral"
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return "neutral"
    res = _resolver(timeout)
    try:
        txts = res.resolve(domain, "TXT")
    except Exception:
        return "none"
    spf = None
    for t in txts:
        s = b"".join(t.strings).decode("utf-8", "replace") if hasattr(t, "strings") else str(t).strip('"')
        if s.lower().startswith("v=spf1"):
            spf = s
            break
    if not spf:
        return "none"
    default = "neutral"
    for tok in spf.split()[1:]:
        q = "pass"
        if tok[0] in "+-~?":
            q = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[tok[0]]
            tok = tok[1:]
        low = tok.lower()
        try:
            if low == "all":
                default = q
            elif low.startswith("ip4:") or low.startswith("ip6:"):
                net = ipaddress.ip_network(tok.split(":", 1)[1], strict=False)
                if addr in net:
                    return q
            elif low.startswith("include:") and depth < 2:
                sub = _spf_lite(tok.split(":", 1)[1], ip, timeout, depth + 1)
                if sub == "pass":
                    return q
            elif low in ("a", "mx") or low.startswith("a:") or low.startswith("mx:"):
                d = tok.split(":", 1)[1] if ":" in tok else domain
                is_mx = low.startswith("mx")
                try:
                    hosts = []
                    if is_mx:
                        for mx in res.resolve(d, "MX"):
                            hosts.append(str(mx.exchange).rstrip("."))
                    else:
                        hosts = [d]
                    for h in hosts:
                        for a in res.resolve(h, "A"):
                            if addr == ipaddress.ip_address(a.address):
                                return q
                except Exception:
                    pass
        except Exception:
            continue
    return default


def _text_of(msg) -> str:
    try:
        if msg.is_multipart():
            out = []
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html") and \
                        "attachment" not in str(part.get("Content-Disposition", "")):
                    payload = part.get_payload(decode=True)
                    if payload:
                        out.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
            return "\n".join(out)
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode(msg.get_content_charset() or "utf-8", "replace")
        return str(msg.get_payload() or "")
    except Exception:
        return ""


def score_message(raw_bytes: bytes, *, mail_from: str = "", peer_ip: str | None = None,
                  helo: str = "", our_domains=(), allow_domains=(), block_domains=(),
                  threshold: float = 6.0, use_dnsbl: bool = True, use_dkim: bool = True,
                  use_spf: bool = True, dns_timeout: float = 3.0) -> Verdict:
    """Score one inbound message. FAIL-OPEN: on any error, returns ham."""
    try:
        our_domains = {d.lower() for d in our_domains}
        allow_domains = {d.lower() for d in allow_domains} | our_domains
        block_domains = {d.lower() for d in block_domains}
        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        except Exception:
            return Verdict(False, 0.0, ["parse-error(fail-open)"])

        from_hdr = msg.get("From", "") or ""
        disp_name, from_addr = email.utils.parseaddr(from_hdr)
        from_addr = (from_addr or "").lower()
        from_dom = from_addr.split("@")[-1] if "@" in from_addr else ""
        env_dom = (mail_from or "").split("@")[-1].lower()

        reasons: list = []
        score = 0.0

        # Hard blocklist wins.
        if from_dom in block_domains or env_dom in block_domains:
            return Verdict(True, 99.0, [f"blocklisted:{from_dom or env_dom}"])

        # DNSBL first — it also lets us honor allowlist safely (a listed IP
        # spoofing our own domain still gets caught).
        dnsbl = []
        if use_dnsbl and peer_ip and _is_public_ip(peer_ip):
            dnsbl = _dnsbl_hits(peer_ip, dns_timeout)
            if dnsbl:
                score += 4.0 * len(dnsbl)
                reasons.append("dnsbl:" + ",".join(dnsbl))

        # Allowlist: our own / trusted domains skip content scoring — UNLESS the
        # connecting IP is blocklisted (i.e. someone forging our domain).
        allowlisted = (from_dom in allow_domains or env_dom in allow_domains)
        if allowlisted and not dnsbl:
            return Verdict(False, 0.0, [f"allowlisted:{from_dom or env_dom}"])

        # DKIM verification (only if the message claims a signature).
        if use_dkim and _HAVE_DKIM and b"dkim-signature" in raw_bytes[:20000].lower():
            try:
                if not _dkim.verify(raw_bytes):
                    score += 2.0
                    reasons.append("dkim-fail")
            except Exception:
                pass  # malformed sig / DNS issue — don't punish

        # SPF-lite on the envelope-from domain.
        if use_spf and peer_ip and env_dom and _is_public_ip(peer_ip):
            spf = _spf_lite(env_dom, peer_ip, dns_timeout)
            if spf == "fail":
                score += 3.0
                reasons.append("spf-fail")
            elif spf == "softfail":
                score += 1.0
                reasons.append("spf-softfail")

        # Content / heuristic rules.
        subject = msg.get("Subject", "") or ""
        body = _text_of(msg)
        blob = f"{subject}\n{body}"
        for name, rx, w in SPAM_PATTERNS:
            if rx.search(blob):
                score += w
                reasons.append(f"kw:{name}")

        letters = [c for c in subject if c.isalpha()]
        if len(letters) >= 8 and sum(c.isupper() for c in letters) / len(letters) > 0.8:
            score += 1.0
            reasons.append("shouty-subject")

        # Display name impersonates one of our brands but sends from elsewhere.
        dl = (disp_name or "").lower()
        if from_dom and from_dom not in our_domains:
            for d in our_domains:
                brand = d.split(".")[0]
                if brand and len(brand) >= 4 and brand in dl:
                    score += 2.0
                    reasons.append("brand-spoof-display")
                    break

        # From domain vs envelope domain mismatch (weak signal).
        if from_dom and env_dom and from_dom != env_dom and from_dom not in allow_domains:
            score += 0.5
            reasons.append("from-envelope-mismatch")

        urls = re.findall(r"https?://[^\s\"'<>]+", blob)
        if len(urls) >= 15:
            score += 1.0
            reasons.append(f"many-urls:{len(urls)}")
        if any(SHORTENERS.search(u) for u in urls):
            score += 1.0
            reasons.append("url-shortener")
        if from_dom and SUSP_TLD.search(from_dom):
            score += 1.0
            reasons.append("suspicious-tld")

        try:
            for part in (msg.walk() if msg.is_multipart() else []):
                fn = (part.get_filename() or "")
                if fn and RISKY_ATTACH.search(fn):
                    score += 1.5
                    reasons.append(f"risky-attach:{fn[-14:]}")
                    break
        except Exception:
            pass

        if not from_addr:
            score += 1.0
            reasons.append("no-from-addr")

        return Verdict(score >= threshold, round(score, 1), reasons)
    except Exception as e:  # absolute fail-open backstop
        log.warning("spamfilter error (fail-open): %s", e)
        return Verdict(False, 0.0, [f"error(fail-open):{type(e).__name__}"])
