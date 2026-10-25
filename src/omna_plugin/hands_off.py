"""Requests Omna forwards byte-for-byte: the AI site's own security and reports.

Owner rule (2026-10-25): mask only what YOU send — never play with an AI
company's security layer, never fight them. Live, through the system door:

- claude.ai: masking Cloudflare's robot-check reports (a false CRYPTO_ADDRESS)
  made Cloudflare refuse every request and claude.ai signed the browser out.
- perplexity.ai: masking the browser's answer to Cloudflare's check
  (`?__cf_chl_…`) left the page stuck on the check.
- chatgpt.com and grok.com rejected their own usage/error reports (400) after
  a false CREDIT_CARD; claude.ai's timing reports minted ~245 false ID tokens
  per page load.

Checked live the same day: these reports carried the sites' own data
(timings, `googlers@google.com`, a Sentry address), never the typed message.
Site reports are listed per site, only where verified live — a report path on
another site is still masked. TRIPWIRE: if a site ever puts what you typed in
one of these, this list is where it would get through.
"""

from __future__ import annotations

import re

SECURITY = "passthrough-security-check"
SITE_REPORT = "passthrough-site-report"

# Any host: these are never anything you typed.
_SECURITY_ANY_HOST = [
    re.compile(r"^/cdn-cgi/"),             # Cloudflare's robot check (scripts + fingerprint reports)
    re.compile(r"[?&]__cf_chl_"),          # the browser's answer to Cloudflare's check
]

# (host, path pattern) — verified live 2026-10-25.
_SECURITY_BY_HOST = [
    ("chatgpt.com", re.compile(r"^/backend-api/sentinel/")),   # ChatGPT's anti-abuse check before each message
]
_REPORTS_BY_HOST = [
    ("claude.ai", re.compile(r"^/api/v2/rum\b")),
    ("claude.ai", re.compile(r"^/api/event_logging/")),
    ("chatgpt.com", re.compile(r"/events/statsc/")),
    ("chatgpt.com", re.compile(r"^/ces/")),
    ("chatgpt.com", re.compile(r"^/realtime/wm$")),   # device codes + numbers, no text (purpose not public)
    ("grok.com", re.compile(r"^/monitoring\b")),
    ("grok.com", re.compile(r"^/ht/v1/")),
    ("gemini.google.com", re.compile(r"^/_/BardChatUi/(jserror|web-reports)\b")),
    ("meta.ai", re.compile(r"^/monitoring\b")),        # rejected 401 once masked
    ("meta.ai", re.compile(r"^/api/analytics$")),
]


def _on(host: str, site: str) -> bool:
    return host == site or host.endswith("." + site)


def reason(host: str, path: str) -> str | None:
    """Why this request must be forwarded untouched, or None to mask it as usual."""
    h = (host or "").lower().rsplit(":", 1)[0]
    p = path or ""
    if any(rx.search(p) for rx in _SECURITY_ANY_HOST):
        return SECURITY
    bare = p.split("?", 1)[0]
    if any(_on(h, site) and rx.search(bare) for site, rx in _SECURITY_BY_HOST):
        return SECURITY
    if any(_on(h, site) and rx.search(bare) for site, rx in _REPORTS_BY_HOST):
        return SITE_REPORT
    return None
