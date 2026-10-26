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
Site reports are listed per site in sites.py, only where verified live — a report path on
another site is still masked. TRIPWIRE: if a site ever puts what you typed in
one of these, this list is where it would get through.
"""

from __future__ import annotations

import re

from . import sites

SECURITY = "passthrough-security-check"
SITE_REPORT = "passthrough-site-report"

# Any host: these are never anything you typed.
_SECURITY_ANY_HOST = [
    re.compile(r"^/cdn-cgi/"),             # Cloudflare's robot check (scripts + fingerprint reports)
]
# The browser's answer to Cloudflare's check goes to the page's own address
# with `?__cf_chl_…` added. A web form that was challenged is re-sent to that
# same address WITH the person's form in its body, so only Cloudflare's own
# answer — no body, or one carrying Cloudflare's fields — is left alone; any
# other body there is masked as usual (architecture review, MASTER #178).
# TRIPWIRE: a replayed form that ALSO carries Cloudflare's fields still passes.
_CF_CHALLENGE = re.compile(r"[?&]__cf_chl_")
_CF_ANSWER_FIELDS = re.compile(
    r'(^|[&{,\s"])(md|cf[-_][\w-]*|h-captcha-response|g-recaptcha-response|jschl[\w-]*)"?\s*[=:]')

# (host, path pattern) per site — verified live 2026-10-25; listed in sites.py.
_SECURITY_BY_HOST = sites.compiled("security")
_REPORTS_BY_HOST = sites.compiled("reports")


def _cloudflare_answer(body: bytes) -> bool:
    if not body.strip():
        return True
    head = body[:4096].decode("utf-8", "replace")
    return _CF_ANSWER_FIELDS.search(head) is not None


def reason(host: str, path: str, body: bytes = b"") -> str | None:
    """Why this request must be forwarded untouched, or None to mask it as usual."""
    h = (host or "").lower().rsplit(":", 1)[0]
    p = path or ""
    if any(rx.search(p) for rx in _SECURITY_ANY_HOST):
        return SECURITY
    if _CF_CHALLENGE.search(p) and _cloudflare_answer(body or b""):
        return SECURITY
    bare = p.split("?", 1)[0]
    if any(sites.on(h, site) and rx.search(bare) for site, rx in _SECURITY_BY_HOST):
        return SECURITY
    if any(sites.on(h, site) and rx.search(bare) for site, rx in _REPORTS_BY_HOST):
        return SITE_REPORT
    return None
