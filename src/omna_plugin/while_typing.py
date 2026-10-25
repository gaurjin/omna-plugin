"""Requests an AI site sends WHILE you type, before you press Send.

Live test 2026-10-24 (MASTER #156): these carry what is in the text box. Masking
them is not enough — a value you are half-way through typing cannot be detected
yet, so Copilot (one request per keystroke) received `jane.doe@example.c`, 18 of
20 characters, in plain text. They only power suggestions, token counts and a
faster first reply, so they are blocked outright (owner's choice "A",
2026-10-24). The Chrome extension blocks the same four
(file-input-interceptor.ts, EARLY_REQUESTS).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_COPILOT = ("copilot.com", "copilot.microsoft.com")

# (host, path pattern, only when the request comes from one of these sites)
_RULES: list[tuple[str, re.Pattern[str], tuple[str, ...]]] = [
    ("chatgpt.com", re.compile(r"^/backend-api/f/conversation/prepare$"), ()),
    # The same address serves Outlook's search-as-you-type, which must keep working.
    ("substrate.office.com", re.compile(r"^/search/api/v1/suggestions"), _COPILOT),
    ("alkalimakersuite-pa.clients6.google.com", re.compile(r"CountTokens"), ()),
    ("suggest.perplexity.ai", re.compile(r"^/"), ()),   # a WebSocket: blocking the handshake blocks every frame
]


def _from(headers: dict[str, str], sites: tuple[str, ...]) -> bool:
    for name in ("origin", "referer"):
        value = next((v for k, v in headers.items() if k.lower() == name), "")
        host = urlsplit(value).hostname or ""
        if any(host == s or host.endswith("." + s) for s in sites):
            return True
    return False


def blocked(host: str, path: str, headers: dict[str, str]) -> bool:
    """True when this request is one an AI site sends while you type."""
    h = (host or "").lower().rsplit(":", 1)[0]
    p = (path or "").split("?", 1)[0]
    return any(h == rh and rp.search(p) and (not sites or _from(headers, sites)) for rh, rp, sites in _RULES)
