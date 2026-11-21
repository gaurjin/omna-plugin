"""Which browsers have Omna for Chrome working in them right now.

Client test, 2026-11-21 (issues #8, #11, #12, #13): with both products
installed — exactly what omna.dev tells people to do — the system door ALSO
opened every request Chrome made to claude.ai and chatgpt.com. Result: 12-second
page loads, chatgpt.com refused, thousands of false catches in the sites' own
page traffic, and the message Omna for Chrome had already masked was masked a
second time (its `[EMAIL_1]` came out as a bracketed PERSON token).

Omna for Chrome masks in the chat box, before anything leaves the page, and it
is the only one of the two that can show the person what it hid. So while it is
checking in from a browser, the system door leaves that browser's traffic to the
sites Omna for Chrome covers completely alone (no decryption, a plain tunnel),
and goes back to masking it a few minutes after the check-ins stop (the browser
quit, the extension was removed, or protection was switched off in its popup).

The check-in is signed by the extension (extension_auth), so a web page cannot
fake one. The app is read from the check-in's own connection with the same
process lookup the system door uses, so "Google Chrome" here and there match.
"""

from __future__ import annotations

import threading
import time

# Omna for Chrome checks in every minute (plugin-bridge.ts CHECKIN_PERIOD_MINUTES).
# Three missed check-ins and the system door masks that browser again.
TTL_S = 180.0

# The sites Omna for Chrome masks (its manifest's content_scripts matches).
# Keep in step with omna-workspace/extension/manifest.json. A site missing here
# is simply masked by the system door as before — never a gap.
COVERED = (
    "chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com",
    "aistudio.google.com", "perplexity.ai", "chat.deepseek.com", "grok.com",
    "meta.ai", "muse.ai", "x.com", "copilot.com", "copilot.microsoft.com",
)

_lock = threading.Lock()
_seen: dict[str, float] = {}


def covered_host(host: str | None) -> bool:
    h = (host or "").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in COVERED)


def mark(app: str | None, protecting: bool = True, now: float | None = None) -> None:
    """Record a check-in from ``app``. ``protecting=False`` (switched off in
    the popup) forgets it at once, so the system door masks again."""
    if not app:
        return
    with _lock:
        if protecting:
            _seen[app] = time.time() if now is None else now
        else:
            _seen.pop(app, None)


def covers(app: str | None, host: str | None, now: float | None = None) -> bool:
    """True when Omna for Chrome in ``app`` is masking ``host`` right now."""
    if not app or not covered_host(host):
        return False
    t = time.time() if now is None else now
    with _lock:
        last = _seen.get(app)
    return last is not None and t - last <= TTL_S


def apps(now: float | None = None) -> list[str]:
    t = time.time() if now is None else now
    with _lock:
        return sorted(a for a, last in _seen.items() if t - last <= TTL_S)


def reset() -> None:
    with _lock:
        _seen.clear()
