"""The only part of Omna that can send anything to Omna (#132).

Deliberately its own module. ``crashlog.py`` builds and stores the report and
has a test that fails the build if networking ever appears in it; this file is
the single, obvious place a reviewer looks to answer "what leaves my machine?".

What it sends: the already-masked rows from ``~/.omna/crashes.jsonl``, exactly
as they sit on disk. What it does not send: prompts, unmasked values, file
paths, usernames, hostnames, the device id, or anything gathered at send time.

It only runs when ``policy.crash_reports == "on"``, which only happens after
the person answered yes to a question. Failure is always silent — a crash
report that cannot be delivered must never become a second visible problem.
"""

from __future__ import annotations

import httpx

from . import config, crashlog

ENDPOINT = "https://omna.dev/api/public/crash"
TIMEOUT = 5.0


def send_pending(endpoint: str | None = None) -> int:
    """Send anything not yet sent. Returns how many went. Never raises.

    Rows are marked sent only on a 2xx, so a failed attempt is retried next
    time rather than silently dropped — and marking does not delete the local
    copy, which is the whole point.
    """
    if not crashlog.may_send():
        return 0
    rows = crashlog.unsent()
    if not rows:
        return 0
    return _deliver(rows, endpoint or ENDPOINT)


def send_now(rows: list[dict], endpoint: str | None = None) -> int:
    """Send these specific rows regardless of the stored preference.

    This is the path behind an explicit ``omna crash --send``: the person is
    asking for it right now, so a stored "off" does not apply to a direct
    instruction. It still sends only the rows handed to it.
    """
    if not rows:
        return 0
    return _deliver(rows, endpoint or ENDPOINT)


def _deliver(rows: list[dict], endpoint: str) -> int:
    try:
        r = httpx.post(
            endpoint,
            json=crashlog.payload(rows),
            timeout=TIMEOUT,
            headers={"user-agent": f"omna-plugin/{_version()}"},
        )
    except httpx.HTTPError:
        return 0
    if r.status_code // 100 != 2:
        return 0
    crashlog.mark_sent(rows)
    return len(rows)


def _version() -> str:
    try:
        from .proxy import __version__

        return __version__
    except Exception:
        return "unknown"


def ask_and_remember(rows: list[dict], *, input_fn=input, out=None) -> bool:
    """Ask the one question, once, and write the answer down.

    Asked only where there is a real terminal (see ``cli.maybe_ask_about_crashes``)
    and only when something has actually broken, because a consent prompt at a
    moment the person does not care about is how you train people to say no.
    """
    import sys

    out = out or sys.stderr
    n = len(rows)
    what = "a problem" if n == 1 else f"{n} problems"
    print(f"\nomna hit {what} recently and saved the details on this machine.", file=out)
    print(f"  You can read exactly what was saved:  omna crash", file=out)
    print("  It is already masked — your prompts and your real values are not in it.", file=out)
    try:
        answer = input_fn("  Send it to the developers so it gets fixed? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print("", file=out)
        return False
    yes = str(answer).strip().lower() in ("y", "yes")
    crashlog.remember_choice(yes)
    if yes:
        print("  Thank you. Turn this off any time with `omna crash --never`.", file=out)
    else:
        print("  Nothing was sent, and you will not be asked again.", file=out)
    return yes
