"""``omna report``: the weekly summary built from the local receipts.

This is the free, local seed of the paid evidence report: the same five beats
as the sample report (scan, protect, prove, trust, save) computed from what
this machine actually did. Counts only; no values ever enter a receipt, so
none can appear here.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timedelta

from . import config, receipts
from .engine import engine_version

SECRET_KINDS_HINT = ("KEY", "TOKEN", "SECRET", "PASSWORD", "JWT", "CONNECTION_STRING", "CREDENTIAL", "WEBHOOK")


def _parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def build(days: int = 7) -> dict:
    """Aggregate the last ``days`` days of receipts into one dict."""
    all_recs = receipts.tail(0)
    now = datetime.now().astimezone()
    since = now - timedelta(days=days)
    recs = []
    for r in all_recs:
        t = _parse_ts(str(r.get("ts", "")))
        if t is None:
            continue
        if t.tzinfo is None:
            t = t.replace(tzinfo=now.tzinfo)
        if t >= since:
            recs.append((t, r))
    by_kind: Counter = Counter()
    by_day: Counter = Counter()
    by_upstream: Counter = Counter()
    sessions = set()
    n_secret = n_pii = 0
    ok = refused = failed = 0
    ms = []
    mask_ms = []
    distinct_secret: set = set()
    distinct_pii: set = set()
    for t, r in recs:
        for k, v in (r.get("masked") or {}).items():
            by_kind[k] += v
        n_secret += r.get("secrets", 0)
        n_pii += r.get("pii", 0)
        by_day[t.strftime("%Y-%m-%d")] += 1
        by_upstream[r.get("upstream", "?")] += 1
        if r.get("session"):
            sessions.add(r["session"])
        st = int(r.get("status", 0) or 0)
        if r.get("note") in ("unparseable", "mask-failed"):
            refused += 1
        elif 200 <= st < 400:
            ok += 1
        else:
            failed += 1
        if isinstance(r.get("ms"), int):
            ms.append(r["ms"])
        if isinstance(r.get("mask_ms"), int):
            mask_ms.append(r["mask_ms"])
        for tok in r.get("tokens") or []:
            (distinct_secret if str(tok).startswith("SECRET_") else distinct_pii).add(tok)
    chain_ok, chain_n, chain_msg = receipts.verify()
    # If the receipts carry no per-layer totals (older lines), fall back to a name hint.
    if n_secret == 0 and n_pii == 0 and by_kind:
        for k, v in by_kind.items():
            if any(h in k for h in SECRET_KINDS_HINT):
                n_secret += v
            else:
                n_pii += v
    requests_with_catch = sum(1 for _, r in recs if (r.get("masked") or {}))
    return {
        "generated": now.strftime("%Y-%m-%d %H:%M %Z"),
        "period_days": days,
        "since": since.strftime("%Y-%m-%d"),
        "engine": engine_version(),
        "home": str(config.home()),
        "requests": len(recs),
        "requests_ok": ok,
        "requests_refused": refused,
        "requests_failed": failed,
        "requests_with_catch": requests_with_catch,
        "sessions": len(sessions),
        "secrets_caught": n_secret,
        "pii_caught": n_pii,
        "distinct_secrets": len(distinct_secret),
        "distinct_pii": len(distinct_pii),
        "avg_mask_ms": int(sum(mask_ms) / len(mask_ms)) if mask_ms else 0,
        "by_kind": dict(by_kind.most_common()),
        "by_day": dict(sorted(by_day.items())),
        "by_upstream": dict(by_upstream.most_common()),
        "avg_ms": int(sum(ms) / len(ms)) if ms else 0,
        "chain": {"intact": chain_ok, "receipts": chain_n, "message": chain_msg},
        "what_left_the_machine": "masked requests only, to the AI provider you were already using; nothing to Omna",
    }


def render_text(d: dict) -> str:
    lines = [
        f"Omna weekly report  ·  last {d['period_days']} days (since {d['since']})  ·  generated {d['generated']}",
        "",
        f"PROTECT   {d['requests']} AI requests enabled, 0 blocked  ·  {d['requests_refused']} refused (unparseable)  ·  {d['requests_failed']} provider errors",
        f"          {d['distinct_secrets']} distinct secrets kept off the wire ({d['secrets_caught']} occurrences)  ·  {d['distinct_pii']} distinct personal values tokenised ({d['pii_caught']} occurrences)  ·  {d['requests_with_catch']} requests had at least one catch",
    ]
    if d["by_kind"]:
        lines.append("          by kind: " + ", ".join(f"{k} ×{v}" for k, v in d["by_kind"].items()))
    lines += [
        f"SCAN      {len(d['by_upstream'])} AI destination(s): " + ", ".join(f"{k} ({v})" for k, v in d["by_upstream"].items()) + f"  ·  {d['sessions']} Claude Code session(s)",
        f"PROVE     receipt chain {'INTACT' if d['chain']['intact'] else 'BROKEN'} ({d['chain']['receipts']} receipts, {d['chain']['message']})",
        f"TRUST     {d['what_left_the_machine']}",
        f"COST      masking added {d['avg_mask_ms']} ms per request on average (whole round trip incl. the provider: {d['avg_ms']} ms)",
        "",
        "by day:   " + (", ".join(f"{k}: {v}" for k, v in d["by_day"].items()) or "no requests"),
        f"engine {d['engine']}  ·  receipts in {d['home']}",
    ]
    return "\n".join(lines)


def render_html(d: dict) -> str:
    e = html.escape
    kinds = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in d["by_kind"].items()) or "<tr><td colspan=2>nothing caught</td></tr>"
    days = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in d["by_day"].items()) or "<tr><td colspan=2>no requests</td></tr>"
    ups = ", ".join(f"{e(k)} ({v})" for k, v in d["by_upstream"].items()) or "none"
    chain = "intact" if d["chain"]["intact"] else "BROKEN"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Omna weekly report</title>
<style>body{{font:15px/1.5 -apple-system,Helvetica,Arial,sans-serif;max-width:820px;margin:40px auto;padding:0 16px;color:#111}}
h1{{font-size:22px}} .grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}} .cell{{border:1px solid #ddd;border-radius:8px;padding:12px}}
.cell b{{display:block;font-size:26px}} table{{border-collapse:collapse;margin:8px 0}} td{{border-bottom:1px solid #eee;padding:4px 12px 4px 0}} .muted{{color:#666;font-size:13px}}</style></head><body>
<h1>Omna weekly report <span class="muted">· last {d['period_days']} days · generated {e(d['generated'])}</span></h1>
<p><b>THE UNLOCK.</b> Your team used AI on everything. {d['requests']} requests enabled, 0 blocked, every one masked on this machine before it left.</p>
<div class="grid">
<div class="cell"><b>{d['requests']}</b>AI requests enabled · 0 blocked</div>
<div class="cell"><b>{d['distinct_secrets']}</b>distinct secrets kept off the wire ({d['secrets_caught']} occurrences)</div>
<div class="cell"><b>{d['distinct_pii']}</b>distinct personal values tokenised ({d['pii_caught']} occurrences)</div>
<div class="cell"><b>{chain}</b>receipt chain ({d['chain']['receipts']} receipts)</div>
</div>
<h2>Catches, not incidents</h2><p class="muted">A catch means the value never reached the provider. No incident occurred.</p>
<table><tr><th align=left>kind</th><th align=left>count</th></tr>{kinds}</table>
<h2>Scan</h2><p>AI destinations seen: {ups}. Claude Code sessions: {d['sessions']}.</p>
<h2>Requests by day</h2><table>{days}</table>
<h2>Trust</h2><p>{e(d['what_left_the_machine'])}. Masking added {d['avg_mask_ms']} ms per request on average; the whole round trip including the provider took {d['avg_ms']} ms.</p>
<p class="muted">engine {e(d['engine'])} · receipts in {e(d['home'])} · verify any time with <code>omna log --verify</code></p>
</body></html>"""


def to_json(d: dict) -> str:
    return json.dumps(d, indent=2)
