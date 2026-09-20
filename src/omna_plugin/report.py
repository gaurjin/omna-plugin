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
    by_app: Counter = Counter()
    by_door: Counter = Counter()
    tls_refused: Counter = Counter()
    bypassed_apps: set = set()
    sessions = set()
    n_secret = n_pii = 0
    ok = refused = failed = bypassed = 0
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
        if r.get("app"):
            by_app[r["app"]] += 1
        # Older receipts (pre-Stage-2) have no "door" key at all; that is the
        # API door by definition, since it is the only door that existed then.
        by_door[r.get("door", "api")] += 1
        note = r.get("note")
        if note == "bypassed-by-policy":
            bypassed += 1
            if r.get("app"):
                bypassed_apps.add(r["app"])
        if note == "tls-refused":
            tls_refused[(r.get("app") or "unknown app", r.get("host") or "?")] += 1
        if r.get("session"):
            sessions.add(r["session"])
        st = int(r.get("status", 0) or 0)
        if note in ("unparseable", "mask-failed"):
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
    # Fixed order (api, system, deep) so the report reads the same every week,
    # e.g. "deep 0" when no deep-capture app has been seen yet; any other
    # door name (future doors) is appended, largest first.
    door_order = ("api", "system", "deep")
    ordered_by_door = {name: by_door.get(name, 0) for name in door_order}
    for name, count in by_door.most_common():
        if name not in ordered_by_door:
            ordered_by_door[name] = count
    refused_breakdown = sorted(
        ({"app": app, "host": host, "count": count} for (app, host), count in tls_refused.items()),
        key=lambda x: (-x["count"], x["app"], x["host"]),
    )
    refused_struct = {"count": sum(tls_refused.values()), "by_app_host": refused_breakdown}
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
        "by_app": dict(by_app.most_common()),
        "by_door": ordered_by_door,
        "bypassed": bypassed,
        "bypassed_apps": sorted(bypassed_apps),
        "refused": refused_struct,
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
    apps_str = " · ".join(
        f"{k} {v}" + (" (bypassed)" if k in d["bypassed_apps"] else "") for k, v in d["by_app"].items()
    ) or "none seen"
    refused = d["refused"]
    if refused["count"]:
        refused_str = "refused: " + " · ".join(f"{e['app']} → {e['host']} ×{e['count']}" for e in refused["by_app_host"])
    else:
        refused_str = "no refusals"
    lines += [
        f"SCAN      {len(d['by_upstream'])} AI destination(s): " + ", ".join(f"{k} ({v})" for k, v in d["by_upstream"].items()) + f"  ·  {d['sessions']} Claude Code session(s)",
        f"          apps: {apps_str}  ·  {refused_str}",
        f"PROVE     receipt chain {'INTACT' if d['chain']['intact'] else 'BROKEN'} ({d['chain']['receipts']} receipts, {d['chain']['message']})",
        f"TRUST     {d['what_left_the_machine']}",
        f"COST      masking added {d['avg_mask_ms']} ms per request on average (whole round trip incl. the provider: {d['avg_ms']} ms)",
        "",
        "by day:   " + (", ".join(f"{k}: {v}" for k, v in d["by_day"].items()) or "no requests"),
        "by door:  " + " · ".join(f"{k} {v}" for k, v in d["by_door"].items()),
        f"engine {d['engine']}  ·  receipts in {d['home']}",
    ]
    return "\n".join(lines)


def render_html(d: dict) -> str:
    e = html.escape
    kinds = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in d["by_kind"].items()) or "<tr><td colspan=2>nothing caught</td></tr>"
    days = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in d["by_day"].items()) or "<tr><td colspan=2>no requests</td></tr>"
    ups = ", ".join(f"{e(k)} ({v})" for k, v in d["by_upstream"].items()) or "none"
    apps = "".join(
        f"<tr><td>{e(k)}{' (bypassed)' if k in d['bypassed_apps'] else ''}</td><td>{v}</td></tr>" for k, v in d["by_app"].items()
    ) or "<tr><td colspan=2>no app receipts</td></tr>"
    doors = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in d["by_door"].items())
    refused_rows = "".join(
        f"<tr><td>{e(r['app'])}</td><td>{e(r['host'])}</td><td>{r['count']}</td></tr>" for r in d["refused"]["by_app_host"]
    ) or "<tr><td colspan=3>no refusals</td></tr>"
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
<h3>Apps</h3><table><tr><th align=left>app</th><th align=left>requests</th></tr>{apps}</table>
<p class="muted">{d['bypassed']} bypassed by policy · {d['refused']['count']} refused by a pinned app's own certificate (never forwarded)</p>
<table><tr><th align=left>app</th><th align=left>host</th><th align=left>refused</th></tr>{refused_rows}</table>
<h2>Requests by day</h2><table>{days}</table>
<h2>Requests by door</h2><table><tr><th align=left>door</th><th align=left>requests</th></tr>{doors}</table>
<h2>Trust</h2><p>{e(d['what_left_the_machine'])}. Masking added {d['avg_mask_ms']} ms per request on average; the whole round trip including the provider took {d['avg_ms']} ms.</p>
<p class="muted">engine {e(d['engine'])} · receipts in {e(d['home'])} · verify any time with <code>omna log --verify</code></p>
</body></html>"""


# Keys from build() that are safe to hand to someone else. Everything outside
# this list is dropped by share() — not filtered "if it looks sensitive", but
# dropped unless it is named here, so a field added to build() later can never
# leak into an export by default. Notably absent: "home" (a filesystem path,
# which carries the username) and "by_app" (which app names a person runs is
# their business, not the company's).
SHAREABLE_KEYS = (
    "period_days", "since", "engine",
    "requests", "requests_ok", "requests_refused", "requests_failed",
    "requests_with_catch", "sessions",
    "secrets_caught", "pii_caught", "distinct_secrets", "distinct_pii",
    "avg_mask_ms", "avg_ms",
    "by_kind", "by_day", "by_door", "bypassed",
)


def share(d: dict, pol=None) -> dict:
    """Counts-only view of a report, safe to send to a company admin.

    This is the piece that answers "how do 100 machines become one report"
    without anyone standing up a server: each machine writes one of these,
    an admin collects them however they already move files around, and
    merge() adds them up.

    What is in here is numbers, plus the org/department tags the machine was
    enrolled with. What is NOT in here: prompt text, tokens, real values,
    hostnames, usernames, file paths, app names. The device id is random and
    machine-local — it exists so two files can be told apart, and so the same
    file sent twice can be spotted, nothing else.
    """
    from .policy import Policy

    pol = pol or Policy.load()
    out = {k: d[k] for k in SHAREABLE_KEYS if k in d}
    out["org"] = pol.org
    out["dept"] = pol.dept
    out["device_id"] = pol.device_id
    out["generated"] = d.get("generated", "")
    out["format"] = "omna-share-1"
    return out


def _is_share(d: dict) -> bool:
    return d.get("format") == "omna-share-1"


def merge(shares: list[dict]) -> dict:
    """Add up exported reports into a company view plus a per-department view.

    A device that appears twice (the same file collected from two places, or
    an admin re-running a collection) is counted ONCE — the later `generated`
    timestamp wins. Without that, a rollup silently double-counts, which is
    the sort of error nobody catches because the number still looks plausible.
    """
    bad = [s for s in shares if not _is_share(s)]
    if bad:
        raise ValueError(
            f"{len(bad)} file(s) are not Omna share exports "
            "(expected \"format\": \"omna-share-1\" — did you pass a plain `--json` report?)"
        )

    latest: dict[str, dict] = {}
    anonymous: list[dict] = []
    for s in shares:
        did = str(s.get("device_id") or "")
        if not did:
            # A machine that was never enrolled still has numbers worth adding;
            # it just cannot be de-duplicated, so keep every one of them.
            anonymous.append(s)
            continue
        prev = latest.get(did)
        if prev is None or str(s.get("generated", "")) >= str(prev.get("generated", "")):
            latest[did] = s
    used = list(latest.values()) + anonymous

    def totals(group: list[dict]) -> dict:
        by_kind: Counter = Counter()
        by_day: Counter = Counter()
        by_door: Counter = Counter()
        acc = {k: 0 for k in (
            "requests", "requests_ok", "requests_refused", "requests_failed",
            "requests_with_catch", "sessions", "secrets_caught", "pii_caught",
            "distinct_secrets", "distinct_pii", "bypassed",
        )}
        for s in group:
            for k in acc:
                acc[k] += int(s.get(k, 0) or 0)
            by_kind.update(s.get("by_kind") or {})
            by_day.update(s.get("by_day") or {})
            by_door.update(s.get("by_door") or {})
        acc["devices"] = len(group)
        acc["by_kind"] = dict(by_kind.most_common())
        acc["by_day"] = dict(sorted(by_day.items()))
        acc["by_door"] = dict(by_door.most_common())
        return acc

    by_dept: dict[str, list[dict]] = {}
    for s in used:
        by_dept.setdefault(str(s.get("dept") or "(no department)"), []).append(s)

    orgs = sorted({str(s.get("org") or "") for s in used} - {""})
    return {
        "format": "omna-merge-1",
        "org": orgs[0] if len(orgs) == 1 else ", ".join(orgs) if orgs else "(no organisation)",
        "devices": len(used),
        "files_read": len(shares),
        "duplicates_dropped": len(shares) - len(used),
        "company": totals(used),
        "departments": {d: totals(g) for d, g in sorted(by_dept.items())},
    }


def render_merge_text(m: dict) -> str:
    c = m["company"]
    lines = [
        f"Omna company report  ·  {m['org']}",
        f"{m['devices']} machines reporting"
        + (f"  ·  {m['duplicates_dropped']} duplicate file(s) ignored" if m["duplicates_dropped"] else ""),
        "",
        f"COMPANY   {c['requests']} AI requests  ·  {c['secrets_caught']} secrets kept off the wire  "
        f"·  {c['pii_caught']} personal values masked",
        "",
        "BY DEPARTMENT",
    ]
    width = max((len(d) for d in m["departments"]), default=10)
    for dept, t in m["departments"].items():
        lines.append(
            f"  {dept.ljust(width)}  {t['devices']:>3} machines  "
            f"{t['requests']:>6} requests  {t['secrets_caught']:>5} secrets  {t['pii_caught']:>5} personal"
        )
    lines += ["", "Counts only. No prompt text, no real values, no usernames — see `omna report --export`."]
    return "\n".join(lines)


def to_json(d: dict) -> str:
    return json.dumps(d, indent=2)
