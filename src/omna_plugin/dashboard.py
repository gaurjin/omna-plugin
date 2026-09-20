"""The live dashboard: `omna dashboard`, served at 127.0.0.1:7788/omna/dashboard.

Why a served page rather than a desktop app: the plugin is already an HTTP
server, so a dashboard costs one route and opens in the browser you already
have. A competitor (Kiji) ships a whole Electron window to show the same
numbers — that is a second process and ~100 MB of runtime for a page.

Everything here is inline: no CDN, no framework, no webfont, no external
request of any kind. That is not stinginess, it is the product's own claim —
a privacy tool whose dashboard phones out to a CDN to render is not one. The
page can be opened with the network unplugged and looks identical.

`report.build()` already computes every number. This adds the live surface,
a short cache so polling can't thrash the receipt log, and the two things an
average hides: the p95 tail and the deliberate-override count.
"""

from __future__ import annotations

import json
import time

from . import report

# The receipts file is re-read to build a snapshot. At a 3 s poll that would
# mean re-parsing the whole log 20× a minute for numbers that barely move, so
# hold each snapshot briefly. Short enough to still read as "live".
_CACHE_TTL_SECONDS = 2.0
_cache: dict = {"at": 0.0, "days": None, "data": None}


def snapshot(days: int = 7, sent_as_is: int = 0) -> dict:
    """Numbers for the dashboard. Cached for a couple of seconds."""
    now = time.time()
    if _cache["data"] is not None and _cache["days"] == days and now - _cache["at"] < _CACHE_TTL_SECONDS:
        d = _cache["data"]
    else:
        d = report.build(days=days)
        _cache.update(at=now, days=days, data=d)
    out = dict(d)
    out["sent_as_is"] = sent_as_is
    return out


def _bars(by_day: dict) -> str:
    """A timeline without a charting library: divs sized by percentage."""
    if not by_day:
        return '<p class="empty">No requests yet. Use an AI tool and this fills in.</p>'
    peak = max(by_day.values()) or 1
    cells = []
    for day, n in by_day.items():
        pct = max(4, round(100 * n / peak))
        label = day[5:]  # MM-DD; the year is in the header
        cells.append(
            f'<div class="bar-col" title="{day}: {n} requests">'
            f'<div class="bar-val">{n}</div>'
            f'<div class="bar" style="height:{pct}%"></div>'
            f'<div class="bar-day">{label}</div></div>'
        )
    return f'<div class="bars">{"".join(cells)}</div>'


def _rows(d: dict, limit: int = 8) -> str:
    items = list(d.items())[:limit]
    if not items:
        return '<p class="empty">Nothing caught yet.</p>'
    peak = max(v for _, v in items) or 1
    out = []
    for k, v in items:
        pct = max(2, round(100 * v / peak))
        out.append(
            f'<div class="row"><span class="row-k">{k}</span>'
            f'<span class="row-bar"><i style="width:{pct}%"></i></span>'
            f'<span class="row-v">{v}</span></div>'
        )
    return "".join(out)


def render(d: dict) -> str:
    chain_ok = d["chain"]["intact"]
    chain_cls = "ok" if chain_ok else "bad"
    chain_txt = "intact" if chain_ok else "BROKEN"
    doors = " · ".join(f"{k} {v}" for k, v in d["by_door"].items())
    override = d.get("sent_as_is", 0)
    override_cls = "warn" if override else "muted"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Omna — live</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{{--bg:#fdfcfa;--ink:#1c1917;--muted:#78716c;--line:rgba(28,25,21,.08);
--brand:#6c5ce7;--ok:#2f7d5d;--bad:#a13838;--warn:#b45309;--card:#fff}}
@media(prefers-color-scheme:dark){{:root{{--bg:#16150f;--ink:#f5f4f1;--muted:#a8a29e;
--line:rgba(245,244,241,.12);--card:#211f1a}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}}
.wrap{{max-width:960px;margin:0 auto;padding:28px 16px 56px}}
header{{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:4px}}
h1{{font-size:21px;margin:0;letter-spacing:-.01em}}
.live{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--ok);
display:inline-flex;align-items:center;gap:6px}}
.dot{{width:7px;height:7px;border-radius:50%;background:var(--ok);animation:p 2s infinite}}
@keyframes p{{0%,100%{{opacity:1}}50%{{opacity:.25}}}}
.sub{{color:var(--muted);font-size:13px;margin:0 0 22px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:10px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:13px 15px}}
.card b{{display:block;font-size:27px;line-height:1.15;letter-spacing:-.02em}}
.card span{{display:block;font-size:12px;color:var(--muted);margin-top:3px}}
.ok{{color:var(--ok)}} .bad{{color:var(--bad)}} .warn{{color:var(--warn)}} .muted{{color:var(--muted)}}
h2{{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);
margin:26px 0 10px;font-weight:600}}
.panel{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:15px 17px}}
.bars{{display:flex;align-items:flex-end;gap:7px;height:130px}}
.bar-col{{flex:1;display:flex;flex-direction:column;justify-content:flex-end;
align-items:center;height:100%;gap:5px}}
.bar{{width:100%;max-width:46px;background:var(--brand);border-radius:5px 5px 0 0;min-height:3px}}
.bar-day,.bar-val{{font-size:10.5px;color:var(--muted)}}
.row{{display:flex;align-items:center;gap:10px;padding:5px 0}}
.row-k{{flex:0 0 170px;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.row-bar{{flex:1;height:7px;background:var(--line);border-radius:4px;overflow:hidden}}
.row-bar i{{display:block;height:100%;background:var(--brand)}}
.row-v{{flex:0 0 52px;text-align:right;font-size:13px;color:var(--muted);font-variant-numeric:tabular-nums}}
.two{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
@media(max-width:700px){{.two{{grid-template-columns:1fr}}.row-k{{flex-basis:110px}}}}
.empty{{color:var(--muted);font-size:13px;margin:4px 0}}
footer{{margin-top:26px;color:var(--muted);font-size:12px;line-height:1.7}}
code{{background:var(--line);padding:1px 5px;border-radius:4px;font-size:11.5px}}
</style></head><body><div class="wrap">

<header><h1>Omna</h1><span class="live"><span class="dot"></span>live</span></header>
<p class="sub">Last {d['period_days']} days · engine {d['engine']} · doors: {doors}</p>

<div class="grid">
  <div class="card"><b>{d['requests']}</b><span>AI requests · 0 blocked</span></div>
  <div class="card"><b class="ok">{d['distinct_secrets']}</b><span>secrets kept off the wire</span></div>
  <div class="card"><b class="ok">{d['distinct_pii']}</b><span>personal values masked</span></div>
  <div class="card"><b class="{override_cls}">{override}</b><span>sent as-is on purpose</span></div>
</div>
<div class="grid">
  <div class="card"><b>{d['avg_mask_ms']}<small style="font-size:13px"> ms</small></b><span>masking cost · p95 {d['p95_mask_ms']} ms</span></div>
  <div class="card"><b>{d['p95_ms']}<small style="font-size:13px"> ms</small></b><span>round trip p95 · median {d['p50_ms']} ms</span></div>
  <div class="card"><b class="{chain_cls}">{chain_txt}</b><span>receipt chain · {d['chain']['receipts']} receipts</span></div>
  <div class="card"><b>{d['requests_refused']}</b><span>refused, never forwarded</span></div>
</div>

<h2>Requests per day</h2>
<div class="panel">{_bars(d['by_day'])}</div>

<div class="two">
  <div><h2>What was caught</h2><div class="panel">{_rows(d['by_kind'])}</div></div>
  <div><h2>Where it went</h2><div class="panel">{_rows(d['by_upstream'])}</div></div>
</div>

<div class="two">
  <div><h2>By door</h2><div class="panel">{_rows(d['by_door'])}</div></div>
  <div><h2>By app</h2><div class="panel">{_rows(d['by_app'])}</div></div>
</div>

<footer>
Counts only — no prompt text, no real values, ever. {d['what_left_the_machine']}.<br>
Verify the chain yourself: <code>omna log --verify</code> · export the week: <code>omna report --html FILE</code><br>
This page loads nothing from the internet. Refreshes every 3s.
</footer>
</div>
<script>
// Re-fetch and swap the body rather than reloading, so scroll position holds.
setInterval(async () => {{
  try {{
    const r = await fetch('/omna/dashboard', {{cache: 'no-store'}});
    if (!r.ok) return;
    const doc = new DOMParser().parseFromString(await r.text(), 'text/html');
    const next = doc.querySelector('.wrap');
    if (next) document.querySelector('.wrap').replaceWith(next);
  }} catch (e) {{ /* daemon stopped; keep the last good view on screen */ }}
}}, 3000);
</script>
</body></html>"""


def render_json(d: dict) -> str:
    return json.dumps(d, indent=2, sort_keys=True)
