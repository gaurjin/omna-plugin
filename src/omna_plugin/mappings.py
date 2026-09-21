"""The Mappings Review screen: every value Omna has masked, on 127.0.0.1
only, behind the dashboard token (#134 — never a second auth scheme, #144).

Kiji's "Mapping Review" is four columns (Entity Type / Original / Masked /
Date) plus delete-one and clear-all. This joins the registry (what a value
IS — kind, detection layer, whether a checksum validated it, which style it
was last written in) against the receipts (what HAPPENED to it — how many
times it was sent, when last, which provider, which app), because "what
was masked" alone answers a lot less than "what, how sure, and where it
went."

This is the most sensitive screen in the product: the only place in Omna
that ever puts a real personal value in front of a person. Real values are
NEVER embedded in the base page or the default JSON response — they are
disclosed only through an explicit `reveal` request (see `snapshot`'s
`reveal` parameter), so the value is simply absent from the wire until asked
for by name. Secrets are never in the registry (memory-only, see
`engine.py`), so they can never appear here either — that omission is
explained on the page itself, not left silent.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict

from . import receipts
from .engine import MaskingSession

_CACHE_TTL_SECONDS = 2.0
_cache: dict = {"at": 0.0, "rows": None}


def _usage_by_label() -> dict[str, dict]:
    """Scan receipts once: per label, how many requests carried it, the ISO
    timestamp of the last one, which providers, which apps. A receipt only
    ever holds the label ("EMAIL_3"), never a real value — same guarantee
    `report.py` already relies on, reused here rather than re-derived."""
    out: dict[str, dict] = defaultdict(lambda: {"times": 0, "last": "", "upstreams": set(), "apps": set()})
    for rec in receipts.tail(0):
        ts = str(rec.get("ts") or "")
        for label in rec.get("tokens") or []:
            u = out[label]
            u["times"] += 1
            if ts > u["last"]:
                u["last"] = ts
            up = rec.get("upstream")
            if up:
                u["upstreams"].add(up)
            app = rec.get("app")
            if app:
                u["apps"].add(app)
    return out


def _rows(session: MaskingSession) -> list[dict]:
    now = time.time()
    if _cache["rows"] is not None and now - _cache["at"] < _CACHE_TTL_SECONDS:
        return _cache["rows"]
    usage = _usage_by_label()
    rows = []
    for r in session.registry_rows():
        u = usage.get(r["label"], {"times": 0, "last": "", "upstreams": set(), "apps": set()})
        rows.append({
            **r,
            "times_sent": u["times"],
            "last_sent": u["last"] or None,
            "providers": sorted(u["upstreams"]),
            "apps": sorted(u["apps"]),
        })
    rows.sort(key=lambda r: r["created"] or "", reverse=True)
    _cache.update(at=now, rows=rows)
    return rows


def invalidate_cache() -> None:
    _cache.update(at=0.0, rows=None)


def snapshot(session: MaskingSession, *, q: str = "", kind: str = "", sort: str = "created",
             dir: str = "desc", page: int = 1, per_page: int = 50,
             reveal: str = "") -> dict:
    """Query the joined rows. `reveal` is either "" (no values disclosed,
    the default), a single label ("EMAIL_3", disclose that one row's value),
    or "all" (disclose every row ON THIS PAGE — never the whole registry in
    one response). Every row's `value`/`fake` keys are present but `None`
    unless disclosed, so a caller can tell "hidden" from "no fake exists"
    apart.
    """
    rows = _rows(session)
    if q:
        needle = q.lower()
        rows = [r for r in rows if needle in r["label"].lower() or needle in r["kind"].lower()]
    if kind:
        rows = [r for r in rows if r["kind"] == kind]
    reverse = dir != "asc"
    rows = sorted(rows, key=lambda r: (r.get(sort) or ""), reverse=reverse)
    total = len(rows)
    per_page = max(1, min(per_page, 200))
    page = max(1, page)
    start = (page - 1) * per_page
    page_rows = rows[start:start + per_page]
    out_rows = []
    for r in page_rows:
        disclose = reveal == "all" or reveal == r["label"]
        out_rows.append({**r, "value": r["value"] if disclose else None,
                          "fake": r["fake"] if disclose else None})
    return {
        "rows": out_rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "kinds": sorted({r["kind"] for r in _rows(session)}),
    }


def render_json(d: dict) -> str:
    return json.dumps(d, indent=2, sort_keys=True)


def render(d: dict) -> str:
    empty_registry = d["total"] == 0 and not d["kinds"]
    body_note = (
        '<p class="empty">Omna hasn\'t masked any personal values on this machine yet. '
        "Once it does, they show up here for review.</p>"
        if empty_registry else ""
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Omna — mappings</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{{--bg:#fdfcfa;--ink:#1c1917;--muted:#78716c;--line:rgba(28,25,21,.08);
--brand:#6c5ce7;--ok:#2f7d5d;--bad:#a13838;--warn:#b45309;--card:#fff}}
@media(prefers-color-scheme:dark){{:root{{--bg:#16150f;--ink:#f5f4f1;--muted:#a8a29e;
--line:rgba(245,244,241,.12);--card:#211f1a}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}}
.wrap{{max-width:1080px;margin:0 auto;padding:28px 16px 56px}}
header{{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:4px}}
h1{{font-size:21px;margin:0;letter-spacing:-.01em}}
.sub{{color:var(--muted);font-size:13px;margin:0 0 18px}}
.controls{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}}
.controls input,.controls select,.controls button{{font:13px -apple-system,sans-serif;
padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink)}}
.controls button{{cursor:pointer}}
.controls button.primary{{background:var(--brand);color:#fff;border-color:var(--brand)}}
table{{width:100%;border-collapse:collapse;font-size:13px;background:var(--card);
border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}}
th{{cursor:pointer;color:var(--muted);font-weight:600;font-size:11.5px;
text-transform:uppercase;letter-spacing:.04em}}
td.value{{font-family:ui-monospace,Menlo,monospace;max-width:220px;overflow:hidden;text-overflow:ellipsis}}
button.reveal{{font-size:11px;padding:3px 7px;border:1px solid var(--line);border-radius:6px;
background:var(--card);cursor:pointer;color:var(--muted)}}
button.del{{font-size:11px;padding:3px 7px;border:1px solid var(--bad);border-radius:6px;
background:var(--card);cursor:pointer;color:var(--bad)}}
.empty{{color:var(--muted);font-size:13px;margin:16px 0}}
.pager{{display:flex;gap:8px;align-items:center;margin-top:12px;font-size:13px;color:var(--muted)}}
footer{{margin-top:26px;color:var(--muted);font-size:12px;line-height:1.7}}
code{{background:var(--line);padding:1px 5px;border-radius:4px;font-size:11.5px}}
</style></head><body><div class="wrap">

<header><h1>Omna — mappings</h1></header>
<p class="sub">Every personal value Omna has masked on this machine. Real values are hidden until
you click Reveal — they are never sent to this page until then.</p>

<div class="controls">
  <input id="q" placeholder="search label or kind" />
  <select id="kind"><option value="">all entity types</option></select>
  <button id="revealAll">Reveal all on this page</button>
  <button id="clearAll" style="color:var(--bad)">Clear all mappings</button>
</div>

{body_note}
<table id="tbl" style="display:{'none' if empty_registry else 'table'}">
<thead><tr>
<th data-k="kind">Entity type</th><th data-k="value">Original</th><th>Masked as</th>
<th data-k="layer">Layer</th><th data-k="validated">Checksum</th><th data-k="style">Style</th>
<th data-k="times_sent">Times sent</th><th data-k="last_sent">Last sent</th>
<th>Providers</th><th>Apps</th><th data-k="created">First seen</th><th></th>
</tr></thead>
<tbody></tbody>
</table>
<div class="pager"><button id="prev">Prev</button><span id="pageInfo"></span><button id="next">Next</button></div>

<footer>
Secrets (API keys, passwords, tokens) are never stored anywhere and never appear on this screen —
they live in memory only for the length of one request. See <code>omna status</code> for a live count.<br>
Deleting a mapping removes its token and its realistic-style fake together. If this value is masked
again, it gets a brand new token or fake — the deleted one never comes back.<br>
This page loads nothing from the internet. Values are fetched only when you click Reveal.
</footer>
</div>
<script>
const params = new URLSearchParams(location.search);
const k = params.get('k') || '';
let state = {{q:'', kind:'', sort:'created', dir:'desc', page:1, per_page:50}};

function api(extra) {{
  const p = new URLSearchParams({{...state, ...extra, k}});
  return fetch('/omna/mappings.json?' + p.toString(), {{cache:'no-store'}}).then(r => r.json());
}}

function row(r) {{
  const tr = document.createElement('tr');
  tr.dataset.label = r.label;
  const val = r.value !== null ? r.value : '••••••••';
  const fake = r.fake !== null ? (r.fake || '') : (r.style === 'realistic' ? '••••••••' : '');
  tr.innerHTML = `<td>${{r.kind}}</td>
    <td class="value">${{val}} <button class="reveal" data-label="${{r.label}}">reveal</button></td>
    <td>${{fake || '[' + r.label + ']'}}</td>
    <td>${{r.layer || 'unknown'}}</td>
    <td>${{r.validated ? 'yes' : 'no'}}</td>
    <td>${{r.style || 'unknown (masked before this was recorded)'}}</td>
    <td>${{r.times_sent}}</td>
    <td>${{r.last_sent || 'never'}}</td>
    <td>${{(r.providers||[]).join(', ') || '—'}}</td>
    <td>${{(r.apps||[]).join(', ') || '—'}}</td>
    <td>${{r.created || 'unknown'}}</td>
    <td><button class="del" data-label="${{r.label}}">delete</button></td>`;
  return tr;
}}

async function load() {{
  const d = await api({{}});
  const tbl = document.getElementById('tbl');
  const tbody = tbl.querySelector('tbody');
  tbody.innerHTML = '';
  if (d.total === 0) {{
    tbl.style.display = 'none';
  }} else {{
    tbl.style.display = 'table';
    d.rows.forEach(r => tbody.appendChild(row(r)));
  }}
  const sel = document.getElementById('kind');
  const cur = sel.value;
  sel.innerHTML = '<option value="">all entity types</option>' +
    d.kinds.map(kk => `<option value="${{kk}}">${{kk}}</option>`).join('');
  sel.value = cur;
  document.getElementById('pageInfo').textContent =
    `page ${{d.page}} of ${{Math.max(1, Math.ceil(d.total / d.per_page))}} (${{d.total}} total)`;
}}

document.getElementById('q').addEventListener('input', e => {{ state.q = e.target.value; state.page = 1; load(); }});
document.getElementById('kind').addEventListener('change', e => {{ state.kind = e.target.value; state.page = 1; load(); }});
document.querySelectorAll('th[data-k]').forEach(th => th.addEventListener('click', () => {{
  const key = th.dataset.k;
  state.dir = (state.sort === key && state.dir === 'desc') ? 'asc' : 'desc';
  state.sort = key; load();
}}));
document.getElementById('prev').addEventListener('click', () => {{ if (state.page > 1) {{ state.page--; load(); }} }});
document.getElementById('next').addEventListener('click', () => {{ state.page++; load(); }});

document.getElementById('tbl').addEventListener('click', async e => {{
  if (e.target.classList.contains('reveal')) {{
    const d = await api({{reveal: e.target.dataset.label}});
    const tr = document.querySelector(`tr[data-label="${{e.target.dataset.label}}"]`);
    const r = d.rows.find(x => x.label === e.target.dataset.label);
    if (tr && r) tr.replaceWith(row(r));
  }}
  if (e.target.classList.contains('del')) {{
    const label = e.target.dataset.label;
    if (!confirm(`Delete this mapping? If this value is masked again it gets a brand new ` +
                 `token/fake — this one (${{label}}) is gone for good.`)) return;
    await fetch('/omna/mappings/delete?k=' + encodeURIComponent(k), {{
      method: 'POST', headers: {{'content-type':'application/json'}},
      body: JSON.stringify({{label}}),
    }});
    load();
  }}
}});

document.getElementById('revealAll').addEventListener('click', async () => {{
  const d = await api({{reveal: 'all'}});
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = '';
  d.rows.forEach(r => tbody.appendChild(row(r)));
}});

document.getElementById('clearAll').addEventListener('click', async () => {{
  if (!confirm('Clear every mapping? This is the same as `omna forget` — it also resets your ' +
               'secret counters and encryption key. Every value masked again afterward gets a ' +
               'brand new token. This cannot be undone.')) return;
  await fetch('/omna/mappings/clear?k=' + encodeURIComponent(k), {{method: 'POST'}});
  load();
}});

load();
</script>
</body></html>"""
