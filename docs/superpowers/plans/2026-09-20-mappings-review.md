# Mappings Review Screen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this
> plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `/omna/mappings`, a token-gated local screen showing every PII value Omna has
masked — join the registry (what a value IS: kind, detection layer, checksum-validated, masking
style) against the receipts (what HAPPENED to it: times sent, last sent, which provider, which
app) — with search/filter/sort/pagination, per-row and reveal-all disclosure, and delete-one /
clear-all that correctly drops both the token AND the realistic-style fake.

**Architecture:** Three new pieces of state/behaviour on `MaskingSession` (per-mapping metadata,
a read-only row accessor, a delete method that cleans up every registry the value touches) feed a
new `mappings.py` module that joins those rows against `receipts.tail(0)`, with all real values
kept server-side and disclosed only on an explicit `?reveal=` request — never embedded in the base
page or JSON. Two new proxy routes reuse the existing `_dashboard_ok` token check (no second auth
scheme), plus a nav link from the dashboard and a `omna mappings` CLI command for parity with
`omna dashboard`.

**Tech Stack:** Python 3.12, Starlette, pytest + pytest-anyio, no new dependencies.

---

## Context already gathered (do not re-derive)

- `~/Developer/omna-workspace/docs/competitive/kiji-comparison.md` rows 46/62/79: Kiji's "Mapping
  Review" keeps real values in a reviewable UI; Omna's differentiator has always been that real
  values live in exactly ONE place (the encrypted registry) and are never duplicated into a log.
  This screen does NOT change that claim — it is a view onto the one place, not a second copy.
- `src/omna_plugin/engine.py` — `MaskingSession`: `_token_to_value` (bracketed token → real value,
  persisted, the one place tokens AND realistic-style rows both register their real value —
  `_rebuild` always calls `_stable_token` regardless of style), `_value_to_fake` /
  `_fake_to_value` (realistic-style fakes, persisted beside tokens), `_secret_token_to_value`
  (memory-only, NEVER persisted — secrets are already correctly absent from anything this screen
  reads). `_save_registry` / `_load_registry` read/write one JSON blob (sealed via `vault.py` when
  encrypted) with keys `tokens`, `counters`, `fakes`, `fake_salt`.
- `src/omna_plugin/receipts.py` — hash-chained, encrypted-at-rest, append-only. Each record already
  carries `tokens` (list of UNBRACKETED labels, e.g. `"EMAIL_3"`), `upstream`, `app`, `ts`, `door`,
  `style`. `receipts.tail(0)` returns every record. No real value is ever in a receipt — reused
  as-is, this is the join key for "how many times / when last / which provider / which app."
- `src/omna_plugin/dashboard.py` — the pattern to copy: zero external requests, all CSS/JS inline,
  short in-process cache (`_CACHE_TTL_SECONDS`) so a poll can't thrash the receipt log, a footer
  that states plainly what is and isn't recorded.
- `src/omna_plugin/proxy.py:188-226` — `_dashboard_ok(request)` is the ONE token check (query `?k=`
  or `Authorization: Bearer`, constant-time compare, backed by `config.dashboard_token()` /
  `~/.omna/dashboard.token`, #134). Reused as-is — do not add a second token file or scheme.
- `src/omna_plugin/style.py` — `TOKENS` / `REALISTIC`; `style_for_door` is the only place a door's
  style is decided. This plan does not touch that decision, only records which style was actually
  used when a given value was last rebuilt.
- `tests/test_proxy.py` — `env(tmp_path, monkeypatch)` fixture: sandboxes `OMNA_HOME` into
  `tmp_path`, wires a fake upstream, returns `(up, session, client)`. `tests/conftest.py` forces
  `OMNA_REGISTRY_ENCRYPTION=off` for the whole suite. Reuse both — never touch the real Keychain
  or the real `~/.omna` from a test.
- `tests/test_engine.py` — `home(tmp_path, monkeypatch)` fixture sandboxing `OMNA_HOME` for
  engine-only unit tests (no HTTP layer). New engine tests belong here, next to the existing
  registry/fake/secret tests.
- Backlog number: this ships as **#144** in `omna-workspace/MASTER.md` (checked live — #142 and
  #143 are the two most recent entries there; #144 is free).
- **The literal-token landmine (repo CLAUDE.md):** never type a full `[KIND_N]` bracketed literal
  in any file here — two adjacent string pieces instead (e.g. `"[EMAIL_" "3]"`), because a proxied
  Claude Code session restores full token literals into real values while writing the file. Code
  and test snippets in THIS plan document already follow that rule where a literal token appears in
  a string; apply it again when actually writing the files, not just when copying from here.

## File Structure

- Modify `src/omna_plugin/engine.py` — add per-mapping metadata capture, `registry_rows()`,
  `delete_mapping()`.
- Create `src/omna_plugin/mappings.py` — receipts join, snapshot/query, HTML + JSON rendering.
  Kept separate from `engine.py` (which must stay receipts-ignorant — it's the mail room's engine,
  not a reporting layer) and separate from `dashboard.py` (different screen, different data shape).
- Modify `src/omna_plugin/proxy.py` — four new routes, all behind `_dashboard_ok`.
- Modify `src/omna_plugin/dashboard.py` — one nav link (adjacent gap, same pass).
- Modify `src/omna_plugin/cli.py` — `omna mappings` command mirroring `cmd_dashboard`.
- Test: `tests/test_engine.py` — metadata capture, `registry_rows()`, `delete_mapping()` including
  the fake-cleanup and cache-invalidation guarantees.
- Test: `tests/test_mappings.py` (new) — receipts join, snapshot filtering/sort/paginate, HTML/JSON
  route behaviour, auth reuse, no-store headers, disclosure-on-demand, delete/clear routes.
- Modify `README.md` — one new section under "Commands" / near "Two masking styles".

---

### Task 1: Registry — per-mapping metadata (layer, validated, style, created)

**Files:**
- Modify: `src/omna_plugin/engine.py`
- Test: `tests/test_engine.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_engine.py`:

```python
def test_registry_rows_carries_layer_validated_style_and_created(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    rows = s.registry_rows()
    assert len(rows) == 1
    r = rows[0]
    assert r["label"] == "EMAIL_1"
    assert r["kind"] == "EMAIL"
    assert r["value"] == "john.smith@acme.com"
    assert r["layer"] in ("L1", "L2", "L3")  # whichever layer this build's engine used
    assert isinstance(r["validated"], bool)
    assert r["style"] == TOKENS
    assert r["created"]  # non-empty ISO timestamp


def test_registry_rows_records_the_style_actually_used_realistic(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=REALISTIC)
    rows = s.registry_rows()
    assert rows[0]["style"] == REALISTIC
    assert rows[0]["fake"]  # a fake was minted
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_engine.py -k registry_rows -v`
Expected: FAIL — `AttributeError: 'MaskingSession' object has no attribute 'registry_rows'`

- [ ] **Step 3: Add the metadata dict, capture it in `_rebuild`, persist it**

In `src/omna_plugin/engine.py`, add `import time` to the top-level imports (currently
`hashlib, json, os, re, threading` — `time` is not yet imported).

In `MaskingSession.__init__`, next to the other registry dicts (after
`self._fake_salt = b""`), add:

```python
        # Per-mapping metadata for the Mappings Review screen (#144): which
        # layer caught it, whether a checksum validated it, which style was
        # last used to write it, and when it was first seen. Keyed the same
        # way as `_value_to_fake` ("KIND\x00value") so all three registries
        # agree on identity. A row written before this existed has no entry
        # here — `registry_rows()` must report that honestly, never guess.
        self._meta: dict[str, dict] = {}
```

In `_load_registry`, after the `for key, fake in dict(data.get("fakes", {})).items():` block,
add:

```python
        self._meta = dict(data.get("meta", {}))
```

In `_save_registry`, add `"meta": self._meta` to the `payload` dict literal (alongside
`"tokens"`, `"counters"`, `"fakes"`, `"fake_salt"`).

In `_rebuild`, in the `else:` branch that handles non-secret spans (where `label =
self._stable_token(kind, core)` already runs), immediately after `labels.append(label[1:-1])`,
add:

```python
                meta_key = f"{kind}\x00{core}"
                meta = self._meta.setdefault(meta_key, {"created": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
                meta["layer"] = sp.get("layer") or meta.get("layer") or "?"
                meta["validated"] = bool(sp.get("validated"))
                meta["style"] = style
```

`_rebuild`'s `changed` return value is computed by comparing a `(len(_token_to_value),
len(_fake_to_value), _fake_salt)` snapshot before/after the loop — a metadata-only update on an
ALREADY-minted token (same value seen again under a different style) would not move any of those
three lengths, so the registry wouldn't be saved and the style/layer update would be lost on
restart. Fix this by tracking meta writes directly. Change the snapshot line and the return line:

```python
        changed_before = (len(self._token_to_value), len(self._fake_to_value), self._fake_salt)
        meta_touched = False
```

(add `meta_touched = False` right after the existing `changed_before` line), then inside the
`else:` branch, change the three-line meta block above to set the flag too:

```python
                meta_key = f"{kind}\x00{core}"
                meta = self._meta.setdefault(meta_key, {"created": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
                meta["layer"] = sp.get("layer") or meta.get("layer") or "?"
                meta["validated"] = bool(sp.get("validated"))
                meta["style"] = style
                meta_touched = True
```

and change the final return line from:

```python
        now = (len(self._token_to_value), len(self._fake_to_value), self._fake_salt)
        return "".join(out), labels, now != changed_before
```

to:

```python
        now = (len(self._token_to_value), len(self._fake_to_value), self._fake_salt)
        return "".join(out), labels, now != changed_before or meta_touched
```

- [ ] **Step 4: Add `registry_rows()`**

Add this method to `MaskingSession`, near `registry_size`/`at_rest` (the other read-only
reporting properties):

```python
    def registry_rows(self) -> list[dict]:
        """One row per PII mapping currently held (#144 Mappings Review).

        Secrets never appear here — they never entered `_token_to_value` in
        the first place (memory-only, see the module docstring). A row
        written before per-mapping metadata existed has `layer`/`validated`/
        `style` all `None` — report that honestly rather than guessing.
        """
        with self._lock:
            rows = []
            for token, value in self._token_to_value.items():
                m = TOKEN_RE.fullmatch(token)
                if not m:
                    continue
                kind = m.group(1)
                key = f"{kind}\x00{value}"
                meta = self._meta.get(key, {})
                rows.append({
                    "label": token[1:-1],
                    "kind": kind,
                    "value": value,
                    "fake": self._value_to_fake.get(key),
                    "layer": meta.get("layer"),
                    "validated": bool(meta.get("validated")),
                    "style": meta.get("style"),
                    "created": meta.get("created"),
                })
            return rows
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_engine.py -k registry_rows -v`
Expected: PASS

- [ ] **Step 6: Run the full engine suite (regression check on the `changed` logic edit)**

Run: `.venv/bin/pytest tests/test_engine.py -v`
Expected: all PASS — the `changed`/`meta_touched` edit must not break any existing
save/restart/fake test.

- [ ] **Step 7: Commit**

```bash
git add src/omna_plugin/engine.py tests/test_engine.py
git commit -m "engine: per-mapping metadata (layer, validated, style, created) + registry_rows()"
```

---

### Task 2: Registry — `delete_mapping()` cleans up token, fake, and cache

**Files:**
- Modify: `src/omna_plugin/engine.py`
- Test: `tests/test_engine.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_engine.py`:

```python
def test_delete_mapping_removes_the_token_and_the_value_no_longer_restores(home):
    s = MaskingSession()
    r = s.mask_text("email john.smith@acme.com", style=TOKENS)
    assert s.delete_mapping("EMAIL_1") is True
    assert s.registry_rows() == []
    assert s.restore_text(r.masked) == r.masked  # the token is now unrecognised, not restored


def test_delete_mapping_of_a_realistic_row_also_drops_the_fake(home):
    s = MaskingSession()
    r = s.mask_text("email john.smith@acme.com", style=REALISTIC)
    fake = s.registry_rows()[0]["fake"]
    assert fake and fake in r.masked
    assert s.delete_mapping("EMAIL_1") is True
    # the fake must not resolve back to the real value any more
    assert s.restore_text(fake) == fake


def test_delete_mapping_of_an_unknown_label_returns_false(home):
    s = MaskingSession()
    assert s.delete_mapping("EMAIL_99") is False


def test_the_same_real_value_gets_a_brand_new_token_after_delete(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    s.delete_mapping("EMAIL_1")
    r2 = s.mask_text("email john.smith@acme.com", style=TOKENS)
    # counter is NOT reused — the old label must never come back to life
    assert "[EMAIL_" "1]" not in r2.masked
    assert "[EMAIL_" "2]" in r2.masked


def test_delete_mapping_persists_across_a_restart(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    s.delete_mapping("EMAIL_1")
    assert MaskingSession().registry_rows() == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_engine.py -k delete_mapping -v`
Expected: FAIL — `AttributeError: 'MaskingSession' object has no attribute 'delete_mapping'`

- [ ] **Step 3: Implement `delete_mapping()`**

Add to `MaskingSession`, after `registry_rows()`:

```python
    def delete_mapping(self, label: str) -> bool:
        """Forget one PII mapping (#144). Removes the token, its real value,
        its metadata, AND its realistic-style fake if it has one — dropping
        only the token would leave the fake still resolving the "deleted"
        value on every future restore, which is worse than not deleting at
        all. The counter is never reused, so the label a person just deleted
        can never silently come back: the same real value gets a brand new
        token/fake on its next occurrence.
        """
        token = f"[{label}]"
        with self._lock:
            value = self._token_to_value.pop(token, None)
            if value is None:
                return False
            m = TOKEN_RE.fullmatch(token)
            kind = m.group(1) if m else ""
            key = f"{kind}\x00{value}"
            self._value_to_token.pop(key, None)
            self._real_values.discard(value)
            self._meta.pop(key, None)
            fake = self._value_to_fake.pop(key, None)
            if fake is not None:
                self._fake_to_value.pop(fake, None)
                self._fake_prefixes = set()
                self._max_fake_len = 0
                for f in self._fake_to_value:
                    self._max_fake_len = max(self._max_fake_len, len(f))
                    for i in range(1, len(f)):
                        self._fake_prefixes.add(f[:i])
                self._restore_re = None
            # A cached MaskResult for identical future text would otherwise
            # hand back the just-deleted token/fake (see `allow()`, same fix).
            self._cache.clear()
            self._save_registry()
            return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_engine.py -k delete_mapping -v`
Expected: PASS

- [ ] **Step 5: Break the guard, watch it fail, restore it (Lesson #88 — a test never watched red proves nothing)**

Temporarily comment out the `fake is not None:` block's body inside `delete_mapping` (leave the
`if fake is not None:` line, `pass` the body) and re-run
`test_delete_mapping_of_a_realistic_row_also_drops_the_fake`. Confirm it now FAILS with the fake
still restoring to the real value. Then restore the real body and re-run to confirm green again.
Note the result in the final report — do not skip this step even though it feels redundant.

- [ ] **Step 6: Run the full engine suite**

Run: `.venv/bin/pytest tests/test_engine.py -v`
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add src/omna_plugin/engine.py tests/test_engine.py
git commit -m "engine: delete_mapping() drops the token, its fake, and the cache together"
```

---

### Task 3: `mappings.py` — join registry rows against receipts usage

**Files:**
- Create: `src/omna_plugin/mappings.py`
- Test: `tests/test_mappings.py` (new)

- [ ] **Step 1: Write the failing test**

Create `tests/test_mappings.py`:

```python
"""Tests for the Mappings Review screen (#144): the registry/receipts join,
query (search/filter/sort/paginate), and disclosure-on-demand rules."""

from __future__ import annotations

import pytest

from omna_plugin import mappings, receipts
from omna_plugin.engine import MaskingSession
from omna_plugin.style import REALISTIC, TOKENS


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def test_snapshot_joins_times_sent_last_sent_providers_and_apps(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    receipts.append({"tokens": ["EMAIL_1"], "upstream": "api.anthropic.com", "app": "Claude Code",
                      "ts": "2026-09-20T10:00:00+0000"})
    receipts.append({"tokens": ["EMAIL_1"], "upstream": "api.openai.com", "app": "aider",
                      "ts": "2026-09-20T11:00:00+0000"})
    mappings.invalidate_cache()
    rows = mappings.snapshot(s)
    assert len(rows) == 1
    r = rows[0]
    assert r["label"] == "EMAIL_1"
    assert r["times_sent"] == 2
    assert r["last_sent"] == "2026-09-20T11:00:00+0000"
    assert r["providers"] == ["api.anthropic.com", "api.openai.com"]
    assert r["apps"] == ["Claude Code", "aider"]


def test_snapshot_row_with_no_receipts_yet_shows_zero_not_missing(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    mappings.invalidate_cache()
    r = mappings.snapshot(s)[0]
    assert r["times_sent"] == 0
    assert r["last_sent"] is None
    assert r["providers"] == []
    assert r["apps"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_mappings.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'omna_plugin.mappings'`

- [ ] **Step 3: Write `mappings.py` (join + snapshot)**

Create `src/omna_plugin/mappings.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_mappings.py -v`
Expected: PASS

- [ ] **Step 5: Add and run the disclosure/query tests**

Append to `tests/test_mappings.py`:

```python
def test_reveal_is_off_by_default(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s)
    assert d["rows"][0]["value"] is None


def test_reveal_one_label_discloses_only_that_row(home):
    s = MaskingSession()
    s.mask_text("email a@x.com", style=TOKENS)
    s.mask_text("email b@x.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s, reveal="EMAIL_1")
    by_label = {r["label"]: r for r in d["rows"]}
    assert by_label["EMAIL_1"]["value"] == "a@x.com"
    assert by_label["EMAIL_2"]["value"] is None


def test_reveal_all_discloses_every_row_on_the_page(home):
    s = MaskingSession()
    s.mask_text("email a@x.com", style=TOKENS)
    s.mask_text("email b@x.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s, reveal="all")
    assert all(r["value"] for r in d["rows"])


def test_filter_by_kind(home):
    s = MaskingSession()
    s.mask_text("email a@x.com and key AKIAIOSFODNN7EXAMPLE", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s, kind="EMAIL")
    assert all(r["kind"] == "EMAIL" for r in d["rows"])
    assert "EMAIL" in d["kinds"]


def test_search_by_label(home):
    s = MaskingSession()
    s.mask_text("email a@x.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s, q="email_1")
    assert len(d["rows"]) == 1


def test_pagination(home):
    s = MaskingSession()
    for i in range(5):
        s.mask_text(f"email person{i}@x.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s, per_page=2, page=1)
    assert len(d["rows"]) == 2 and d["total"] == 5
    d2 = mappings.snapshot(s, per_page=2, page=3)
    assert len(d2["rows"]) == 1
```

Run: `.venv/bin/pytest tests/test_mappings.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/omna_plugin/mappings.py tests/test_mappings.py
git commit -m "mappings: join registry against receipts, query + disclosure-on-demand"
```

---

### Task 4: HTML + JSON rendering

**Files:**
- Modify: `src/omna_plugin/mappings.py`
- Test: `tests/test_mappings.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_mappings.py`:

```python
import json as _json


def test_render_page_never_embeds_a_real_value(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s)
    page = mappings.render(d)
    assert "john.smith@acme.com" not in page
    for bad in ("http://", "https://", "cdn.", "<script src"):
        assert bad not in page


def test_render_page_explains_the_empty_state(home):
    s = MaskingSession()
    d = mappings.snapshot(s)
    page = mappings.render(d)
    assert "hasn" in page.lower() or "no" in page.lower()


def test_render_page_explains_secrets_are_never_shown_here(home):
    s = MaskingSession()
    d = mappings.snapshot(s)
    page = mappings.render(d)
    assert "secret" in page.lower()


def test_render_json_round_trips(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s)
    parsed = _json.loads(mappings.render_json(d))
    assert parsed["total"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_mappings.py -k render -v`
Expected: FAIL — `AttributeError: module 'omna_plugin.mappings' has no attribute 'render'`

- [ ] **Step 3: Implement `render()` and `render_json()`**

Append to `src/omna_plugin/mappings.py`:

```python
def render_json(d: dict) -> str:
    import json
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_mappings.py -v`
Expected: PASS (full file)

- [ ] **Step 5: Commit**

```bash
git add src/omna_plugin/mappings.py tests/test_mappings.py
git commit -m "mappings: render the review page (no embedded values) + JSON"
```

---

### Task 5: Wire the routes into `proxy.py`

**Files:**
- Modify: `src/omna_plugin/proxy.py`
- Test: `tests/test_mappings.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_mappings.py`:

```python
import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from omna_plugin import config
from omna_plugin.proxy import create_app


class _Upstream:
    def __init__(self):
        self.app = Starlette(routes=[Route("/v1/messages", self._ok, methods=["POST"])])

    async def _ok(self, request: Request):
        return JSONResponse({"id": "m1", "content": []})


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    up = _Upstream()
    session = MaskingSession()
    up_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app))
    app = create_app(session, anthropic_upstream="http://anthropic.test",
                      openai_upstream="http://openai.test", client=up_client)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://omna.local")
    return session, client


@pytest.mark.anyio
async def test_mappings_page_and_json_require_the_dashboard_token(app_env):
    session, client = app_env
    for path in ("/omna/mappings", "/omna/mappings.json"):
        r = await client.get(path)
        assert r.status_code == 401, path


@pytest.mark.anyio
async def test_mappings_page_and_json_open_with_the_dashboard_token(app_env):
    session, client = app_env
    session.mask_text("email john.smith@acme.com", style=TOKENS)
    k = config.dashboard_token(create=True)
    r = await client.get(f"/omna/mappings?k={k}")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    j = await client.get(f"/omna/mappings.json?k={k}")
    assert j.status_code == 200
    body = j.json()
    assert body["total"] == 1 and body["rows"][0]["value"] is None


@pytest.mark.anyio
async def test_mappings_routes_send_no_store_cache_headers(app_env):
    session, client = app_env
    k = config.dashboard_token(create=True)
    for path in (f"/omna/mappings?k={k}", f"/omna/mappings.json?k={k}"):
        r = await client.get(path)
        assert "no-store" in r.headers.get("cache-control", "")


@pytest.mark.anyio
async def test_mappings_delete_requires_token_and_removes_the_row(app_env):
    session, client = app_env
    session.mask_text("email john.smith@acme.com", style=TOKENS)
    r = await client.post("/omna/mappings/delete", json={"label": "EMAIL_1"})
    assert r.status_code == 401
    k = config.dashboard_token(create=True)
    r = await client.post(f"/omna/mappings/delete?k={k}", json={"label": "EMAIL_1"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert session.registry_rows() == []


@pytest.mark.anyio
async def test_mappings_clear_wipes_everything(app_env):
    session, client = app_env
    session.mask_text("email john.smith@acme.com", style=TOKENS)
    k = config.dashboard_token(create=True)
    r = await client.post(f"/omna/mappings/clear?k={k}")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert session.registry_rows() == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_mappings.py -k "mappings_page or mappings_routes or mappings_delete or mappings_clear" -v`
Expected: FAIL — 404s (routes don't exist yet)

- [ ] **Step 3: Add the routes**

In `src/omna_plugin/proxy.py`, add the import near the top (alongside the existing `from . import
config, crashlog, receipts`):

```python
from . import config, crashlog, mappings, receipts
```

After the existing `dashboard_json` function (around line 225, right before `async def pac`), add:

```python
    _NO_STORE = {"cache-control": "no-store"}

    async def mappings_page(request: Request) -> Response:
        if not _dashboard_ok(request):
            return _unauthorised()
        return Response(mappings.render(mappings.snapshot(session)), media_type="text/html; charset=utf-8",
                         headers=_NO_STORE)

    async def mappings_json(request: Request) -> Response:
        if not _dashboard_ok(request):
            return _unauthorised()
        q = request.query_params
        d = mappings.snapshot(
            session,
            q=q.get("q", ""), kind=q.get("kind", ""),
            sort=q.get("sort", "created"), dir=q.get("dir", "desc"),
            page=int(q.get("page", "1") or "1"), per_page=int(q.get("per_page", "50") or "50"),
            reveal=q.get("reveal", ""),
        )
        return JSONResponse(d, headers=_NO_STORE)

    async def mappings_delete(request: Request) -> Response:
        if not _dashboard_ok(request):
            return _unauthorised()
        try:
            body = await request.json()
        except ValueError:
            body = {}
        label = str((body or {}).get("label") or "")
        ok = bool(label) and session.delete_mapping(label)
        return JSONResponse({"ok": ok}, headers=_NO_STORE)

    async def mappings_clear(request: Request) -> Response:
        if not _dashboard_ok(request):
            return _unauthorised()
        session.forget()
        mappings.invalidate_cache()
        return JSONResponse({"ok": True}, headers=_NO_STORE)
```

In the `routes=[` list inside `create_app` (where `Route("/omna/dashboard", ...)` and
`Route("/omna/dashboard.json", ...)` are registered), add, right after those two:

```python
            Route("/omna/mappings", mappings_page, methods=["GET"]),
            Route("/omna/mappings.json", mappings_json, methods=["GET"]),
            Route("/omna/mappings/delete", mappings_delete, methods=["POST"]),
            Route("/omna/mappings/clear", mappings_clear, methods=["POST"]),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_mappings.py -v`
Expected: all PASS

- [ ] **Step 5: Run the whole suite (regression check on the shared `proxy.py` edit)**

Run: `.venv/bin/pytest -q`
Expected: all PASS, no new failures in `test_proxy.py` or elsewhere.

- [ ] **Step 6: Commit**

```bash
git add src/omna_plugin/proxy.py tests/test_mappings.py
git commit -m "proxy: wire the mappings review routes behind the existing dashboard token"
```

---

### Task 6: Dashboard nav link + `omna mappings` CLI command

**Files:**
- Modify: `src/omna_plugin/dashboard.py`
- Modify: `src/omna_plugin/cli.py`
- Test: `tests/test_proxy.py`, `tests/test_cli.py`

- [ ] **Step 1: Write the failing test for the nav link**

Append to `tests/test_proxy.py` (near `test_dashboard_serves_html_and_json`):

```python
@pytest.mark.anyio
async def test_dashboard_links_to_the_mappings_review_screen(env):
    from omna_plugin import config

    up, session, client = env
    k = config.dashboard_token(create=True)
    r = await client.get(f"/omna/dashboard?k={k}")
    assert "/omna/mappings" in r.text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_proxy.py -k links_to_the_mappings -v`
Expected: FAIL

- [ ] **Step 3: Add the link**

In `src/omna_plugin/dashboard.py`, in `render()`, change the `<header>` line from:

```python
<header><h1>Omna</h1><span class="live"><span class="dot"></span>live</span></header>
```

to:

```python
<header><h1>Omna</h1><span class="live"><span class="dot"></span>live</span>
<a href="/omna/mappings" style="font-size:12px;color:var(--muted)">review mappings →</a></header>
```

(The link is relative and same-origin, so the caller's own `?k=` isn't needed here — the mappings
page's own auth applies when it's opened, same as any other same-site link.)

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_proxy.py -k links_to_the_mappings -v`
Expected: PASS

- [ ] **Step 5: Add `omna mappings` CLI command**

Read `src/omna_plugin/cli.py:652-667` (`cmd_dashboard`) and the argparse wiring right after it
(`s = sub.add_parser("dashboard", ...)`). Add, immediately after `cmd_dashboard`:

```python
def cmd_mappings(a) -> int:
    """Open the Mappings Review screen in the browser — every value Omna has
    masked, real values hidden until clicked. Same token as the dashboard."""
    import webbrowser

    if not _health(a.port):
        print(f"omna: the proxy isn't running, so there's nothing to show yet.", file=sys.stderr)
        print("  start it with `omna start -d`, then run this again.", file=sys.stderr)
        return 1
    url = f"{config.base_url(a.port)}/omna/mappings?k={config.dashboard_token()}"
    print(f"omna: opening the mappings review screen on {config.base_url(a.port)}")
    if not webbrowser.open(url):
        print(f"  (couldn't open a browser — paste this in yourself: {url})")
    return 0
```

Find where `s = sub.add_parser("dashboard", ...)` registers the `dashboard` subcommand and add
right after it:

```python
    s = sub.add_parser("mappings", help="open the mappings review screen in your browser")
    add_port(s); s.set_defaults(fn=cmd_mappings)
```

- [ ] **Step 6: Write and run a CLI test**

Check `tests/test_cli.py` for how `cmd_dashboard` is tested (grep `cmd_dashboard` there) and add a
matching test for `cmd_mappings` following the exact same pattern (same fixtures, same
`webbrowser.open` monkeypatch approach) — read that existing test first and mirror its structure
exactly rather than guessing the fixture names.

Run: `.venv/bin/pytest tests/test_cli.py -k mappings -v`
Expected: PASS

- [ ] **Step 7: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: all PASS

- [ ] **Step 8: Commit**

```bash
git add src/omna_plugin/dashboard.py src/omna_plugin/cli.py tests/test_proxy.py tests/test_cli.py
git commit -m "dashboard: link to mappings review; cli: omna mappings command"
```

---

### Task 7: Live verification (sandboxed — never the owner's real `~/.omna`)

**Files:** none (verification only)

- [ ] **Step 1: Start a sandboxed daemon on a spare port**

```bash
export OMNA_HOME=$(mktemp -d)
.venv/bin/omna start -d --port 7799
```

- [ ] **Step 2: Mask something real through the running proxy so a mapping exists**

```bash
curl -s http://127.0.0.1:7799/v1/messages \
  -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' -H 'x-api-key: test' \
  -d '{"model":"claude-3-5-sonnet-latest","max_tokens":16,"messages":[{"role":"user","content":"email john.smith@acme.com"}]}' \
  > /dev/null  # expected to fail reaching the real Anthropic API with a fake key — that's fine, masking still ran before the forward
```

If that 401s on the upstream (expected, the API key is fake), confirm the mapping was still
recorded despite the upstream failure:

```bash
cat "$OMNA_HOME/registry.json"   # should show one EMAIL entry, plaintext since OMNA_HOME is a fresh temp dir with no Keychain entry yet unless one already exists — either is fine, just confirm ONE row exists
```

- [ ] **Step 3: Open the mappings screen and confirm it loads**

```bash
TOKEN=$(cat "$OMNA_HOME/dashboard.token")
curl -s "http://127.0.0.1:7799/omna/mappings.json?k=$TOKEN" | python3 -m json.tool
```

Expected: JSON with `"total": 1`, the row's `"value"` is `null` (hidden by default).

- [ ] **Step 4: Confirm reveal-by-label returns the real value, and delete removes it**

```bash
curl -s "http://127.0.0.1:7799/omna/mappings.json?k=$TOKEN&reveal=EMAIL_1" | python3 -m json.tool
curl -s -X POST "http://127.0.0.1:7799/omna/mappings/delete?k=$TOKEN" \
  -H 'content-type: application/json' -d '{"label":"EMAIL_1"}'
curl -s "http://127.0.0.1:7799/omna/mappings.json?k=$TOKEN" | python3 -m json.tool  # total: 0
```

- [ ] **Step 5: Stop the sandboxed daemon and confirm no real state was touched**

```bash
.venv/bin/omna stop --port 7799
unset OMNA_HOME
echo "confirm this did NOT create/modify ~/.omna:"
ls -la ~/.omna 2>/dev/null | head -3   # compare mtimes against before this task started
```

- [ ] **Step 6: Record the result**

Note in the final report whether each of steps 1-5 produced the expected output, verbatim, not
just "looks fine."

---

### Task 8: Docs

**Files:**
- Modify: `README.md`
- Modify: `~/Developer/omna-workspace/MASTER.md` (different repo — separate commit there)

- [ ] **Step 1: Add a README section**

In `README.md`, find the `## Commands` section (around line 135) and add `mappings` to the
command list alongside `dashboard`. Also add a short new subsection right after "## Two masking
styles..." (around line 244-306) titled `## Reviewing what was masked`, explaining: what the
screen shows (join of registry + receipts), that it is token-gated behind the same dashboard
token, that values are hidden by default and disclosed only on click, and that delete-one /
clear-all exist and what each does (clear-all == `omna forget`). Follow the file's existing prose
style (short paragraphs, a code block showing the command).

- [ ] **Step 2: Add the omna-workspace MASTER.md entry**

In `~/Developer/omna-workspace/MASTER.md`, add a new row using the same table format as the
existing `#143` row (checked live 2026-09-20 — `#144` is the next free number):

```
| 144 | _(opened and shipped 2026-09-20)_ **Mappings Review screen in the plugin** — `omna
mappings` / `/omna/mappings`, behind the existing dashboard token (#134, no second auth scheme).
Matches Kiji's four columns (Entity Type / Original / Masked / Date) plus delete-one and
clear-all, then goes past them: joins the registry against the receipts so each row also shows
which layer caught it, whether a checksum validated it, which masking style it was written in (a
pre-#142 row says so honestly instead of guessing "tokens"), how many times it was sent, when
last, and to which provider/app. Real values are never embedded in the page or the default JSON —
disclosed only per-row or via "reveal all" on explicit request, hidden by default. Secrets are
never in the registry and the page says so. Delete removes the token AND its realistic-style fake
together (a fake alone would keep resolving a "deleted" value); the same real value gets a brand
new token/fake on its next occurrence. | Medium | Shipped |
```

- [ ] **Step 3: Commit both**

In `omna-plugin`:
```bash
git add README.md
git commit -m "docs: document the mappings review screen"
```

In `omna-workspace`:
```bash
cd ~/Developer/omna-workspace
git add MASTER.md
git commit -m "MASTER: #144 mappings review screen shipped in the plugin"
```

- [ ] **Step 4: Push both repos to main** (release discipline for this task: commit + push to
  main only — no version bump, no tag, no GitHub release, no `uv publish`, no cask rebuild, no new
  repository)

```bash
cd ~/Developer/omna-plugin && git push origin main
cd ~/Developer/omna-workspace && git push origin main
```

---

## Self-Review Notes (from the plan author, before handing this off)

- **Spec coverage:** four base columns (Task 3/4 row shape) ✓; layer/validated/times/last/
  providers/app/style (Task 1 + Task 3 join) ✓; honest "unknown" for pre-style rows (Task 1's
  `meta.get("style")` defaults `None`, Task 4's `render()` JS shows "unknown (masked before this
  was recorded)") ✓; secrets excluded + explained (Task 1 `registry_rows()` never touches
  `_secret_token_to_value`; Task 4 footer line) ✓; search/filter/sort/paginate (Task 3 `snapshot`
  params) ✓; explicit empty state (Task 4 `render()` `body_note`) ✓; dashboard token reuse, no
  second scheme (Task 5 reuses `_dashboard_ok`) ✓; values never logged/receipted/crash-reported
  (nothing in this plan writes a real value to `receipts.append`, `crashlog`, or any `print`) ✓;
  no external network/fonts/scripts (Task 4 inline CSS/JS, same-origin fetches only) ✓; no-store
  headers (Task 5 `_NO_STORE`) ✓; hidden-by-default/reveal-per-row/reveal-all (Task 3 `reveal`
  param, Task 4 JS) ✓; delete via `MaskingSession`, never the file directly (Task 2) ✓; delete
  also drops the fake (Task 2, tested + guard-break drill) ✓; "gets a new token/fake next time"
  said in the UI (Task 4 confirm dialogs) ✓; two-piece token literals in this plan's own code
  samples where a bracketed literal appears (Task 2's test) ✓; release discipline — commit+push
  only (Task 8 Step 4) ✓.
- **Placeholder scan:** none found — every step has real code or an exact command.
- **Type consistency:** `label` (unbracketed, e.g. `"EMAIL_1"`) is the identifier used consistently
  across `registry_rows()`, `delete_mapping(label)`, `mappings.snapshot(..., reveal=label)`, the
  JSON rows' `"label"` key, and the JS `data-label` attributes — never mixed with the bracketed
  `token` form except inside `engine.py` itself where `TOKEN_RE`/`_token_to_value` require it.
