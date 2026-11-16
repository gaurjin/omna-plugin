"""Read the form the Gemini website sends its own calls in ("batchexecute"),
so that only what a person could have typed is masked.

Why: found live 2026-11-16 — every call gemini.google.com makes to
``/_/BardChatUi/data/batchexecute`` (list my chats, load a chat, settings) was
masked as one flat text. Google's own function names were read as people and
secrets (``MaZiqc``, ``K4WWud``), a chat's id as a secret, and the page's
anti-forgery token (``at=``) was edited on every call. None of that is data
sent to the AI (owner rule 2026-11-15).

The format: a form with two values. ``f.req`` is JSON —
``[[["<function name>", "<its arguments, JSON written as a string>", null,
"generic"]]]`` — and ``at`` is the page's anti-forgery token. Arguments are
lists without field names, so nothing says which string a person typed (a
chat's new name, a saved instruction). Each string is therefore handed to the
caller's ``visit`` on its own; the function names and ``at`` go as they are.
"""

from __future__ import annotations

import json
from typing import Callable
from urllib.parse import quote, unquote_plus

Visit = Callable[[str], str]

_REQ, _TOKEN = "f.req", "at"
_MAX_DEPTH = 64


def _nested(text: str):
    """The value of a string that is itself JSON (a list or an object), else None."""
    s = text.strip()
    if len(s) < 2 or s[0] not in "[{" or s[-1] not in "]}":
        return None
    try:
        obj = json.loads(s)
    except ValueError:
        return None
    return obj if isinstance(obj, (list, dict)) else None


def _walk(obj, visit: Visit, depth: int = 0):
    """``obj`` with every string passed through ``visit``; the very same
    object when nothing changed."""
    if depth > _MAX_DEPTH:
        raise ValueError("nested too deep")
    if isinstance(obj, str):
        inner = _nested(obj)
        if inner is None:
            return visit(obj)
        new = _walk(inner, visit, depth + 1)
        return obj if new is inner else json.dumps(new, ensure_ascii=False, separators=(",", ":"))
    if isinstance(obj, dict):
        out = {k: _walk(v, visit, depth + 1) for k, v in obj.items()}
        return obj if all(out[k] is obj[k] for k in obj) else out
    if isinstance(obj, list):
        # A call is [name, arguments-as-JSON, …]: the name is Google's own.
        is_call = len(obj) >= 2 and isinstance(obj[0], str) and isinstance(obj[1], str) and _nested(obj[1]) is not None
        out = [v if is_call and i == 0 else _walk(v, visit, depth + 1) for i, v in enumerate(obj)]
        return obj if all(a is b for a, b in zip(out, obj)) else out
    return obj


def rewrite_form(body: bytes, visit: Visit) -> bytes | None:
    """The form with every string a person could have typed passed through
    ``visit``. The very same object when nothing changed; None when the body
    is not this format (the caller handles it the way it did before)."""
    try:
        pairs = body.decode("utf-8").split("&")
    except UnicodeDecodeError:
        return None
    if not any(p.partition("=")[0] == _REQ for p in pairs):
        return None
    changed = False
    for i, pair in enumerate(pairs):
        key, eq, raw = pair.partition("=")
        if not eq or key == _TOKEN or not raw:
            continue
        value = unquote_plus(raw)
        if key == _REQ:
            try:
                obj = json.loads(value)
            except ValueError:
                return None
            new = _walk(obj, visit)
            if new is obj:
                continue
            value = json.dumps(new, ensure_ascii=False, separators=(",", ":"))
        else:
            new = visit(value)
            if new == value:
                continue
            value = new
        pairs[i] = key + "=" + quote(value, safe="")
        changed = True
    return "&".join(pairs).encode("utf-8") if changed else body
