"""Walk JSON request/response bodies, masking or restoring the human text.

Generic on purpose: Anthropic Messages, OpenAI chat completions and the OpenAI
Responses API all put text in nested dicts/lists. We mask every string value
except the ones that must stay byte-identical (signatures, thinking blocks,
base64 media, tool schemas, config fields) and skip anything that looks like a
binary blob.
"""

from __future__ import annotations

import re

from .engine import MaskingSession
from .style import TOKENS

# Keys whose values are never human prose, or must reach the upstream untouched.
SKIP_KEYS = frozenset(
    {
        # identity / config
        "id", "model", "type", "role", "tool_use_id", "tool_call_id",
        "call_id", "media_type", "stop_reason", "stop_sequence", "stop_sequences",
        "file_id", "service_tier", "anthropic_version", "stream",
        "tool_choice", "output_config", "context_management",
        "mcp_servers", "container", "response_format", "modalities",
        # must be byte-identical for the API to accept the request back
        "signature", "thinking", "redacted_thinking", "cache_control",
        # binary / opaque
        "image_url", "b64_json", "encrypted_content",
        # tool definitions are schemas, not prose
        "tools", "functions", "input_schema", "parameters",
    }
)

# Long runs with no whitespace and only base64 characters: media, not prose.
_BLOB_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{256,}$")


def _is_blob(s: str) -> bool:
    return len(s) >= 256 and _BLOB_RE.match(s) is not None


def _skip_in(parent: dict, key: str, value) -> bool:
    """Keys whose meaning depends on the object they sit in. They used to be
    skipped everywhere, so text under them never got masked (architecture
    review, MASTER #177): an Anthropic text document keeps its words in
    ``data``, a link carries ``?token=ghp_…`` in ``url``, OpenAI's ``user`` is
    often an email, and a chat message's ``name`` is the person speaking."""
    if key == "data":
        # Media and file bytes stay byte-identical; a text document, or an
        # object a chat site wraps its message in, is prose to be masked.
        if not isinstance(value, str) or parent.get("type") == "text":
            return False
        media = str(parent.get("media_type") or parent.get("mime_type") or "")
        return parent.get("type") in ("base64", "image", "file", "input_image") or (
            bool(media) and not media.startswith("text/"))
    if key == "url":
        return isinstance(value, str) and value.startswith("data:")
    if key == "name":
        # A message's speaker is masked; a tool's or a function's name is an
        # identifier the API matches against the tool list.
        return "role" not in parent
    return False


def _walk(obj, fn, counts: dict[str, int], key: str | None = None):
    if isinstance(obj, str):
        if key in SKIP_KEYS or _is_blob(obj):
            return obj
        return fn(obj, counts)
    if isinstance(obj, list):
        if key in SKIP_KEYS:
            return obj
        return [_walk(item, fn, counts, key) for item in obj]
    if isinstance(obj, dict):
        if key in SKIP_KEYS:
            return obj
        out = {}
        for k, v in obj.items():
            out[k] = v if _skip_in(obj, k, v) else _walk(v, fn, counts, k)
        return out
    return obj


def mask_body(session: MaskingSession, obj, style: str = TOKENS):
    """Return (masked_copy, counts, labels). ``obj`` is not modified.

    ``counts`` maps entity name -> occurrences and carries reserved keys that
    the receipt writer pops off: ``_secrets`` / ``_pii`` (totals by layer),
    ``_validated`` (catches a checksum actually proved) and ``_layer_L1`` etc.

    ``labels`` are the numbered token names minted for this body ("EMAIL_1"),
    whatever the style. Receipts count those, so the audit trail is the same
    under both styles even when the masked body carries no brackets at all.
    """
    counts: dict[str, int] = {}
    labels: list[str] = []

    def fn(s: str, c: dict[str, int]) -> str:
        r = session.mask_text(s, style=style)
        labels.extend(r.labels)
        for k, n in r.counts.items():
            c[k] = c.get(k, 0) + n
        if r.secrets:
            c["_secrets"] = c.get("_secrets", 0) + r.secrets
        if r.pii:
            c["_pii"] = c.get("_pii", 0) + r.pii
        if r.validated:
            c["_validated"] = c.get("_validated", 0) + r.validated
        for layer, n in r.by_layer.items():
            k = f"_layer_{layer}"
            c[k] = c.get(k, 0) + n
        return r.masked

    return _walk(obj, fn, counts), counts, sorted(set(labels))


def restore_body(session: MaskingSession, obj):
    """Return a copy with every reversible token replaced by its real value."""

    def fn(s: str, _c) -> str:
        return session.restore_text(s)

    return _walk(obj, fn, {})
