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

# Keys whose values are never human prose, or must reach the upstream untouched.
SKIP_KEYS = frozenset(
    {
        # identity / config
        "id", "model", "type", "role", "name", "tool_use_id", "tool_call_id",
        "call_id", "media_type", "stop_reason", "stop_sequence", "stop_sequences",
        "url", "file_id", "service_tier", "anthropic_version", "stream",
        "tool_choice", "metadata", "output_config", "context_management",
        "mcp_servers", "container", "response_format", "modalities", "user",
        # must be byte-identical for the API to accept the request back
        "signature", "thinking", "redacted_thinking", "cache_control",
        # binary / opaque
        "data", "image_url", "b64_json", "encrypted_content",
        # tool definitions are schemas, not prose
        "tools", "functions", "input_schema", "parameters",
    }
)

# Long runs with no whitespace and only base64 characters: media, not prose.
_BLOB_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{256,}$")


def _is_blob(s: str) -> bool:
    return len(s) >= 256 and _BLOB_RE.match(s) is not None


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
            out[k] = _walk(v, fn, counts, k)
        return out
    return obj


def mask_body(session: MaskingSession, obj):
    """Return (masked_copy, counts). ``obj`` is not modified."""
    counts: dict[str, int] = {}

    def fn(s: str, c: dict[str, int]) -> str:
        r = session.mask_text(s)
        for k, n in r.counts.items():
            c[k] = c.get(k, 0) + n
        return r.masked

    return _walk(obj, fn, counts), counts


def restore_body(session: MaskingSession, obj):
    """Return a copy with every reversible token replaced by its real value."""

    def fn(s: str, _c) -> str:
        return session.restore_text(s)

    return _walk(obj, fn, {})
