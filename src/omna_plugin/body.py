"""Walk JSON request/response bodies, masking or restoring the human text.

Generic on purpose: Anthropic Messages, OpenAI chat completions and the OpenAI
Responses API all put text in nested dicts/lists. We mask every string value
except the ones that must stay byte-identical — signatures, thinking blocks,
base64 media, request settings, a message's or block's own identifiers, and the
names/types/schema words of a tool's definition — each skipped only at its own
place (finding 4), never by name anywhere. Anything that looks like a binary
blob is skipped too.
"""

from __future__ import annotations

import re

from . import receipts
from .engine import MaskingSession
from .style import TOKENS

# WHERE a field is skipped matters (security review 2026-11-11, finding 4).
# These names used to be skipped ANYWHERE in the body, so a real email under
# "id" or a key under "type" inside a tool call's input, a token in a tool's
# description and an MCP server's access token all reached the provider. Now
# each set applies only at its own place:
#
# Request settings — skipped at the top of the request only.
TOP_KEYS = frozenset({
    "model", "stream", "stop_sequences", "tool_choice", "service_tier", "anthropic_version",
    "output_config", "context_management", "container", "response_format", "modalities",
    "previous_response_id", "store", "include", "truncation", "parallel_tool_calls",
    "reasoning", "background",
    # NOT here: "prompt_cache_key" (often a user id or email) and "text"
    # (Responses output format + schema) — both were masked before finding 4.
})
# Structure of a message, a content block or a reply item: identifiers and
# byte-exact fields the API matches on. Skipped on messages and blocks, never
# inside a tool call's input (that is your data) or a tool's definition.
STRUCT_KEYS = frozenset({
    "id", "model", "type", "role", "tool_use_id", "tool_call_id", "call_id", "media_type",
    "stop_reason", "stop_sequence", "file_id",
    # must be byte-identical for the API to accept the request back
    "signature", "thinking", "redacted_thinking", "cache_control",
    # binary / opaque ("image_url": only its data: form is skipped — _skip_in)
    "b64_json", "encrypted_content",
})
# Inside a tool's DEFINITION (tools[], functions[], mcp_servers[]): what the
# API and the model match on stays; descriptions, defaults, examples, enum
# values, server addresses and access tokens are masked.
TOOLDEF_KEEP = frozenset({
    "name", "type", "required", "strict", "cache_control", "$schema", "$ref", "$id", "format",
    "additionalProperties", "server_label", "require_approval", "allowed_tools",
    "defer_loading", "id",
})
# A keep-word keeps a VALUE (a string, a list of names) — never an object: in
# a schema's "properties", "name" or "id" is a property whose description,
# enum and default are prose to mask (found by /security-review, 2026-11-12).
# "pattern" is not kept: a literal in it is masked like any other text.
# Kept for anything that imported it: every name skipped somewhere.
SKIP_KEYS = TOP_KEYS | STRUCT_KEYS

_MSG, _DATA, _TOOLDEF = "msg", "data", "tooldef"
# A field whose NAME says its value is a credential (finding 4).
_CRED_KEY = re.compile(r"(?i)(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth)")
_TOOLDEF_KEYS = frozenset({"tools", "functions", "mcp_servers"})

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
    if key in ("url", "image_url"):
        # Embedded picture bytes stay byte-identical; a web link is text, and
        # carries ?token=… often enough to be masked (it used to be skipped
        # whole — /security-review 2026-11-12).
        return isinstance(value, str) and value.startswith("data:")
    if key == "name":
        # A message's speaker is masked; a tool's or a function's name is an
        # identifier the API matches against the tool list.
        return "role" not in parent
    return False


# A field a site names as one of its own identifiers ("requestId", "trace_id",
# "session", "hash", "version"). In data that is not a prompt, its value is
# the site's, not yours: masking it as a phone or card number broke the
# site's request (architecture review, MASTER #178). Secrets and email
# addresses are still masked there; nothing changes in a prompt.
_ID_KEY_CAMEL = re.compile(r"[a-z0-9](?:Id|Ids|ID|Uuid|Hash|Nonce|Ts|Timestamp|Time|Version)$")
_ID_KEY_PLAIN = re.compile(
    r"(?:^|[_\-.])(?:ids?|uuid|guid|nonce|hash|sha\d*|checksum|crc|etag|trace|span|session|sid|cid|rid|"
    r"ts|timestamp|time|version|build|rev|seq|index|offset)$", re.I)
ONLY_IN_IDS = frozenset({"EMAIL"})


def is_id_key(key: str | None) -> bool:
    return bool(key) and bool(_ID_KEY_CAMEL.search(key) or _ID_KEY_PLAIN.search(key))


def _skip(parent: dict, key: str, value, mode: str, depth: int) -> bool:
    if mode == _DATA:
        return False
    if mode == _TOOLDEF:
        return key in TOOLDEF_KEEP and not isinstance(value, dict)
    if depth == 0 and key in TOP_KEYS:
        return True
    return key in STRUCT_KEYS or _skip_in(parent, key, value)


def _child_mode(parent: dict, key: str, mode: str) -> str:
    if mode != _MSG:
        return mode
    if key in _TOOLDEF_KEYS:
        return _TOOLDEF
    if key == "metadata" or (key == "input" and is_tool_call(parent)):
        return _DATA
    return _MSG


def _walk(obj, visit, mode: str = _MSG, key: str | None = None, depth: int = 0, in_tool: bool = False):
    """Visit every string that is someone's content; ``visit(s, key, in_tool)``
    returns its replacement. ``in_tool``: the string is part of a tool CALL
    (finding 2). One walker for masking and restoring, so whatever is masked
    can be put back."""
    if isinstance(obj, str):
        return obj if _is_blob(obj) else visit(obj, key, in_tool)
    if isinstance(obj, list):
        return [_walk(item, visit, mode, key, depth + 1, in_tool) for item in obj]
    if isinstance(obj, dict):
        here = in_tool or is_tool_call(obj)
        out = {}
        for k, v in obj.items():
            if _skip(obj, k, v, mode, depth):
                out[k] = v
            else:
                out[k] = _walk(v, visit, _child_mode(obj, k, mode), k, depth + 1, here or k in _TOOL_KEYS)
        return out
    return obj


def mask_body(session: MaskingSession, obj, style: str = TOKENS, careful: bool = False):
    """Return (masked_copy, counts, labels). ``obj`` is not modified.

    ``counts`` maps entity name -> occurrences and carries reserved keys that
    the receipt writer pops off: ``_secrets`` / ``_pii`` (totals by layer),
    ``_validated`` (catches a checksum actually proved), ``_layer_L1`` etc.
    and ``_finds`` (the masking engine's L6 events, grouped — #184).

    ``labels`` are the numbered token names minted for this body ("EMAIL_1"),
    whatever the style. Receipts count those, so the audit trail is the same
    under both styles even when the masked body carries no brackets at all.

    ``careful``: data that is not a prompt — a field named as the site's own
    identifier keeps everything but secrets and emails (``is_id_key``).
    """
    counts: dict[str, int] = {}
    labels: list[str] = []
    finds: list[list[dict]] = []

    c = counts

    def fn(s: str, key: str | None = None, _in_tool: bool = False) -> str:
        only = ONLY_IN_IDS if careful and is_id_key(key) else None
        r = session.mask_text(s, style=style, only=only)
        masked = r.masked
        if r.masked == s and key and _CRED_KEY.search(key) and s and not any(ch.isspace() for ch in s):
            # {"password": "S3cure-Horse-Battery-99"}: each value is masked on
            # its own, so the engine never saw the word that makes it a
            # password (finding 4). Ask again WITH its name, using the
            # engine's own rule (keyword + entropy floor), and keep the value.
            r2 = session.mask_text(f"{key}={s}", style=style, only=only)
            head = f"{key}="
            if r2.masked.startswith(head) and r2.masked[len(head):] != s:
                r, masked = r2, r2.masked[len(head):]   # never edit r2: the engine caches it
        labels.extend(r.labels)
        if r.finds:
            finds.append(r.finds)
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
        return masked

    masked = _walk(obj, fn)
    if finds:
        counts["_finds"] = receipts.merge_finds(*finds)  # type: ignore[assignment]
    return masked, counts, sorted(set(labels))


# Reply parts that are a TOOL CALL — something the agent will run or write
# (finding 2). Anthropic content blocks; OpenAI Responses output items (every
# "*_call": function_call, custom_tool_call, local_shell_call, mcp_call, …);
# OpenAI chat's ``tool_calls`` / legacy ``function_call``.
_TOOL_BLOCK_TYPES = frozenset({"tool_use", "server_tool_use", "mcp_tool_use"})
# Gemini writes a tool call as a part ``{"functionCall": {"name", "args"}}``.
_TOOL_KEYS = frozenset({"tool_calls", "function_call", "functionCall"})


def is_tool_call(obj: dict) -> bool:
    t = obj.get("type")
    return isinstance(t, str) and (t in _TOOL_BLOCK_TYPES or t.endswith("_call"))


def restore_body(session, obj, tools=None):
    """Return a copy with every reversible token replaced by its real value.

    ``tools``: the restorer for TOOL CALLS inside the reply (an
    ``engine.ToolView``) — secrets stay stand-ins there by default (finding
    2). None restores tool calls like any other text."""
    tools = tools or session
    return _walk(obj, lambda s, _key, in_tool: (tools if in_tool else session).restore_text(s))
