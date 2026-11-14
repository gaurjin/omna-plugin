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

import base64
import binascii
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
    "context_management", "container", "modalities",
    "previous_response_id", "store", "include", "truncation", "parallel_tool_calls",
    "reasoning", "background",
    # NOT here: "prompt_cache_key" (often a user id or email); and the output
    # SCHEMAS — "text" (Responses), "response_format" (OpenAI chat),
    # "output_config" (Anthropic) — read like a tool definition below.
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
# (``SKIP_KEYS`` — "skip these names anywhere" — is gone: security review
# 2026-11-11, delete list.)
# The STRUCT_KEYS that hold an IDENTIFIER (one word, no spaces). On an AI
# company's API that is all they ever hold. On a chat website the same names
# can hold a person's text ({"type": "my email is …"}), and it went out as it
# was. So an identifier key is skipped only while its value still looks like
# an identifier: text with a space in it, or an "@", is masked like any other.
_IDENT_KEYS = frozenset({"id", "model", "type", "role", "tool_use_id", "tool_call_id", "call_id", "media_type",
                         "stop_reason", "stop_sequence", "file_id"})


def _looks_like_text(value) -> bool:
    return isinstance(value, str) and ("@" in value or any(ch.isspace() for ch in value.strip()))

_MSG, _DATA, _TOOLDEF = "msg", "data", "tooldef"
# A field whose NAME says its value is a credential (finding 4).
_CRED_KEY = re.compile(r"(?i)(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth)")
_TOOLDEF_KEYS = frozenset({"tools", "functions", "mcp_servers"})
# A request's output schema: names, types and "strict" stay, its descriptions,
# enum values, defaults and examples are masked (found by /security-review).
_SCHEMA_KEYS = frozenset({"text", "response_format", "output_config"})

# Long runs with no whitespace and only base64 characters: media, not prose.
_BLOB_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{256,}$")


def _is_blob(s: str) -> bool:
    return len(s) >= 256 and _BLOB_RE.match(s) is not None


# data:<type>/<subtype>[;name=value…][;base64],  — parameter values are plain
# words only: anything with a space, an "@" or a line break in it is not a
# parameter but somebody's text, and then the string is not a data: address.
_DATA_URL_RE = re.compile(r"^data:([\w.+\-]+/[\w.+\-]+)?((?:;[\w.+\-]+=[\w.+\-%]*)*)(;base64)?,", re.I)


def _data_prefix(m: re.Match, visit) -> str:
    """The part of a data: address before its payload, shown to the engine
    WHOLE — type, parameters and all. Nothing in it is taken on trust:
    ``;name=402-99-1234.pdf`` is a file name, and ``data:a/ghp_…;base64,``
    carries a key where the type should be (/security-review rounds 2 and 3,
    2026-11-14). A real prefix (``data:image/png;base64,``) comes back as it was."""
    return visit(m[0])


def _media_word(media: str) -> str:
    """The receipt word for bytes Omna did not read (finding 7)."""
    m = media.lower()
    if m.startswith("image/"):
        return "image"
    if m == "application/pdf":
        return "pdf"
    if m.startswith("audio/"):
        return "audio"
    if m.startswith("video/"):
        return "video"
    return "encoded-data"


def _b64_bytes(data: str) -> bytes | None:
    """What strict base64 decodes to, or None when the string is not base64.
    Line breaks are allowed only the way real wrapped base64 has them (every
    line but the last at least 60 characters): "4111 1111 1111 1111" is
    base64 characters and spaces, and it is a card number."""
    lines = data.strip("\r\n").splitlines()
    if len(lines) > 1 and any(len(ln) < 60 for ln in lines[:-1]):
        return None
    packed = "".join(lines)
    if not packed or len(packed) % 4 or any(ch.isspace() for ch in packed):
        return None
    try:
        return base64.b64decode(packed, validate=True)
    except (binascii.Error, ValueError):
        return None


def _as_text(raw: bytes) -> str | None:
    """The bytes as UTF-8 text, or None when they are not text."""
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


_SHORT_PAYLOAD = 8192


def _packed(prefix: str, payload: str, media: str, visit):
    """``payload`` claims to be base64. (replacement, receipt word or None):

    * not base64 at all  -> it is readable text: masked as text;
    * base64 of text     -> decoded, masked, packed again (byte-identical
                            when nothing in it needed masking);
    * base64 of bytes    -> left exactly as it is, and named in the receipt."""
    raw = _b64_bytes(payload)
    if raw is None:
        return prefix + visit(payload), None
    text = _as_text(raw)
    if text is None:
        if len(payload) <= _SHORT_PAYLOAD:
            # Too short to be a file, and many plain values are valid base64
            # by accident (a card number, a key): let the engine look at it.
            seen = visit(payload)
            if seen != payload:
                return prefix + seen, None
        return prefix + payload, _media_word(media)
    if len(payload) <= _SHORT_PAYLOAD:
        # A plain value can be valid base64 of "text" by accident: the engine
        # sees the raw characters first (hardening from /security-review).
        seen = visit(payload)
        if seen != payload:
            return prefix + seen, None
    masked = visit(text)
    if masked == text:
        return prefix + payload, None
    return prefix + base64.b64encode(masked.encode("utf-8")).decode("ascii"), None


def _text_in_data_url(value: str, visit) -> str | None:
    """For a string that is NOT in a file-carrying place: if it is a
    ``data:…;base64,`` address whose payload is base64 of plain text, the same
    address with that text masked; else None (the caller masks the string as
    ordinary text, as it always did)."""
    m = _DATA_URL_RE.match(value)
    if not m or not m[3]:
        return None
    raw = _b64_bytes(value[m.end():])
    text = _as_text(raw) if raw is not None else None
    if text is None:
        return None
    if len(value) <= _SHORT_PAYLOAD and visit(value) != value:
        return None        # the engine finds a value in the raw string: mask it as plain text
    masked = visit(text)
    prefix = _data_prefix(m, visit)
    if masked == text:
        return prefix + value[m.end():]
    return prefix + base64.b64encode(masked.encode("utf-8")).decode("ascii")


def _media(parent: dict | None, key: str | None, value: str, visit):
    """A value in a place that carries a FILE (a picture, a PDF, a file as
    base64 or a ``data:`` address). Returns (replacement, receipt word or None).

    Only real bytes are left alone — base64 that does not decode to text. The
    label is never trusted: a ``data:`` prefix or a media type in front of
    readable text is still readable text, and it is masked (``_packed``).

    (The first version believed the prefix: any string that merely STARTED
    with ``data:a/b,`` went out unmasked, which the released version did not
    do — found by /security-review, 2026-11-14.)"""
    m = _DATA_URL_RE.match(value)
    if m:
        media, prefix, payload = (m[1] or "text/plain"), _data_prefix(m, visit), value[m.end():]
        if not m[3]:
            return prefix + visit(payload), None          # "data:text/plain,the text itself"
        return _packed(prefix, payload, media, visit)
    media = str((parent or {}).get("media_type") or (parent or {}).get("mime_type") or "")
    if not media and key in ("image_url", "b64_json"):
        media = "image/"
    return _packed("", value, media, visit)


_MEDIA_KEYS = frozenset({"data", "url", "image_url", "b64_json", "file_data"})


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
        # A tool's or a function's name is an identifier the API matches
        # against the tool list: kept. Any other "name" is somebody's text —
        # a message's speaker, a FILE's name, a project's — and is masked. It
        # used to be kept everywhere but on a message, so "Jane Doe SSN
        # 402-99-1234.txt" went out as it was (security review, finding 12).
        return is_tool_call(parent) or any(k in parent for k in _TOOL_SHAPE_KEYS)
    return False


# What sits next to a tool's or function's "name": OpenAI's ``function``
# {"name", "arguments"}, Gemini's ``functionCall`` {"name", "args"} and
# ``functionResponse`` {"name", "response"}, a definition met outside
# ``tools`` {"name", "parameters" / "input_schema"}, a tool call {"name", "input"}.
_TOOL_SHAPE_KEYS = frozenset({"arguments", "args", "response", "parameters", "input_schema", "input", "tool_use_id"})


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
        # A setting holds a word ("auto", a model name, an id) or an object;
        # a sentence under a setting's name is somebody's text.
        return not _looks_like_text(value)
    if key in _IDENT_KEYS:
        return not _looks_like_text(value)
    return key in STRUCT_KEYS or _skip_in(parent, key, value)


def _child_mode(parent: dict, key: str, mode: str, depth: int = 1) -> str:
    if mode != _MSG:
        return mode
    if key in _TOOLDEF_KEYS:
        return _TOOLDEF
    if depth == 0 and key in _SCHEMA_KEYS:
        # "text" is an output schema only in its Responses shape
        # ({"format": …}); any other top-level "text" stays a message.
        v = parent.get(key)
        if key != "text" or (isinstance(v, dict) and "format" in v):
            return _TOOLDEF
    if key == "metadata" or (key == "input" and is_tool_call(parent)):
        return _DATA
    return _MSG


def _walk(obj, visit, mode: str = _MSG, key: str | None = None, depth: int = 0, in_tool: bool = False,
          media=None):
    """Visit every string that is someone's content; ``visit(s, key, in_tool)``
    returns its replacement. ``in_tool``: the string is part of a tool CALL
    (finding 2). One walker for masking and restoring, so whatever is masked
    can be put back.

    ``media(parent, key, value)`` (masking only) is handed every string that
    is BYTES, not prose — base64 media, a ``data:`` address, a long opaque
    run — and returns what to send in its place (finding 7)."""
    if isinstance(obj, str):
        if _is_blob(obj):
            # A long run of base64 characters. Skipped as it always was when
            # restoring; when masking it is opened: text inside is masked.
            return media(None, key, obj) if media is not None else obj
        if media is not None and _DATA_URL_RE.match(obj):
            if key in _MEDIA_KEYS:
                return media(None, key, obj)      # a file handed over as a data: address
            # Elsewhere a data: address is opened only when it is base64 of
            # plain text (masked inside); anything else is somebody's text
            # and goes to the engine below, whatever it starts with — exactly
            # as before this function knew about media.
            opened = _text_in_data_url(obj, lambda t: visit(t, key, in_tool))
            if opened is not None:
                return opened
        return visit(obj, key, in_tool)
    if isinstance(obj, list):
        return [_walk(item, visit, mode, key, depth + 1, in_tool, media) for item in obj]
    if isinstance(obj, dict):
        here = in_tool or is_tool_call(obj)
        out = {}
        for k, v in obj.items():
            if _skip(obj, k, v, mode, depth):
                out[k] = media(obj, k, v) if media is not None and k in _MEDIA_KEYS and isinstance(v, str) and v else v
            else:
                out[k] = _walk(v, visit, _child_mode(obj, k, mode, depth), k, depth + 1,
                               here or k in _TOOL_KEYS, media)
        return out
    return obj


def mask_body(session: MaskingSession, obj, style: str = TOKENS, careful: bool = False):
    """Return (masked_copy, counts, labels). ``obj`` is not modified.

    ``counts`` maps entity name -> occurrences and carries reserved keys that
    the receipt writer pops off: ``_secrets`` / ``_pii`` (totals by layer),
    ``_validated`` (catches a checksum actually proved), ``_layer_L1`` etc.,
    ``_finds`` (the masking engine's L6 events, grouped — #184) and
    ``_not_read`` (pictures, PDFs and other bytes that went out unread).

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

    not_read: list[str] = []

    def media(parent: dict | None, key: str | None, value: str) -> str:
        out, word = _media(parent, key, value, lambda text: fn(text, key))
        if word and word not in not_read:
            not_read.append(word)
        return out

    masked = _walk(obj, fn, media=media)
    if not_read:
        counts["_not_read"] = not_read  # type: ignore[assignment]
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
    # "*tool_use" also covers Anthropic Managed Agents' events
    # (agent.custom_tool_use, agent.tool_use, agent.mcp_tool_use) — found by
    # /security-review, 2026-11-12.
    return isinstance(t, str) and (t in _TOOL_BLOCK_TYPES or t.endswith("_call") or t.endswith("tool_use"))


def restore_body(session, obj, tools=None):
    """Return a copy with every reversible token replaced by its real value.

    ``tools``: the restorer for TOOL CALLS inside the reply (an
    ``engine.ToolView``) — secrets stay stand-ins there by default (finding
    2). None restores tool calls like any other text."""
    tools = tools or session
    return _walk(obj, lambda s, _key, in_tool: (tools if in_tool else session).restore_text(s))
