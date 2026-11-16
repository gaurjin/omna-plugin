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
import contextvars
import re

from . import receipts, sites
from . import smart as smart_models
from .engine import MaskingSession, sending_site
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
    # Anthropic's own safety check on what an agent may run ("dangerous_tool_use"):
    # Claude Code tells it the permission mode and folders. It is the AI
    # company's security layer, not the person's message, so it goes as it is
    # (2026-11-15: smart masking edited 57 values in it in one request).
    "safeguards",
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


# Set while the walker is inside a field that holds the person's own text on
# a chat website (``sites.Site.person_text``).
_in_person_text: contextvars.ContextVar[bool] = contextvars.ContextVar("omna_in_person_text", default=False)


def _walk(obj, visit, mode: str = _MSG, key: str | None = None, depth: int = 0, in_tool: bool = False,
          media=None, person: frozenset | None = None):
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
        return [_walk(item, visit, mode, key, depth + 1, in_tool, media, person) for item in obj]
    if isinstance(obj, dict):
        here = in_tool or is_tool_call(obj)
        out = {}
        for k, v in obj.items():
            if _skip(obj, k, v, mode, depth):
                out[k] = media(obj, k, v) if media is not None and k in _MEDIA_KEYS and isinstance(v, str) and v else v
            else:
                tok = _in_person_text.set(True) if person and k in person else None
                try:
                    out[k] = _walk(v, visit, _child_mode(obj, k, mode, depth), k, depth + 1,
                                   here or k in _TOOL_KEYS, media, person)
                finally:
                    if tok is not None:
                        _in_person_text.reset(tok)
        return out
    return obj


# Claude Code's billing line: a system block of its own, exactly
# "x-anthropic-billing-header: name=value; name=value;". Anthropic checks it
# and refuses the whole request if it was edited (400 "x-anthropic-billing-header
# is a reserved keyword"). Found 2026-11-15: the compact smart model read "cc_"
# and "cli" in it as names, and Claude Code stopped working through Omna. It is
# the AI company's billing check, not anything the person typed, so it goes
# byte-for-byte — only as its own system block, and only while it holds
# nothing but settings (a word, "=", a value of letters, digits, ".", "_", "-").
_BILLING_LINE = re.compile(r"x-anthropic-billing-header:(?: [a-z][a-z0-9_]*=[A-Za-z0-9._-]*;)+")


# Claude Code's identity for Anthropic: metadata.user_id is exactly
# {"device_id": 64 hex, "account_uuid": uuid, "session_id": uuid} (2026-11-15:
# smart masking read pieces of the ids as secrets). Random ids, no person's
# text; Anthropic uses them for its own limits and abuse checks. Spared only in
# exactly that shape — any other user_id (an email, a name) is masked.
_HEX = "[0-9a-f]"
_UUID = f"{_HEX}{{8}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{4}}-{_HEX}{{12}}"
_CLAUDE_CODE_USER_ID = re.compile(
    r'\{"device_id":"' + _HEX + r'{64}","account_uuid":"(?:' + _UUID + r')?","session_id":"' + _UUID + r'"\}')


def _claude_code_user_id(obj) -> bool:
    meta = obj.get("metadata") if isinstance(obj, dict) else None
    uid = meta.get("user_id") if isinstance(meta, dict) else None
    return isinstance(uid, str) and bool(_CLAUDE_CODE_USER_ID.fullmatch(uid))


def _billing_blocks(obj) -> list[int]:
    system = obj.get("system") if isinstance(obj, dict) else None
    if not isinstance(system, list):
        return []
    return [i for i, b in enumerate(system)
            if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
            and _BILLING_LINE.fullmatch(b["text"])]


# OWNER RULE 2026-11-15: Omna checks only the PERSON's data — what they type,
# paste, upload or attach, and what an agent reads or runs for them (tool
# results) — plus the earlier turns of the chat, which carry those values back
# (the AI's replies hold real values: Omna put them back for the person). What
# the app adds on its own is the app's, not the person's, and goes as it is:
# its instructions ("system", "instructions", "systemInstruction"), its tool
# list, its output schema, system/developer messages, and the notes Claude
# Code puts into the person's turn (verified 2026-11-15, Claude Code 2.1.325:
# the CLAUDE.md files, the account context, the commit-attribution note).
# Before this, the whole request was checked: never an owner decision; it
# made most false alarms (tool words read as names) and a ~25 s wait.
# Where the data lives in an AI API request: the conversation. Everything
# outside it (system prompt, tools, connectors, schemas, settings, ids) is
# the app's and goes as it is.
_CONVERSATION_KEYS = frozenset({"messages", "input", "contents", "prompt"})
_APP_ROLES = frozenset({"system", "developer"})
_APP_NOTES = (
    "<system-reminder>\nCodebase and user instructions are shown below",
    "<system-reminder>\nAs you answer the user's questions, you can use the following context",
    "<system-reminder>\nAttribution for git commits",
)
_NOTE_END = "</system-reminder>"
# Codex's own note at the start of a chat (recorded live 2026-11-16, Codex
# 0.169): the work folder, the shell, today's date, the time zone — today's
# date was masked as a birth date.
_CODEX_NOTE = ("<environment_context>", "</environment_context>")
# Codex's label block on every message of its conversation (same recording):
# a turn id and what kind of text the message holds ("user.text") — never
# the text itself.
_MESSAGE_LABELS = "internal_chat_message_metadata_passthrough"


def _is_app_note(text) -> bool:
    """One of Claude Code's own notes, and nothing else. A block that merely
    STARTS with a note is not the app's: an editor selection or an @-file
    glued behind it in the same block is the person's data (found 2026-11-15).
    So the note's own closing tag must be the end of the text; anything after
    it makes the whole block data (the rule's tiebreaker) and it is checked."""
    if not isinstance(text, str):
        return False
    if text.startswith(_CODEX_NOTE[0]):
        close = _CODEX_NOTE[1]
    elif text.startswith(_APP_NOTES):
        close = _NOTE_END
    else:
        return False
    end = text.find(close)
    return end >= 0 and not text[end + len(close):].strip()


# Claude Code's role "system" turns inside the chat (2.1.325) are NOT on that
# list: they mix its own notes (hook/plugin text, tool notices) with data — a
# background agent's report, the lines the person selected in their editor,
# a file that changed on disk — and Claude Code glues neighbouring notes into
# one block, so an app note can carry data behind it (security review
# 2026-11-15, two rounds). Omna cannot cut such a block apart safely, so the
# rule's tiebreaker applies: when it cannot tell data from app text, it is
# data. Those turns are checked (fast masking, see mask_body); only a pure
# tool definition is skipped.
# A tool definition handed over mid-chat is the app's, like the tool list.
_APP_BLOCK_TYPES = frozenset({"tool_addition"})


def _is_api_request(obj) -> bool:
    """An AI API request: {"model" + "messages" / "input"}. Gemini names the
    model in the address, not the body: "contents" alone."""
    return isinstance(obj, dict) and not _site_chat(obj) and (
        "contents" in obj or (isinstance(obj.get("model"), str) and any(k in obj for k in ("messages", "input"))))


is_api_request = _is_api_request      # the system door asks this of a WebSocket message


def _site_chat(obj) -> bool:
    """chatgpt.com's own message request (recorded live 2026-11-15): it has
    "model" + "messages" like an API request, but each message names its
    sender under "author", never "role" — the website's body, not the API's.
    (Codex on the same site sends the real Responses shape.)"""
    msgs = obj.get("messages")
    return isinstance(msgs, list) and bool(msgs) and all(
        isinstance(m, dict) and isinstance(m.get("author"), dict) and "role" not in m for m in msgs)


def _site_tool_list(obj) -> bool:
    """A chat website's own tool list: every entry a tool's definition — a
    one-word name with its input schema, or with a one-word type (claude.ai's
    built-in tools: {"type": "widget", "name": "weather_fetch"}). Anything
    else under "tools" is somebody's text."""
    def word(v) -> bool:
        return isinstance(v, str) and bool(v) and not _looks_like_text(v)

    tools = obj.get("tools") if isinstance(obj, dict) else None
    return isinstance(tools, list) and bool(tools) and all(
        isinstance(t, dict) and word(t.get("name"))
        and ("input_schema" in t or "parameters" in t or (word(t.get("type")) and set(t) == {"name", "type"}))
        for t in tools)


def _app_parts(obj):
    """(view, put_back): ``view`` is the request with the app's own parts set
    to None, ``put_back(masked)`` returns them exactly as they came. Only an AI
    API request ({"model" + "messages" / "input"}, or Gemini's "contents"); a chat
    website's own body is left to the walker as before."""
    if not _is_api_request(obj):
        return obj, (lambda m, _u=None: m), {}
    # The conversation is the data; every other field of the request is the
    # app's (owner 2026-11-15: "skip everything except the data").
    keys = {k for k in obj if k not in _CONVERSATION_KEYS}
    view = {k: (None if k in keys else v) for k, v in obj.items()}
    aside_msgs: dict[int, object] = {}
    aside_blocks: dict[tuple[int, int], object] = {}
    unsure: dict[int, object] = {}
    labels: dict[int, object] = {}
    mkey = next((k for k in ("messages", "input") if isinstance(obj.get(k), list)), None)
    if mkey:
        msgs = []
        for i, m in enumerate(obj[mkey]):
            if isinstance(m, dict) and _MESSAGE_LABELS in m:
                labels[i] = m[_MESSAGE_LABELS]
                m = {**m, _MESSAGE_LABELS: None}
            c = m.get("content") if isinstance(m, dict) else None
            # Anthropic's instructions live in the top-level "system" key, so
            # there a system turn inside the chat is judged by what it holds;
            # in OpenAI's shapes a system/developer message IS the instructions.
            app_role = isinstance(m, dict) and m.get("role") in _APP_ROLES and "system" not in obj
            if app_role or _is_app_note(c):
                aside_msgs[i] = m
                msgs.append(None)
                continue
            if isinstance(c, list):
                blocks = list(c)
                for j, b in enumerate(c):
                    t = b.get("text") if isinstance(b, dict) and b.get("type") in ("text", "input_text") else None
                    if _is_app_note(t) or (
                            m.get("role") == "system" and isinstance(b, dict) and b.get("type") in _APP_BLOCK_TYPES):
                        aside_blocks[(i, j)] = b
                        blocks[j] = None
                if blocks != c:
                    m = {**m, "content": blocks}
            if isinstance(m, dict) and m.get("role") == "system" and "system" in obj:
                unsure[i] = m        # masked apart, with fast masking (mask_body)
                msgs.append(None)
                continue
            msgs.append(m)
        view[mkey] = msgs

    def put_back(masked, unsure_masked=None):
        out = {k: (obj[k] if k in keys and k in obj else masked[k]) for k in obj}
        if mkey and (aside_msgs or aside_blocks or unsure_masked or labels):
            msgs = list(out[mkey])
            for i, m in aside_msgs.items():
                msgs[i] = m
            for i, m in (unsure_masked or {}).items():
                msgs[i] = m
            for (i, j), b in aside_blocks.items():
                content = list(msgs[i]["content"])
                content[j] = b
                msgs[i] = {**msgs[i], "content": content}
            for i, v in labels.items():       # last: a message set aside above was stored without them
                if isinstance(msgs[i], dict):
                    msgs[i] = {**msgs[i], _MESSAGE_LABELS: v}
            out[mkey] = msgs
        return out

    return view, put_back, unsure


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
    obj_system = obj.get("system") if isinstance(obj, dict) else None

    c = counts

    # A chat website's own body (recorded live, ``sites.Site.person_text``):
    # the person's fields get smart masking, the site's own fields fast
    # masking, its tool list goes as it is (owner rule 2026-11-15; before
    # this, 35 of claude.ai's own fields were edited in one request).
    person = None if _is_api_request(obj) else sites.person_text(sending_site())
    site_tools = obj["tools"] if person is not None and _site_tool_list(obj) else None
    if site_tools is not None:
        obj = {**obj, "tools": None}

    def mask_text(text: str, only):
        if person is not None and not _in_person_text.get():
            with smart_models.rules_only():
                return session.mask_text(text, style=style, only=only)
        return session.mask_text(text, style=style, only=only)

    own = sites.as_is(sending_site()) if person is not None else frozenset()

    def fn(s: str, key: str | None = None, _in_tool: bool = False) -> str:
        if key in own:
            return s            # the company's security check (``sites.Site.as_is``)
        only = ONLY_IN_IDS if careful and is_id_key(key) else None
        r = mask_text(s, only)
        masked = r.masked
        if r.masked == s and key and _CRED_KEY.search(key) and s and not any(ch.isspace() for ch in s):
            # {"password": "S3cure-Horse-Battery-99"}: each value is masked on
            # its own, so the engine never saw the word that makes it a
            # password (finding 4). Ask again WITH its name, using the
            # engine's own rule (keyword + entropy floor), and keep the value.
            r2 = mask_text(f"{key}={s}", only)
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

    obj, put_back, unsure = _app_parts(obj)
    spared = _billing_blocks(obj)
    if spared:
        obj = {**obj, "system": [None if i in spared else b for i, b in enumerate(obj["system"])]}
    user_id = obj["metadata"]["user_id"] if _claude_code_user_id(obj) else None
    if user_id is not None:
        obj = {**obj, "metadata": {**obj["metadata"], "user_id": None}}
    # How much text the request holds decides which smart model reads it
    # (smart.request: a long agent request gets the compact model alone).
    size = [0]
    _walk(obj, lambda t, _k, _i: size.__setitem__(0, size[0] + len(t)) or t)
    with smart_models.request(size[0]):
        masked = _walk(obj, fn, media=media, person=person)
    if site_tools is not None:
        masked["tools"] = site_tools
    for i in spared:
        masked["system"][i] = obj_system[i]
    if user_id is not None:
        masked["metadata"]["user_id"] = user_id
    # Text Omna cannot tell apart (Claude Code's system turns: its own notes
    # glued to data) gets fast masking — the rules for secrets, emails, cards,
    # phones and values Omna already knows — not the smart models, which read
    # its plugin text as names (owner 2026-11-15: fewer false alarms).
    with smart_models.rules_only():
        unsure_masked = {i: _walk(m, fn, media=media) for i, m in unsure.items()}
    masked = put_back(masked, unsure_masked)
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
