"""Restore masked values inside a server-sent-events (SSE) stream.

The hard part: a masked value can arrive split across two chunks — a token
(``"Hi [PER"`` then ``"SON_1]!"``), or, in the realistic style, a fake value
that has no brackets at all and can therefore split anywhere. We hold back any
trailing text that could still be the start of one, and release it as soon as
it either completes or can no longer be one. ``MaskingSession.hold_from`` owns
that judgement, because only the registry knows what the fake values are.
Everything else (pings, message_start, unknown event types, comments) passes
through byte-identical, because Claude Code counts every byte it receives and
aborts a stream that goes silent.

Supported delta shapes:
- Anthropic: ``content_block_delta`` with ``delta.text`` (text_delta) or
  ``delta.partial_json`` (input_json_delta, JSON-escaped on restore)
- OpenAI chat: ``choices[].delta.content`` and
  ``choices[].delta.tool_calls[].function.arguments`` (JSON-escaped)
- OpenAI Responses API: any event whose ``type`` ends in ``.delta`` with a
  string ``delta`` field (JSON-escaped when the type mentions arguments)
"""

from __future__ import annotations

import json

from .engine import MaskingSession


class TextRestorer:
    """Restore over any text stream, holding back a value that is still arriving.

    The session owns both halves of that job — what a partial value looks like
    and what a complete one means — because a realistic fake value has no
    brackets to recognise it by, only the registry.
    """

    def __init__(self, session: MaskingSession, json_escape: bool = False):
        self.session = session
        self.json_escape = json_escape
        self.pending = ""

    def _restore(self, text: str) -> str:
        return self.session.restore_text(text, json_escape=self.json_escape)

    def feed(self, text: str) -> str:
        buf = self.pending + text
        cut = self.session.hold_from(buf)
        out, self.pending = buf[:cut], buf[cut:]
        return self._restore(out) if out else ""

    def flush(self) -> str:
        out, self.pending = self.pending, ""
        return self._restore(out) if out else ""


# Backwards-compat alias: this class used to be private.
_HoldBack = TextRestorer


class StreamRestorer:
    """Feed raw SSE bytes in, get restored SSE bytes out."""

    def __init__(self, session: MaskingSession):
        self.session = session
        self._buf = b""
        self._text: dict[str, TextRestorer] = {}  # key -> holdback (per content block / choice)

    def _hb(self, key: str, json_escape: bool) -> TextRestorer:
        hb = self._text.get(key)
        if hb is None:
            hb = self._text[key] = TextRestorer(self.session, json_escape)
        return hb

    def feed(self, chunk: bytes) -> bytes:
        self._buf += chunk
        out = []
        while True:
            idx = self._buf.find(b"\n\n")
            if idx < 0:
                break
            frame, self._buf = self._buf[: idx + 2], self._buf[idx + 2:]
            out.append(self._frame(frame))
        return b"".join(out)

    def flush(self) -> bytes:
        """End of stream: release anything held back and any partial frame."""
        out = []
        for key, hb in self._text.items():
            rest = hb.flush()
            if rest:
                out.append(self._synth(key, rest))
        self._text.clear()
        if self._buf:
            out.append(self._buf)
            self._buf = b""
        return b"".join(out)

    # ------------------------------------------------------------------ frames
    def _frame(self, frame: bytes) -> bytes:
        # Only frames with a JSON data line can carry text; everything else is
        # forwarded untouched (pings, comments, keep-alives).
        lines = frame[:-2].split(b"\n")
        data_idx = [i for i, l in enumerate(lines) if l.startswith(b"data:")]
        if not data_idx:
            return frame
        raw = b"\n".join(lines[i][5:].strip() for i in data_idx)
        try:
            evt = json.loads(raw)
        except ValueError:
            return frame
        if not isinstance(evt, dict):
            return frame
        changed = self._restore_event(evt)
        prefix = evt.pop("__omna_prefix__", b"")
        if not changed:
            return prefix + frame
        new_data = b"data: " + json.dumps(evt, ensure_ascii=False).encode("utf-8")
        rebuilt = []
        for i, l in enumerate(lines):
            if i == data_idx[0]:
                rebuilt.append(new_data)
            elif i in data_idx:
                continue
            else:
                rebuilt.append(l)
        return prefix + b"\n".join(rebuilt) + b"\n\n"

    def _restore_event(self, evt: dict) -> bool:
        t = evt.get("type", "")
        # ---- Anthropic
        if t == "content_block_delta":
            d = evt.get("delta") or {}
            idx = str(evt.get("index", 0))
            if d.get("type") == "text_delta" and isinstance(d.get("text"), str):
                d["text"] = self._hb("a:text:" + idx, False).feed(d["text"])
                return True
            if d.get("type") == "input_json_delta" and isinstance(d.get("partial_json"), str):
                d["partial_json"] = self._hb("a:json:" + idx, True).feed(d["partial_json"])
                return True
            return False
        if t == "content_block_stop":
            idx = str(evt.get("index", 0))
            # the block ended: anything still held back is plain text; release
            # it as a synthetic delta emitted just before this stop frame.
            return self._flush_block(evt, idx)
        # ---- OpenAI chat completions
        if "choices" in evt and isinstance(evt["choices"], list):
            changed = False
            for ch in evt["choices"]:
                d = ch.get("delta") if isinstance(ch, dict) else None
                if not isinstance(d, dict):
                    continue
                ci = str(ch.get("index", 0))
                if isinstance(d.get("content"), str):
                    d["content"] = self._hb("o:text:" + ci, False).feed(d["content"])
                    changed = True
                for tc in d.get("tool_calls") or []:
                    fn = tc.get("function") if isinstance(tc, dict) else None
                    if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                        fn["arguments"] = self._hb(f"o:args:{ci}:{tc.get('index', 0)}", True).feed(fn["arguments"])
                        changed = True
                if ch.get("finish_reason"):
                    for key in list(self._text):
                        if key.startswith(f"o:text:{ci}") or key.startswith(f"o:args:{ci}:"):
                            rest = self._text.pop(key).flush()
                            if rest:
                                if key.startswith("o:text"):
                                    d["content"] = (d.get("content") or "") + rest
                                changed = True
            return changed
        # ---- OpenAI Responses API
        if isinstance(t, str) and t.endswith(".delta") and isinstance(evt.get("delta"), str):
            esc = "arguments" in t
            key = f"r:{t}:{evt.get('output_index', 0)}:{evt.get('content_index', 0)}"
            evt["delta"] = self._hb(key, esc).feed(evt["delta"])
            return True
        if isinstance(t, str) and t.endswith(".done"):
            base = t[: -len(".done")] + ".delta"
            key = f"r:{base}:{evt.get('output_index', 0)}:{evt.get('content_index', 0)}"
            hb = self._text.pop(key, None)
            if hb:
                rest = hb.flush()
                # the .done event carries the full final text; restore it whole
                for fld in ("text", "arguments"):
                    if isinstance(evt.get(fld), str):
                        evt[fld] = hb._restore(evt[fld])
                return True
        return False

    def _flush_block(self, stop_evt: dict, idx: str) -> bool:
        """On content_block_stop, release held-back text as an extra delta."""
        extra = b""
        for kind, esc in (("a:text:", False), ("a:json:", True)):
            hb = self._text.pop(kind + idx, None)
            if hb:
                rest = hb.flush()
                if rest:
                    extra += self._synth(kind + idx, rest)
        if extra:
            # Stash the synthetic delta so _frame emits it before the stop frame.
            stop_evt["__omna_prefix__"] = extra
        return False

    def _synth(self, key: str, text: str) -> bytes:
        """Build a synthetic delta frame carrying released hold-back text."""
        kind, _, idx = key.partition(":")
        if key.startswith("a:text:"):
            evt = {"type": "content_block_delta", "index": int(key.rsplit(":", 1)[1]), "delta": {"type": "text_delta", "text": text}}
            return b"event: content_block_delta\ndata: " + json.dumps(evt, ensure_ascii=False).encode() + b"\n\n"
        if key.startswith("a:json:"):
            evt = {"type": "content_block_delta", "index": int(key.rsplit(":", 1)[1]), "delta": {"type": "input_json_delta", "partial_json": text}}
            return b"event: content_block_delta\ndata: " + json.dumps(evt, ensure_ascii=False).encode() + b"\n\n"
        if key.startswith("o:text:"):
            evt = {"choices": [{"index": int(key.rsplit(":", 1)[1]), "delta": {"content": text}}]}
            return b"data: " + json.dumps(evt, ensure_ascii=False).encode() + b"\n\n"
        if key.startswith("r:"):
            t = key.split(":")[1]
            evt = {"type": t, "delta": text}
            return b"event: " + t.encode() + b"\ndata: " + json.dumps(evt, ensure_ascii=False).encode() + b"\n\n"
        return b""
