"""The mail room. Every door (API, system, deep) hands its traffic to this
one object: mask on the way out, restore on the way back, one receipt per
request. It owns nothing network-related."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode

from . import receipts
from .body import mask_body, restore_body
from .engine import MaskingSession, TOKEN_RE
from .stream import StreamRestorer, TextRestorer


@dataclass
class MaskStats:
    counts: dict[str, int] = field(default_factory=dict)
    secrets: int = 0
    pii: int = 0
    mask_ms: int = 0
    tokens: list[str] = field(default_factory=list)


@dataclass
class MaskedBody:
    body: bytes | None
    stats: MaskStats
    refused: str | None = None   # "unparseable" | None


def _tokens_in(text: str) -> list[str]:
    return sorted({m.group(0)[1:-1] for m in TOKEN_RE.finditer(text)})


def _merge(total: MaskStats, st: MaskStats) -> None:
    for k, v in st.counts.items():
        total.counts[k] = total.counts.get(k, 0) + v
    total.secrets += st.secrets
    total.pii += st.pii
    total.mask_ms += st.mask_ms
    total.tokens = sorted(set(total.tokens) | set(st.tokens))


class Pipeline:
    def __init__(self, session: MaskingSession):
        self.session = session

    # ------------------------------------------------------------ masking
    def mask_json(self, obj) -> tuple[object, MaskStats]:
        t0 = time.time()
        masked, counts = mask_body(self.session, obj)
        c = dict(counts)
        stats = MaskStats(
            secrets=c.pop("_secrets", 0),
            pii=c.pop("_pii", 0),
            counts=c,
            mask_ms=int((time.time() - t0) * 1000),
            tokens=_tokens_in(json.dumps(masked, ensure_ascii=False)),
        )
        return masked, stats

    def mask_text(self, text: str) -> tuple[str, MaskStats]:
        t0 = time.time()
        r = self.session.mask_text(text)
        return r.masked, MaskStats(counts=dict(r.counts), secrets=r.secrets, pii=r.pii,
                                    mask_ms=int((time.time() - t0) * 1000), tokens=_tokens_in(r.masked))

    def mask_bytes(self, body: bytes, content_type: str) -> MaskedBody:
        """Mask a request body by content type. Unparseable bodies are refused, never forwarded."""
        ct = (content_type or "").lower()
        try:
            if "json" in ct:
                masked, stats = self.mask_json(json.loads(body))
                return MaskedBody(json.dumps(masked, ensure_ascii=False).encode("utf-8"), stats)
            if "x-www-form-urlencoded" in ct:
                total, out = MaskStats(), []
                for k, v in parse_qsl(body.decode("utf-8"), keep_blank_values=True):
                    mv, st = self.mask_text(v)
                    out.append((k, mv))
                    _merge(total, st)
                return MaskedBody(urlencode(out).encode("utf-8"), total)
            if ct.startswith("text/"):
                masked, stats = self.mask_text(body.decode("utf-8"))
                return MaskedBody(masked.encode("utf-8"), stats)
        except (ValueError, UnicodeDecodeError, TypeError):
            pass
        return MaskedBody(None, MaskStats(), refused="unparseable")

    # ------------------------------------------------------------ restoring
    def restore_json(self, obj):
        return restore_body(self.session, obj)

    def restore_text(self, text: str) -> str:
        return self.session.restore_text(text)

    def sse_restorer(self) -> StreamRestorer:
        """For Anthropic / OpenAI shaped SSE (the API door's formats)."""
        return StreamRestorer(self.session)

    def text_restorer(self, json_escape: bool) -> TextRestorer:
        """Token-level restore over any text stream, with partial-token hold-back."""
        return TextRestorer(self.session, json_escape=json_escape)

    # ------------------------------------------------------------ receipts
    def receipt(self, *, door: str, route: str, host: str, status: int, stats: MaskStats,
                nbytes: int, ms: int, stream: bool, app: str | None, note: str | None,
                session_id: str | None) -> None:
        rec = {
            "door": door, "route": route, "host": host, "upstream": host, "status": status,
            "stream": stream, "masked": stats.counts, "secrets": stats.secrets, "pii": stats.pii,
            "mask_ms": stats.mask_ms, "tokens": stats.tokens, "bytes_in": nbytes, "ms": ms,
            "app": app,
        }
        if note:
            rec["note"] = note
        if session_id:
            rec["session"] = session_id
        try:
            receipts.append(rec)
        except OSError:
            pass
