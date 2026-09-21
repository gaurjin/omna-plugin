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
from .engine import MaskingSession
from .policy import Policy
from .stream import StreamRestorer, TextRestorer
from .style import TOKENS


@dataclass
class MaskStats:
    counts: dict[str, int] = field(default_factory=dict)
    secrets: int = 0
    pii: int = 0
    mask_ms: int = 0
    tokens: list[str] = field(default_factory=list)
    # Catches a checksum proved (IBAN, card, national IDs) — certainty, not a
    # probability. See MaskResult.validated for why we surface this rather
    # than an average confidence score.
    validated: int = 0
    by_layer: dict[str, int] = field(default_factory=dict)


@dataclass
class MaskedBody:
    body: bytes | None
    stats: MaskStats
    refused: str | None = None   # "unparseable" | "mask-failed" | None


def _merge(total: MaskStats, st: MaskStats) -> None:
    for k, v in st.counts.items():
        total.counts[k] = total.counts.get(k, 0) + v
    total.secrets += st.secrets
    total.pii += st.pii
    total.mask_ms += st.mask_ms
    total.validated += st.validated
    for k, v in st.by_layer.items():
        total.by_layer[k] = total.by_layer.get(k, 0) + v
    total.tokens = sorted(set(total.tokens) | set(st.tokens))


class Pipeline:
    def __init__(self, session: MaskingSession):
        self.session = session

    # ------------------------------------------------------------ masking
    def mask_json(self, obj, style: str = TOKENS) -> tuple[object, MaskStats]:
        t0 = time.time()
        masked, counts, labels = mask_body(self.session, obj, style)
        c = dict(counts)
        by_layer = {k[len("_layer_"):]: c.pop(k) for k in [x for x in list(c) if x.startswith("_layer_")]}
        stats = MaskStats(
            secrets=c.pop("_secrets", 0),
            pii=c.pop("_pii", 0),
            validated=c.pop("_validated", 0),
            by_layer=by_layer,
            counts=c,
            mask_ms=int((time.time() - t0) * 1000),
            tokens=labels,
        )
        return masked, stats

    def mask_text(self, text: str, style: str = TOKENS) -> tuple[str, MaskStats]:
        t0 = time.time()
        r = self.session.mask_text(text, style=style)
        return r.masked, MaskStats(counts=dict(r.counts), secrets=r.secrets, pii=r.pii,
                                    validated=r.validated, by_layer=dict(r.by_layer),
                                    mask_ms=int((time.time() - t0) * 1000), tokens=list(r.labels))

    def mask_bytes(self, body: bytes, content_type: str, style: str = TOKENS) -> MaskedBody:
        """Mask a request body by content type. Never forwarded unmasked.

        Two distinct refusal reasons: "unparseable" means the body itself
        couldn't even be read as the shape its content-type promised (bad
        JSON syntax, bad text encoding); "mask-failed" means the body parsed
        fine but the masking step itself blew up on it (e.g. a lone Unicode
        surrogate that survives ``json.loads`` but can't be re-encoded to
        UTF-8). Both are refused, but callers may treat them differently.
        """
        ct = (content_type or "").lower()
        if "json" in ct:
            try:
                obj = json.loads(body)
            except ValueError:
                return MaskedBody(None, MaskStats(), refused="unparseable")
            try:
                masked, stats = self.mask_json(obj, style)
                return MaskedBody(json.dumps(masked, ensure_ascii=False).encode("utf-8"), stats)
            except (TypeError, ValueError, UnicodeEncodeError, UnicodeDecodeError):
                return MaskedBody(None, MaskStats(), refused="mask-failed")
        if "x-www-form-urlencoded" in ct:
            try:
                pairs = parse_qsl(body.decode("utf-8"), keep_blank_values=True)
            except (ValueError, UnicodeDecodeError, TypeError):
                return MaskedBody(None, MaskStats(), refused="unparseable")
            try:
                total, out = MaskStats(), []
                for k, v in pairs:
                    mv, st = self.mask_text(v, style)
                    out.append((k, mv))
                    _merge(total, st)
                return MaskedBody(urlencode(out).encode("utf-8"), total)
            except (TypeError, ValueError, UnicodeEncodeError, UnicodeDecodeError):
                return MaskedBody(None, MaskStats(), refused="mask-failed")
        if ct.startswith("text/"):
            try:
                text = body.decode("utf-8")
            except (ValueError, UnicodeDecodeError, TypeError):
                return MaskedBody(None, MaskStats(), refused="unparseable")
            try:
                masked, stats = self.mask_text(text, style)
                return MaskedBody(masked.encode("utf-8"), stats)
            except (TypeError, ValueError, UnicodeEncodeError, UnicodeDecodeError):
                return MaskedBody(None, MaskStats(), refused="mask-failed")
        return MaskedBody(None, MaskStats(), refused="unparseable")

    # ------------------------------------------------------------ restoring
    def restore_json(self, obj):
        return restore_body(self.session, obj)

    def restore_text(self, text: str, json_escape: bool = False) -> str:
        return self.session.restore_text(text, json_escape=json_escape)

    def sse_restorer(self) -> StreamRestorer:
        """For Anthropic / OpenAI shaped SSE (the API door's formats)."""
        return StreamRestorer(self.session)

    def text_restorer(self, json_escape: bool) -> TextRestorer:
        """Token-level restore over any text stream, with partial-token hold-back."""
        return TextRestorer(self.session, json_escape=json_escape)

    # ------------------------------------------------------------ receipts
    def receipt(self, *, door: str, route: str, host: str, status: int, stats: MaskStats,
                nbytes: int, ms: int, stream: bool, app: str | None, note: str | None,
                session_id: str | None, style: str = TOKENS) -> None:
        # Keep Local Reports off suppresses ordinary usage receipts, but never a
        # refusal: that's "this app isn't working, here's why" diagnostic
        # information (surfaced by `omna status`'s refused line), not usage
        # tracking, and the person still needs to see it to fix a pinned app.
        if note != "tls-refused" and not Policy.load().reports_enabled:
            return
        rec = {
            "door": door, "route": route, "host": host, "upstream": host, "status": status,
            "stream": stream, "masked": stats.counts, "secrets": stats.secrets, "pii": stats.pii,
            "validated": stats.validated, "by_layer": stats.by_layer,
            "mask_ms": stats.mask_ms, "tokens": stats.tokens, "bytes_in": nbytes, "ms": ms,
            "app": app, "style": style,
        }
        if note:
            rec["note"] = note
        if session_id:
            rec["session"] = session_id
        try:
            receipts.append(rec)
        except OSError:
            pass
