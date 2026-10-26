"""The mail room. Every door (API, system, deep) hands its traffic to this
one object: mask on the way out, restore on the way back, one receipt per
request. It owns nothing network-related."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode

from . import office, receipts
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
    # A file the curl command recognised but cannot mask in place (PDF, old
    # binary Word/Excel, an image, PowerPoint): it went through as it is, and
    # the receipt says so (MASTER #160 step 3, owner decision "A").
    not_masked: str = ""


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
    total.not_masked = total.not_masked or st.not_masked


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
        if "multipart/form-data" in ct:
            return self._mask_multipart(body, content_type, style)
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

    def mask_upload_form(self, body: bytes, content_type: str, style: str = TOKENS) -> MaskedBody:
        """A multipart upload form: mask the file parts only, leave every other
        part byte-for-byte (see ``_mask_multipart(files_only=True)``)."""
        return self._mask_multipart(body, content_type, style, files_only=True)

    def mask_file(self, data: bytes, content_type: str, style: str = TOKENS) -> tuple[bytes, MaskStats]:
        """Mask an uploaded file if it is text; anything else comes back untouched.

        Browsers label files they don't recognise (.env, .pem, source code) as
        application/octet-stream, and those are exactly the files that carry
        secrets, so "is it text" is decided by the bytes (strict UTF-8, no NUL),
        not by the label. Word and Excel files are masked inside and stay Word
        and Excel files (``office.py``). Other binary formats (PDF, images,
        old Office) go through as they are — masking those is MASTER #160.
        """
        out, stats = self._mask_file(data, content_type, style, same_size=False)
        return (data if out is None else out), stats

    def mask_file_same_size(self, data: bytes, content_type: str, style: str = TOKENS) -> tuple[bytes | None, MaskStats]:
        """``mask_file``, but the masked file is exactly as long as ``data``.

        For sites that announce the file's size before they upload it and then
        refuse any other size (ChatGPT, "file_size_mismatch", 2026-10-25). Text
        is filled up with spaces at its very end; Word and Excel files with
        their zip comment (``office.py``). None when the masked file would be
        longer and cannot be shrunk: the caller refuses the upload, never
        sends it unmasked.
        """
        return self._mask_file(data, content_type, style, same_size=True)

    def _mask_file(self, data: bytes, content_type: str, style: str, same_size: bool) -> tuple[bytes | None, MaskStats]:
        if office.kind(data) is not None:
            total = MaskStats()

            def mask(text: str) -> str:
                masked, st = self.mask_text(text, style)
                _merge(total, st)
                return masked
            try:
                out = office.mask_office(data, mask, same_size=same_size)
            except office.SizeChanged:
                return None, total
            if out is not None:
                return out, total
            return data, MaskStats()
        if office.is_rtf(data):
            total = MaskStats()

            def mask_rtf_text(text: str) -> str:
                masked, st = self.mask_text(text, style)
                _merge(total, st)
                return masked
            out, stats = office.mask_rtf(data, mask_rtf_text), total
        else:
            out, stats = self._mask_plain_file(data, content_type, style)
        if not same_size or len(out) == len(data):
            return out, stats
        if len(out) > len(data):
            return None, stats
        return out + b" " * (len(data) - len(out)), stats

    def _mask_plain_file(self, data: bytes, content_type: str, style: str) -> tuple[bytes, MaskStats]:
        kind = office.unmaskable_kind(data)
        if kind:
            return data, MaskStats(not_masked=kind)
        ct = (content_type or "").lower()
        if "json" in ct:
            out = self.mask_bytes(data, ct, style)
            if out.refused is None:
                return out.body, out.stats
        if b"\x00" in data:
            return data, MaskStats()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return data, MaskStats()
        masked, stats = self.mask_text(text, style)
        return masked.encode("utf-8"), stats

    def _mask_multipart(self, body: bytes, content_type: str, style: str, files_only: bool = False) -> MaskedBody:
        """multipart/form-data: mask each text part, keep every byte of the framing.

        ``files_only``: mask only the parts that carry a file (``filename=``) —
        for storage forms whose other parts are a signature that must arrive
        exactly as signed (Perplexity's Amazon S3 upload, MASTER #176)."""
        boundary = next((v.strip().strip('"') for k, _, v in
                         (x.strip().partition("=") for x in content_type.split(";"))
                         if k.strip().lower() == "boundary"), "")
        delim = b"--" + boundary.encode("latin-1")
        if not boundary or not body.startswith(delim):
            return MaskedBody(None, MaskStats(), refused="unparseable")
        chunks = body.split(b"\r\n" + delim)
        first = chunks[0][len(delim):]          # b"\r\n<headers>\r\n\r\n<data>"
        total, out = MaskStats(), [chunks[0][:len(delim)]]
        try:
            for i, chunk in enumerate([first] + chunks[1:]):
                if chunk.startswith(b"--"):     # the closing delimiter and whatever trails it
                    out.append(chunk)
                    continue
                head, sep, data = chunk.partition(b"\r\n\r\n")
                if not sep:
                    return MaskedBody(None, MaskStats(), refused="unparseable")
                part_ct = next((ln.split(b":", 1)[1].decode("latin-1").strip() for ln in head.split(b"\r\n")
                                if ln.lower().startswith(b"content-type:")), "")
                if files_only and b"filename=" not in head.lower():
                    out.append(chunk)
                    continue
                masked, st = self.mask_file(data, part_ct, style)
                _merge(total, st)
                out.append(head + sep + masked)
        except (TypeError, ValueError, UnicodeEncodeError, UnicodeDecodeError):
            return MaskedBody(None, MaskStats(), refused="mask-failed")
        if not out[-1].startswith(b"--"):
            return MaskedBody(None, MaskStats(), refused="unparseable")
        return MaskedBody(out[0] + (b"\r\n" + delim).join(out[1:]), total)

    # ------------------------------------------------------------ restoring
    def restore_json(self, obj, sent: bytes | None = None, received: bytes | None = None):
        """``sent`` / ``received``: the request as it left (masked) and as it
        arrived. When given, only the stand-ins this request produced are put
        back (``MaskingSession.scoped``)."""
        return restore_body(self._restorer(sent, received), obj)

    def _restorer(self, sent: bytes | None, received: bytes | None):
        if sent is None:
            return self.session
        text = lambda b: (b or b"").decode("utf-8", errors="replace")  # noqa: E731
        return self.session.scoped(text(sent), text(received))

    def restore_text(self, text: str, json_escape: bool = False) -> str:
        return self.session.restore_text(text, json_escape=json_escape)

    def sse_restorer(self, sent: bytes | None = None, received: bytes | None = None) -> StreamRestorer:
        """For Anthropic / OpenAI shaped SSE (the API door's formats).
        ``sent`` / ``received`` as in ``restore_json``."""
        return StreamRestorer(self._restorer(sent, received))

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
