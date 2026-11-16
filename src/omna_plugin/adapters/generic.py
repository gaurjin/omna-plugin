from __future__ import annotations

from .. import protobuf, sites
from ..pipeline import MaskStats, Pipeline
from ..style import TOKENS
from .base import ENDPOINT_RE, MaskOutcome, RequestView, ResponseMode

_MASKABLE = ("json", "x-www-form-urlencoded", "text/", "multipart/form-data")
# A raw file sent on its own (ChatGPT PUTs it to its storage at attach time)
# carries the file's own label: none, "unknown type" (.env, code) or a Word /
# Excel label. For those the bytes decide (Pipeline.mask_file). Any other
# binary label (protobuf, images, audio) is a site's own format: never touched.
_FILE_LABELS = ("", "application/octet-stream", "officedocument", "application/vnd.ms-excel", "application/msword")


def _is_file_label(ct: str) -> bool:
    ct = ct.split(";")[0].strip()
    return ct in ("", "application/octet-stream") or any(m in ct for m in _FILE_LABELS[2:])


class GenericAdapter:
    """Default for every AI host: mask every prose string in a prompt body; refuse what we cannot parse."""

    name = "generic"
    hosts: tuple[str, ...] = ()

    def is_prompt(self, req: RequestView) -> bool:
        return req.method in ("POST", "PUT", "PATCH") and ENDPOINT_RE.search(req.path) is not None

    def mask(self, pipeline: Pipeline, req: RequestView, style: str = TOKENS) -> MaskOutcome:
        ct = (req.content_type or "").lower()
        maskable = any(m in ct for m in _MASKABLE)
        if req.body and sites.channel(req.host, req.path):
            # The Gemini website's messages (since 2026-11): Google's channel
            # format. Read, masked and sent on — or refused, never sent unread.
            out = pipeline.mask_channel(req.body, style)
            if out.refused:
                return MaskOutcome(None, MaskStats(), refused=out.refused)
            return MaskOutcome(None if out.body is req.body or out.body == req.body else out.body, out.stats)
        if req.body and "x-www-form-urlencoded" in ct and sites.batch(req.host, req.path):
            # The Gemini website's own calls: only what a person could have
            # typed is masked. Not that format after all → handled as before.
            out = pipeline.mask_batch(req.body, style)
            if out is not None:
                if out.refused:
                    return MaskOutcome(None, MaskStats(), refused=out.refused)
                return MaskOutcome(None if out.body is req.body or out.body == req.body else out.body, out.stats)
        if req.body and protobuf.is_packed(ct) and sites.packed(req.host, req.path):
            # The Claude desktop app's messages (5.x): read, masked, and sent
            # on — or refused when they cannot be read, never sent unread.
            out = pipeline.mask_proto(req.body, ct, style)
            if out.refused:
                return MaskOutcome(None, MaskStats(), refused=out.refused)
            return MaskOutcome(None if out.body is req.body or out.body == req.body else out.body, out.stats)
        if not maskable and req.body and _is_file_label(ct):
            masked, stats = pipeline.mask_file(req.body, req.content_type, style)
            if masked == req.body:
                return MaskOutcome(None, stats, passthrough=not self.is_prompt(req))
            return MaskOutcome(masked, stats)
        if not self.is_prompt(req):
            if maskable and req.body:
                # Best effort on non-prompt text, never refused: a site's
                # analytics can carry what you typed (Perplexity, Grok — #162),
                # but its own identifiers are left alone (``careful``, #178).
                out = pipeline.mask_bytes(req.body, req.content_type, style, careful=True)
                if out.refused is None:
                    return MaskOutcome(out.body, out.stats)
                if out.refused == "mask-failed":
                    # The masking engine failed on it. Owner decision (finding
                    # 7): not a prompt, so never blocked — but the receipt
                    # must say it went out unmasked, and why.
                    return MaskOutcome(None, MaskStats(not_masked="engine-error"), passthrough=True)
            return MaskOutcome(None, MaskStats(), passthrough=True)
        if not req.body:
            return MaskOutcome(None, MaskStats(), passthrough=True)
        if not maskable:
            return MaskOutcome(None, MaskStats(), refused="unparseable")
        out = pipeline.mask_bytes(req.body, req.content_type, style)
        return MaskOutcome(out.body, out.stats, refused=out.refused)

    def response_mode(self, content_type: str) -> ResponseMode:
        ct = (content_type or "").lower()
        if "event-stream" in ct or "x-ndjson" in ct:
            return "stream-json"
        if "json" in ct:
            return "json"
        if ct.startswith("text/"):
            return "stream-text"
        return "passthrough"
