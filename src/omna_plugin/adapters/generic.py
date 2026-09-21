from __future__ import annotations

from ..pipeline import MaskStats, Pipeline
from ..style import TOKENS
from .base import ENDPOINT_RE, MaskOutcome, RequestView, ResponseMode

_MASKABLE = ("json", "x-www-form-urlencoded", "text/")


class GenericAdapter:
    """Default for every AI host: mask every prose string in a prompt body; refuse what we cannot parse."""

    name = "generic"
    hosts: tuple[str, ...] = ()

    def is_prompt(self, req: RequestView) -> bool:
        return req.method in ("POST", "PUT", "PATCH") and ENDPOINT_RE.search(req.path) is not None

    def mask(self, pipeline: Pipeline, req: RequestView, style: str = TOKENS) -> MaskOutcome:
        ct = (req.content_type or "").lower()
        maskable = any(m in ct for m in _MASKABLE)
        if not self.is_prompt(req):
            if maskable and req.body:
                out = pipeline.mask_bytes(req.body, ct, style)   # best effort on non-prompt text; never refuse
                if out.refused is None:
                    return MaskOutcome(out.body, out.stats)
            return MaskOutcome(None, MaskStats(), passthrough=True)
        if not req.body:
            return MaskOutcome(None, MaskStats(), passthrough=True)
        if not maskable:
            return MaskOutcome(None, MaskStats(), refused="unparseable")
        out = pipeline.mask_bytes(req.body, ct, style)
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
