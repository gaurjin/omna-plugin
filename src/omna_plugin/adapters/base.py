from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, Protocol

from ..pipeline import MaskStats, Pipeline
from ..style import TOKENS

# Same rule the Chrome extension uses to decide "this POST carries a prompt".
ENDPOINT_RE = re.compile(
    r"/(append_message|completion|conversation|stream|chat|generate|backend-api|message|messages|prompt|responses|complete|embeddings)",
    re.I,
)

ResponseMode = Literal["stream-json", "stream-text", "json", "passthrough"]


@dataclass
class RequestView:
    host: str
    method: str
    path: str
    content_type: str
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class MaskOutcome:
    body: bytes | None            # the masked body to forward (None = forward original, or refused)
    stats: MaskStats
    refused: str | None = None    # set → do NOT forward; answer 400
    passthrough: bool = False     # forwarded unchanged on purpose (not a prompt)


class SiteAdapter(Protocol):
    name: str
    hosts: tuple[str, ...]

    def is_prompt(self, req: RequestView) -> bool: ...
    def mask(self, pipeline: Pipeline, req: RequestView, style: str = TOKENS) -> MaskOutcome: ...
    def response_mode(self, content_type: str) -> ResponseMode: ...
