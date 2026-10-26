from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qs, urlsplit

from ..pipeline import MaskStats, Pipeline
from ..style import TOKENS
from .base import MaskOutcome, RequestView, ResponseMode

# Some AI sites send an attached file to a SHARED storage server the moment it
# is attached, before Send (live test 2026-10-24, MASTER #157). Those servers
# also hold the person's own files and backups, so each adapter here masks ONLY
# that AI's upload — a backup stored with placeholders in it would be ruined.
# Masking changes a file's size, so a file sent in pieces is refused when a
# piece needs masking (the pieces would no longer add up), never sent unmasked.

_COPILOT_REFERERS = ("copilot.com", "copilot.microsoft.com")
_COPILOT_APP = "M365Chat"                 # app_displayname "M365ChatClient" on the upload pass
_RANGE_RE = re.compile(r"bytes (\d+)-(\d+)/(\d+)")


def _piece(stats: MaskStats) -> MaskOutcome:
    """A file sent in pieces, and this piece is not all of it. It cannot be
    checked: a value can be cut across two pieces ("jane.doe@ex" | "ample.com")
    and the middle of a Word or Excel file is not readable on its own. Such a
    piece used to go out whenever masking it changed nothing (architecture
    review, MASTER #177). Now it is refused — unless it is recognisably a kind
    Omna never masks anyway (a picture, a PDF), which goes as a whole file of
    that kind would, marked "file NOT masked" in the receipt."""
    if stats.not_masked:
        return MaskOutcome(None, stats)
    return MaskOutcome(None, stats, refused="unmaskable-chunk")


def _header(req: RequestView, name: str) -> str:
    return next((v for k, v in req.headers.items() if k.lower() == name.lower()), "")


def _from(req: RequestView, hosts: tuple[str, ...]) -> bool:
    referer = urlsplit(_header(req, "Referer")).hostname or ""
    return any(referer == h or referer.endswith("." + h) for h in hosts)


def _made_for_copilot(req: RequestView) -> bool:
    if _from(req, _COPILOT_REFERERS):
        return True
    # The upload address carries a pass (tempauth) naming the app it was made
    # for. Only read to recognise Copilot, never checked or changed.
    token = (parse_qs(urlsplit(req.path).query).get("tempauth") or [""])[0]
    parts = token.split(".")
    if len(parts) < 2:
        return False
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return False
    return isinstance(claims, dict) and str(claims.get("app_displayname", "")).startswith(_COPILOT_APP)


class CopilotOneDriveAdapter:
    """my.microsoftpersonalcontent.com (OneDrive): Copilot PUTs the whole file to
    an upload address Microsoft made for Copilot's app. Mask that, pass the rest."""

    name = "copilot-onedrive"
    hosts: tuple[str, ...] = ("my.microsoftpersonalcontent.com",)
    # The OneDrive app syncs through this host too; it never talks to an AI,
    # so its connections are not even opened (see system_door.tls_clienthello).
    skip_apps: tuple[str, ...] = ("OneDrive",)

    def is_prompt(self, req: RequestView) -> bool:
        return req.method == "PUT" and "/uploadSession" in req.path and _made_for_copilot(req)

    def mask(self, pipeline: Pipeline, req: RequestView, style: str = TOKENS) -> MaskOutcome:
        if not self.is_prompt(req) or not req.body:
            return MaskOutcome(None, MaskStats(), passthrough=True)
        masked, stats = pipeline.mask_file(req.body, req.content_type, style)
        m = _RANGE_RE.fullmatch(_header(req, "Content-Range").strip())
        whole = bool(m and int(m[1]) == 0 and int(m[2]) + 1 == int(m[3]) == len(req.body))
        if not whole:
            return _piece(stats)
        if masked == req.body:
            return MaskOutcome(None, stats)
        return MaskOutcome(masked, stats, headers={"Content-Range": f"bytes 0-{len(masked) - 1}/{len(masked)}"})

    def response_mode(self, content_type: str) -> ResponseMode:
        return "passthrough"


class ChatGptStorageAdapter:
    """*.oaiusercontent.com (ChatGPT's own file storage): at attach time ChatGPT
    first tells chatgpt.com the file's size, then PUTs the raw file here, and
    refuses the file when the two differ ("file_size_mismatch", live
    2026-10-25). So the masked file is made exactly the original size; when it
    cannot be, the upload is refused, never sent unmasked."""

    name = "chatgpt-storage"
    hosts: tuple[str, ...] = ("oaiusercontent.com",)
    skip_apps: tuple[str, ...] = ()

    def is_prompt(self, req: RequestView) -> bool:
        return req.method == "PUT" and req.path.split("?")[0].endswith("/raw")

    def mask(self, pipeline: Pipeline, req: RequestView, style: str = TOKENS) -> MaskOutcome:
        if not self.is_prompt(req) or not req.body:
            return MaskOutcome(None, MaskStats(), passthrough=True)
        masked, stats = pipeline.mask_file_same_size(req.body, req.content_type, style)
        if masked is None:
            return MaskOutcome(None, stats, refused="unmaskable-size")
        if masked == req.body:
            return MaskOutcome(None, stats)
        return MaskOutcome(masked, stats)

    def response_mode(self, content_type: str) -> ResponseMode:
        return "passthrough"


class GeminiUploadAdapter:
    """push.clients6.google.com (Google's upload server): Gemini sends "start"
    (promising the size), then "upload, finalize" with the raw file. Mask the
    file, and drop the size promise — it is optional, and the masked file is
    a different size. Only Gemini's tenant is touched."""

    name = "gemini-upload"
    hosts: tuple[str, ...] = ("push.clients6.google.com",)
    skip_apps: tuple[str, ...] = ()

    def is_prompt(self, req: RequestView) -> bool:
        return req.method in ("POST", "PUT") and (
            _header(req, "X-Tenant-Id") == "bard-storage" or _from(req, ("gemini.google.com",)))

    def mask(self, pipeline: Pipeline, req: RequestView, style: str = TOKENS) -> MaskOutcome:
        if not self.is_prompt(req):
            return MaskOutcome(None, MaskStats(), passthrough=True)
        command = {c.strip() for c in _header(req, "X-Goog-Upload-Command").lower().split(",")}
        if "start" in command:
            return MaskOutcome(None, MaskStats(), headers={"X-Goog-Upload-Header-Content-Length": None})
        if "upload" not in command or not req.body:
            return MaskOutcome(None, MaskStats(), passthrough=True)
        # The label says web form; it is the raw file. Never parse it as a form.
        masked, stats = pipeline.mask_file(req.body, "", style)
        if "finalize" not in command or _header(req, "X-Goog-Upload-Offset").strip() not in ("", "0"):
            return _piece(stats)
        if masked == req.body:
            return MaskOutcome(None, stats)
        return MaskOutcome(masked, stats)

    def response_mode(self, content_type: str) -> ResponseMode:
        return "passthrough"


class MetaAiUploadAdapter:
    """rupload.meta.ai: Meta AI uploads the attached file here at attach time.
    Meta encrypts its chat messages, but NOT this upload. It describes the file
    in its own headers (x-entity-type, x-entity-length, Offset) instead of a
    Content-Type. Mask the file and fix x-entity-length to the masked size."""

    name = "meta-ai-upload"
    hosts: tuple[str, ...] = ("rupload.meta.ai",)
    skip_apps: tuple[str, ...] = ()

    def is_prompt(self, req: RequestView) -> bool:
        return req.method in ("POST", "PUT") and bool(_header(req, "x-entity-length"))

    def mask(self, pipeline: Pipeline, req: RequestView, style: str = TOKENS) -> MaskOutcome:
        if not self.is_prompt(req) or not req.body:
            return MaskOutcome(None, MaskStats(), passthrough=True)
        masked, stats = pipeline.mask_file(req.body, _header(req, "x-entity-type"), style)
        whole = _header(req, "Offset").strip() in ("", "0") and _header(req, "x-entity-length").strip() == str(len(req.body))
        if not whole:
            return _piece(stats)
        if masked == req.body:
            return MaskOutcome(None, stats)
        return MaskOutcome(masked, stats, headers={"x-entity-length": str(len(masked))})

    def response_mode(self, content_type: str) -> ResponseMode:
        return "passthrough"


class PerplexityUploadAdapter:
    """ppl-ai-file-upload.s3.amazonaws.com: Perplexity's own bucket on Amazon S3
    (only Perplexity's files live there). The attached file goes up in a signed
    upload form; the signature parts must arrive exactly as signed, so only the
    file part is masked (MASTER #176, live 2026-10-25: it went out unmasked)."""

    name = "perplexity-upload"
    hosts: tuple[str, ...] = ("ppl-ai-file-upload.s3.amazonaws.com",)
    skip_apps: tuple[str, ...] = ()

    def is_prompt(self, req: RequestView) -> bool:
        return req.method in ("POST", "PUT")

    def mask(self, pipeline: Pipeline, req: RequestView, style: str = TOKENS) -> MaskOutcome:
        if not self.is_prompt(req) or not req.body:
            return MaskOutcome(None, MaskStats(), passthrough=True)
        if "multipart/form-data" in req.content_type.lower():
            out = pipeline.mask_upload_form(req.body, req.content_type, style)
            if out.body is None:
                return MaskOutcome(None, out.stats, refused=out.refused)
            return MaskOutcome(None if out.body == req.body else out.body, out.stats)
        masked, stats = pipeline.mask_file(req.body, req.content_type, style)
        return MaskOutcome(None if masked == req.body else masked, stats)

    def response_mode(self, content_type: str) -> ResponseMode:
        return "passthrough"
