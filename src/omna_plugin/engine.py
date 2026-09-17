"""The masking session: the compiled Omna engine plus a stable token registry.

The ``omna-pii-mask`` wheel numbers tokens per call (``[EMAIL_1]`` is "the
first email in *this* text"). A proxy needs the same real value to become the
same token in every request, otherwise the conversation the AI sees changes
between turns, which defeats prompt caching and trips Claude Code's
preserved-thinking check. This module renames the engine's per-call tokens to
registry-stable ones and persists the registry under ``OMNA_HOME``.

Secrets never enter the registry: the engine redacts them irreversibly as
``[REDACTED:<KIND>]`` and they are never restored.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

import omna_pii_mask

from . import config

# Reversible tokens the engine emits: [PERSON_1], [EMAIL_12], [GOV_ID_3] ...
TOKEN_RE = re.compile(r"\[([A-Z][A-Z0-9_]*?)_(\d+)\]")
# Irreversible redactions: [REDACTED:AWS_KEY]
REDACTED_RE = re.compile(r"\[REDACTED:([A-Z0-9_]+)\]")

_CACHE_SIZE = 4096


@dataclass
class MaskResult:
    masked: str
    counts: dict[str, int] = field(default_factory=dict)  # entity name -> occurrences


class MaskingSession:
    """One engine + one registry. Safe to share across requests in one process."""

    def __init__(self, smart: bool = False):
        self.smart = smart
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, MaskResult] = OrderedDict()
        self.cache_hits = 0
        config.ensure_home()
        self._registry_file = config.registry_path()
        self._value_to_token: dict[str, str] = {}  # "KIND\x00value" -> token
        self._token_to_value: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._load_registry()

    # ------------------------------------------------------------------ registry
    def _load_registry(self) -> None:
        if not self._registry_file.exists():
            return
        try:
            data = json.loads(self._registry_file.read_text())
        except (OSError, ValueError):
            return
        self._token_to_value = dict(data.get("tokens", {}))
        self._counters = dict(data.get("counters", {}))
        for tok, val in self._token_to_value.items():
            m = TOKEN_RE.fullmatch(tok)
            if m:
                self._value_to_token[f"{m.group(1)}\x00{val}"] = tok

    def _save_registry(self) -> None:
        tmp = self._registry_file.with_suffix(".json.tmp")
        payload = {"tokens": self._token_to_value, "counters": self._counters}
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        os.replace(tmp, self._registry_file)

    def _stable_token(self, kind: str, value: str) -> str:
        key = f"{kind}\x00{value}"
        tok = self._value_to_token.get(key)
        if tok:
            return tok
        n = self._counters.get(kind, 0) + 1
        self._counters[kind] = n
        tok = f"[{kind}_{n}]"
        self._value_to_token[key] = tok
        self._token_to_value[tok] = value
        return tok

    def forget(self) -> None:
        """Wipe the registry and cache (``omna forget``)."""
        with self._lock:
            self._value_to_token.clear()
            self._token_to_value.clear()
            self._counters.clear()
            self._cache.clear()
            if self._registry_file.exists():
                self._registry_file.unlink()

    @property
    def registry_size(self) -> int:
        return len(self._token_to_value)

    # ------------------------------------------------------------------ ruleset
    def _ruleset_arg(self) -> str | None:
        p = config.ruleset_path()
        return str(p) if p.exists() else None

    def allow(self, value: str) -> None:
        """Never mask this exact value again (false-positive allowlist)."""
        p = config.ruleset_path()
        data: dict = {"allowlist": [], "custom_rules": []}
        if p.exists():
            try:
                data = json.loads(p.read_text())
            except ValueError:
                pass
        data.setdefault("allowlist", [])
        pat = re.escape(value)
        if pat not in data["allowlist"]:
            data["allowlist"].append(pat)
        p.write_text(json.dumps(data, indent=2))
        with self._lock:
            self._cache.clear()

    # ------------------------------------------------------------------ masking
    def mask_text(self, text: str) -> MaskResult:
        if len(text) < 3:
            return MaskResult(text)
        key = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None:
                self._cache.move_to_end(key)
                self.cache_hits += 1
                return hit
        raw = omna_pii_mask.mask(text, model=self.smart, ruleset=self._ruleset_arg())
        masked: str = raw["masked"]
        counts: dict[str, int] = {}
        for span in raw["spans"]:
            counts[span["entity"]] = counts.get(span["entity"], 0) + 1
        with self._lock:
            mapping: dict[str, str] = {}
            before = len(self._token_to_value)
            for tok, val in raw["tokens"].items():
                m = TOKEN_RE.fullmatch(tok)
                if not m:
                    continue
                stable = self._stable_token(m.group(1), val)
                if stable != tok:
                    mapping[tok] = stable
            if mapping:
                masked = TOKEN_RE.sub(lambda m: mapping.get(m.group(0), m.group(0)), masked)
            if len(self._token_to_value) != before:
                self._save_registry()
            result = MaskResult(masked, counts)
            self._cache[key] = result
            if len(self._cache) > _CACHE_SIZE:
                self._cache.popitem(last=False)
        return result

    def restore_text(self, text: str) -> str:
        if "[" not in text:
            return text
        t2v = self._token_to_value
        return TOKEN_RE.sub(lambda m: t2v.get(m.group(0), m.group(0)), text)

    def lookup(self, token: str) -> str | None:
        return self._token_to_value.get(token)


def engine_version() -> str:
    return omna_pii_mask.version()


def registry_file_exists() -> bool:
    return Path(config.registry_path()).exists()
