"""The masking session: the compiled Omna engine plus stable token registries.

The ``omna-pii-mask`` wheel numbers tokens per call (``[EMAIL_1]`` is "the
first email in *this* text"). A proxy needs the same real value to become the
same token in every request, otherwise the conversation the AI sees changes
between turns, which defeats prompt caching and trips Claude Code's
preserved-thinking check. So we rebuild the masked text ourselves from the
engine's spans, using two registries:

- **PII registry** (persisted to ``OMNA_HOME/registry.json``, 0600, and
  encrypted with a key in the macOS Keychain — see ``vault.py``): reversible
  personal data such as an EMAIL or PERSON token.
- **Secrets registry** (memory only, never written to disk): ``[SECRET_AWS_KEY_1]``.
  The provider never sees the secret. It is put back only in what comes BACK
  from the model (replies and tool calls), so an edit to a line containing a
  key still matches the file on disk. ``restore_secrets=False`` gives the
  engine's irreversible ``[REDACTED:<KIND>]`` behaviour instead.

Rebuilding from spans also fixes an engine quirk where a secret span swallows
its trailing newline (logged in omna-workspace MASTER #123).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass, field

import omna_pii_mask

from . import config, vault

# Reversible tokens: [PERSON_1], [EMAIL_12], [GOV_ID_3], [SECRET_AWS_KEY_2] ...
TOKEN_RE = re.compile(r"\[([A-Z][A-Z0-9_]*?)_(\d+)\]")
# The engine's irreversible form: [REDACTED:AWS_KEY]
REDACTED_RE = re.compile(r"\[REDACTED:([A-Z0-9_]+)\]")
SECRET_PREFIX = "SECRET_"

_CACHE_SIZE = 4096

# A secret span that starts with an assignment ("STRIPE_KEY=sk_…", "password: x",
# "?token=…"): keep the NAME and separator outside the token so the model still
# knows WHICH secret a line holds (omna-workspace MASTER #126).
_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.\- ]{0,63}?\s*[:=]\s*)(\S.*)$", re.DOTALL)

# Values that are never worth masking on a developer machine. Written into a
# fresh ``ruleset.json`` so the user can see and edit them. Allowlist regexes
# must FULL-match the detected value (engine rule).
DEFAULT_ALLOWLIST = [r"127\.0\.0\.1", r"0\.0\.0\.0", r"::1", r"localhost"]


@dataclass
class MaskResult:
    masked: str
    counts: dict[str, int] = field(default_factory=dict)  # entity name -> occurrences
    secrets: int = 0  # spans from L2 (Secrets)
    pii: int = 0      # every other span
    # Which layer found each catch: L1 deterministic (regex+checksum), L2
    # secrets, L3 the contextual model. Worth keeping separate because these
    # are NOT the same kind of certainty — see `validated`.
    by_layer: dict[str, int] = field(default_factory=dict)
    # Catches a checksum actually validated (IBAN, card, national IDs). This
    # is stronger than any confidence score: a validated card number is not
    # "92% likely a card", it is arithmetically a card. A confidence average
    # across layers would blend fixed per-rule weights with real model
    # probabilities and mean nothing, so we surface this instead.
    validated: int = 0


class MaskingSession:
    """One engine + registries. Safe to share across requests in one process."""

    def __init__(self, smart: bool = False, restore_secrets: bool = True):
        self.smart = smart
        self.restore_secrets = restore_secrets
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, MaskResult] = OrderedDict()
        self.cache_hits = 0
        config.ensure_home()
        self._registry_file = config.registry_path()
        self._value_to_token: dict[str, str] = {}  # "KIND\x00value" -> token
        self._token_to_value: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        # secrets: memory only
        self._secret_value_to_token: dict[str, str] = {}
        self._secret_token_to_value: dict[str, str] = {}
        self._secret_counters: dict[str, int] = {}
        # At-rest state (#131), surfaced by `omna status` and /omna/health.
        self._key: bytes | None = None
        self.encrypted = False  # the file on disk is sealed
        self.locked = False     # the file is sealed and we CANNOT open it
        self._load_registry()
        self._ensure_default_ruleset()

    # ------------------------------------------------------------------ registry
    def _load_registry(self) -> None:
        """Read the registry, minting or fetching its key, and record the at-rest state.

        Three outcomes, all of which must leave a working masker behind:
        healthy-encrypted, healthy-plaintext (no Keychain here), and *locked* —
        the file is sealed but the key is gone. Locked keeps masking with
        fresh in-memory numbering and refuses to save, because writing a new
        registry over one we cannot read would destroy every mapping the
        person still has.
        """
        # create=True only matters the first time; after that it is a read.
        self._key = vault.load_key(create=True)
        if not self._registry_file.exists():
            self.encrypted = self._key is not None
            return
        try:
            text = self._registry_file.read_text()
        except OSError:
            return
        was_sealed = vault.is_sealed(text)
        if was_sealed:
            try:
                data = vault.open_sealed(text, self._key)
            except vault.RegistryLocked:
                self.locked = True
                self.encrypted = True
                return
        else:
            try:
                data = json.loads(text)
            except ValueError:
                # Same as before #131: an unreadable plaintext file starts over.
                self.encrypted = self._key is not None
                return
            if not isinstance(data, dict):
                self.encrypted = self._key is not None
                return
        self._token_to_value = dict(data.get("tokens", {}))
        self._counters = dict(data.get("counters", {}))
        for tok, val in self._token_to_value.items():
            m = TOKEN_RE.fullmatch(tok)
            if m:
                self._value_to_token[f"{m.group(1)}\x00{val}"] = tok
        self.encrypted = self._key is not None
        if self.encrypted and not was_sealed:
            # Upgrade path: a registry written before #131 is sealed on the
            # first run that has a key, without waiting for the next mask.
            self._save_registry()

    def _save_registry(self) -> None:
        if self.locked:
            return
        payload = {"tokens": self._token_to_value, "counters": self._counters}
        body = vault.seal(payload, self._key) if self._key else json.dumps(payload)
        tmp = self._registry_file.with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(body)
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

    def _secret_token(self, kind: str, value: str) -> str:
        key = f"{kind}\x00{value}"
        tok = self._secret_value_to_token.get(key)
        if tok:
            return tok
        n = self._secret_counters.get(kind, 0) + 1
        self._secret_counters[kind] = n
        tok = f"[{SECRET_PREFIX}{kind}_{n}]"
        self._secret_value_to_token[key] = tok
        self._secret_token_to_value[tok] = value
        return tok

    def forget(self) -> None:
        """Wipe the registries, the cache and the key (``omna forget``).

        The key goes too: leaving it in the Keychain after the file it opens is
        gone is litter, and this is also the only way out of a locked registry.
        """
        with self._lock:
            self._value_to_token.clear()
            self._token_to_value.clear()
            self._counters.clear()
            self._secret_value_to_token.clear()
            self._secret_token_to_value.clear()
            self._secret_counters.clear()
            self._cache.clear()
            if self._registry_file.exists():
                self._registry_file.unlink()
            vault.delete_key()
            self._key = None
            self.locked = False
            self.encrypted = False

    @property
    def registry_size(self) -> int:
        return len(self._token_to_value)

    @property
    def at_rest(self) -> str:
        """'encrypted' | 'locked' | 'plaintext' — what protects registry.json."""
        if self.locked:
            return "locked"
        return "encrypted" if self.encrypted else "plaintext"

    @property
    def secrets_held(self) -> int:
        return len(self._secret_token_to_value)

    # ------------------------------------------------------------------ ruleset
    def _ensure_default_ruleset(self) -> None:
        p = config.ruleset_path()
        if not p.exists():
            p.write_text(json.dumps({"allowlist": DEFAULT_ALLOWLIST, "custom_rules": []}, indent=2) + "\n")

    def _ruleset_arg(self) -> str | None:
        p = config.ruleset_path()
        return str(p) if p.exists() else None

    def allow(self, value: str) -> None:
        """Never mask this exact value again (false-positive allowlist)."""
        p = config.ruleset_path()
        data: dict = {"allowlist": list(DEFAULT_ALLOWLIST), "custom_rules": []}
        if p.exists():
            try:
                data = json.loads(p.read_text())
            except ValueError:
                pass
        data.setdefault("allowlist", [])
        pat = re.escape(value)
        if pat not in data["allowlist"]:
            data["allowlist"].append(pat)
        p.write_text(json.dumps(data, indent=2) + "\n")
        with self._lock:
            self._cache.clear()

    # ------------------------------------------------------------------ masking
    @staticmethod
    def _kind_of(token: str) -> tuple[str, bool]:
        """('AWS_KEY', True) for [REDACTED:AWS_KEY]; ('EMAIL', False) for [EMAIL_3]."""
        m = REDACTED_RE.fullmatch(token)
        if m:
            return m.group(1), True
        m = TOKEN_RE.fullmatch(token)
        if m:
            return m.group(1), False
        return "", False

    def _rebuild(self, text: str, spans: list[dict]) -> tuple[str, bool]:
        """Rebuild the masked text from spans with our stable tokens.

        Returns (masked, registry_changed). Whitespace at either edge of a span
        stays outside the token, so line structure survives.
        """
        out: list[str] = []
        pos = 0
        changed_before = len(self._token_to_value)
        for sp in sorted(spans, key=lambda s: (s["start"], -s["end"])):
            start, end = sp["start"], sp["end"]
            if start < pos or end <= start:
                continue  # overlap or empty: the previous span already covered it
            value = text[start:end]
            lead = len(value) - len(value.lstrip())
            trail = len(value) - len(value.rstrip())
            core = value[lead: len(value) - trail] if trail else value[lead:]
            kind, is_secret = self._kind_of(sp["token"])
            if not kind or not core:
                continue
            name = ""
            if is_secret:
                m = _ASSIGN_RE.match(core)
                if m:
                    name, core = m.group(1), m.group(2)
                tok = self._secret_token(kind, core) if self.restore_secrets else sp["token"]
            else:
                tok = self._stable_token(kind, core)
            out.append(text[pos:start])
            out.append(value[:lead])
            out.append(name)
            out.append(tok)
            if trail:
                out.append(value[len(value) - trail:])
            pos = end
        out.append(text[pos:])
        return "".join(out), len(self._token_to_value) != changed_before

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
        counts: dict[str, int] = {}
        by_layer: dict[str, int] = {}
        n_secret = n_pii = n_validated = 0
        for span in raw["spans"]:
            counts[span["entity"]] = counts.get(span["entity"], 0) + 1
            layer = span.get("layer") or "?"
            by_layer[layer] = by_layer.get(layer, 0) + 1
            if span.get("validated"):
                n_validated += 1
            if layer == "L2":
                n_secret += 1
            else:
                n_pii += 1
        with self._lock:
            masked, changed = self._rebuild(text, raw["spans"]) if raw["spans"] else (text, False)
            if changed:
                self._save_registry()
            result = MaskResult(masked, counts, n_secret, n_pii, by_layer, n_validated)
            self._cache[key] = result
            if len(self._cache) > _CACHE_SIZE:
                self._cache.popitem(last=False)
        return result

    def lookup(self, token: str) -> str | None:
        v = self._token_to_value.get(token)
        if v is None:
            v = self._secret_token_to_value.get(token)
        return v

    def restore_text(self, text: str) -> str:
        if "[" not in text:
            return text
        return TOKEN_RE.sub(lambda m: self.lookup(m.group(0)) if self.lookup(m.group(0)) is not None else m.group(0), text)


def engine_version() -> str:
    return omna_pii_mask.version()


def registry_status() -> dict:
    """What protects ``registry.json`` and how much it holds — cheaply.

    ``omna status`` must be able to answer "where do the real values live, and
    are they encrypted?" without building an engine or minting a key, so this
    reads the file and only *looks up* an existing key (``create=False``).
    ``entries`` is None when the file is locked, because the count itself is
    inside the sealed part.
    """
    path = config.registry_path()
    out = {"path": str(path), "at_rest": "empty", "entries": 0,
           "keychain": vault.keychain_supported()}
    state = vault.file_state(path)
    if state == "missing":
        return out
    try:
        text = path.read_text()
    except OSError:
        return out
    if state == "encrypted":
        try:
            data = vault.open_sealed(text, vault.load_key(create=False))
        except vault.RegistryLocked:
            return {**out, "at_rest": "locked", "entries": None}
        return {**out, "at_rest": "encrypted", "entries": len(data.get("tokens", {}))}
    try:
        data = json.loads(text)
    except ValueError:
        data = {}
    n = len(data.get("tokens", {})) if isinstance(data, dict) else 0
    return {**out, "at_rest": "plaintext", "entries": n}
