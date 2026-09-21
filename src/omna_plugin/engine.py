"""The masking session: the compiled Omna engine plus stable value registries.

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

**Two styles.** By default a masked value is written as a numbered token. In
the *realistic* style (``style=REALISTIC``, allowed only at the doors
``style.py`` permits) it is written as a realistic fake value instead —
``robert.jones@example.org`` rather than a bracketed token. That needs a third
registry, ``fakes``, persisted beside the tokens because a fake must be the
same after a restart or the provider's prompt cache is thrown away. Restoring
then cannot lean on brackets any more: it matches the registry's own keys.
Secrets never enter this path at all — a fake API key that looked real would be
the worst output this program could produce.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

import omna_pii_mask

from . import config, fakes, vault
from .style import REALISTIC, TOKENS

# Reversible tokens: [PERSON_1], [EMAIL_12], [GOV_ID_3], [SECRET_AWS_KEY_2] ...
TOKEN_RE = re.compile(r"\[([A-Z][A-Z0-9_]*?)_(\d+)\]")
# The engine's irreversible form: [REDACTED:AWS_KEY]
REDACTED_RE = re.compile(r"\[REDACTED:([A-Z0-9_]+)\]")
SECRET_PREFIX = "SECRET_"

_CACHE_SIZE = 4096

# Text that could still turn into a token once the next stream chunk arrives,
# and the longest such run worth holding back ("[" + kind + "_" + digits).
_TOKEN_PREFIX_RE = re.compile(r"\[[A-Z0-9_]*$")
_MAX_TOKEN_HOLD = 48

# How many times a colliding fake value is regenerated before we give up and
# use the numbered token instead. Giving up is safe: the token is the loud form.
_FAKE_ATTEMPTS = 8

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
    # The numbered token names minted for this text ("EMAIL_1"), whatever style
    # was used. Receipts count these, so the audit trail stays identical when
    # the masked text carries realistic fake values and no brackets at all.
    labels: list[str] = field(default_factory=list)


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
        # Realistic style: fake value <-> real value, persisted with the tokens
        # (same file, same encryption) because a fake must survive a restart or
        # the provider's prompt cache is thrown away on every restart.
        self._value_to_fake: dict[str, str] = {}   # "KIND\x00value" -> fake
        self._fake_to_value: dict[str, str] = {}
        self._fake_prefixes: set[str] = set()      # every proper prefix, for stream hold-back
        self._max_fake_len = 0
        self._real_values: set[str] = set()        # what a fake must never collide with
        self._fake_salt = b""
        # Per-mapping metadata for the Mappings Review screen (#144): which
        # layer caught it, whether a checksum validated it, which style was
        # last used to write it, and when it was first seen. Keyed the same
        # way as `_value_to_fake` ("KIND\x00value") so all three registries
        # agree on identity. A row written before this existed has no entry
        # here — `registry_rows()` must report that honestly, never guess.
        self._meta: dict[str, dict] = {}
        self._restore_re: re.Pattern | None = None
        # At-rest state (#131), surfaced by `omna status` and /omna/health.
        self._key: bytes | None = None
        self.encrypted = False  # the file on disk is sealed
        self.locked = False     # the file is sealed and we CANNOT open it
        self._load_registry()
        self._ensure_default_ruleset()

    # ------------------------------------------------------------------ registry
    def _load_registry(self) -> None:
        """Read the registry, minting or fetching its key, and record the at-rest state.

        A sealed file we cannot open splits into two VERY different cases, and
        treating them the same was the bug (owner, 2026-09-20):

        - **The Keychain is out of reach** (``OMNA_REGISTRY_ENCRYPTION=off``, a
          Linux box, a locked login keychain). The key may be perfectly fine —
          we simply cannot get to it right now. Touching the file here could
          destroy mappings that are still recoverable, so we go ``locked``:
          keep masking, save nothing, say so loudly.
        - **The Keychain works and still cannot open this file.** The key is
          gone for good, so the file is unreadable *forever* — no amount of
          waiting brings it back. Refusing to save just leaves a permanently
          broken masker that renumbers on every restart. So we move the dead
          file aside and start a fresh encrypted registry.

        The old mappings are lost either way; the difference is whether Omna
        keeps working afterwards.
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
                self.encrypted = True
                if not vault.keychain_supported():
                    self.locked = True   # recoverable later; do not touch the file
                    return
                self._retire_unreadable_registry()
                data = {}
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
                self._real_values.add(val)
        # Fakes are stored by their own registry key ("KIND\x00value") so both
        # directions come back from one dict.
        for key, fake in dict(data.get("fakes", {})).items():
            kind, _, val = key.partition("\x00")
            if val and fake:
                self._remember_fake(fake, val, kind)
        self._meta = dict(data.get("meta", {}))
        try:
            self._fake_salt = bytes.fromhex(str(data.get("fake_salt", "")))
        except ValueError:
            self._fake_salt = b""
        self.encrypted = self._key is not None
        if self.encrypted and not was_sealed:
            # Upgrade path: a registry written before #131 is sealed on the
            # first run that has a key, without waiting for the next mask.
            self._save_registry()

    def _retire_unreadable_registry(self) -> None:
        """Move a permanently-unreadable registry aside so a fresh one can start.

        Renamed rather than deleted: it costs nothing, it leaves evidence that
        something happened, and if the key ever turns up (restored from a
        backup keychain, say) the file is still there to open. The new name
        carries a timestamp so a second occurrence cannot overwrite the first.
        """
        stamp = __import__("datetime").datetime.now().strftime("%Y%m%d-%H%M%S")
        dead = self._registry_file.with_name(f"{self._registry_file.name}.unreadable-{stamp}")
        try:
            os.replace(self._registry_file, dead)
        except OSError:
            return
        print(f"omna: the registry key is missing from your Keychain, so "
              f"{self._registry_file.name} can no longer be opened. It was kept as "
              f"{dead.name} and a new encrypted registry was started. Tokens restart from 1.",
              file=__import__("sys").stderr)

    def _save_registry(self) -> None:
        if self.locked:
            return
        payload = {"tokens": self._token_to_value, "counters": self._counters,
                   "fakes": self._value_to_fake, "fake_salt": self._fake_salt.hex(),
                   "meta": self._meta}
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

    # ------------------------------------------------------------ fake values
    def _salt(self) -> bytes:
        """Per-machine, random, persisted with the registry.

        Without it a fake would be a pure function of the real value, so anyone
        holding the fake could confirm a guess at the real one by running the
        same function over their guess. Minted on first use.
        """
        if not self._fake_salt:
            self._fake_salt = os.urandom(16)
        return self._fake_salt

    def _remember_fake(self, fake: str, value: str, kind: str) -> None:
        self._fake_to_value[fake] = value
        self._value_to_fake[f"{kind}\x00{value}"] = fake
        self._max_fake_len = max(self._max_fake_len, len(fake))
        for i in range(1, len(fake)):
            self._fake_prefixes.add(fake[:i])
        self._restore_re = None      # the combined restore pattern must be rebuilt

    def _stable_fake(self, kind: str, entity: str, value: str, text: str) -> str | None:
        """A realistic stand-in for ``value``, reused for ever once minted.

        Returns None when there is no generator for this entity (always the case
        for a secret) or when every attempt collided. The caller then uses the
        numbered token, which is the loud and therefore safe form.

        The four collision checks each prevent a different corruption: a fake
        equal to the real value is not a mask at all; a fake already present in
        the text would be put back as the wrong thing on restore; a fake that is
        somebody's real value elsewhere is the same bug one step removed; and a
        fake already standing for another value would restore to that one.
        """
        key = f"{kind}\x00{value}"
        have = self._value_to_fake.get(key)
        if have:
            return have
        for attempt in range(_FAKE_ATTEMPTS):
            cand = fakes.fake_for(entity, value, salt=self._salt(), attempt=attempt)
            if cand is None:
                return None
            if cand == value or cand in text or cand in self._real_values:
                continue
            other = self._fake_to_value.get(cand)
            if other is not None and other != value:
                continue
            self._remember_fake(cand, value, kind)
            return cand
        return None

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
            self._value_to_fake.clear()
            self._fake_to_value.clear()
            self._fake_prefixes.clear()
            self._real_values.clear()
            self._meta.clear()
            self._max_fake_len = 0
            self._fake_salt = b""
            self._restore_re = None
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

    def registry_rows(self) -> list[dict]:
        """One row per PII mapping currently held (#144 Mappings Review).

        Secrets never appear here — they never entered `_token_to_value` in
        the first place (memory-only, see the module docstring). A row
        written before per-mapping metadata existed has `layer`/`validated`/
        `style` all `None` — report that honestly rather than guessing.
        """
        with self._lock:
            rows = []
            for token, value in self._token_to_value.items():
                m = TOKEN_RE.fullmatch(token)
                if not m:
                    continue
                kind = m.group(1)
                key = f"{kind}\x00{value}"
                meta = self._meta.get(key, {})
                rows.append({
                    "label": token[1:-1],
                    "kind": kind,
                    "value": value,
                    "fake": self._value_to_fake.get(key),
                    "layer": meta.get("layer"),
                    "validated": bool(meta.get("validated")),
                    "style": meta.get("style"),
                    "created": meta.get("created"),
                })
            return rows

    def delete_mapping(self, label: str) -> bool:
        """Forget one PII mapping (#144). Removes the token, its real value,
        its metadata, AND its realistic-style fake if it has one — dropping
        only the token would leave the fake still resolving the "deleted"
        value on every future restore, which is worse than not deleting at
        all. The counter is never reused, so the label a person just deleted
        can never silently come back: the same real value gets a brand new
        token/fake on its next occurrence.
        """
        token = f"[{label}]"
        with self._lock:
            value = self._token_to_value.pop(token, None)
            if value is None:
                return False
            m = TOKEN_RE.fullmatch(token)
            kind = m.group(1) if m else ""
            key = f"{kind}\x00{value}"
            self._value_to_token.pop(key, None)
            self._real_values.discard(value)
            self._meta.pop(key, None)
            fake = self._value_to_fake.pop(key, None)
            if fake is not None:
                self._fake_to_value.pop(fake, None)
                self._fake_prefixes = set()
                self._max_fake_len = 0
                for f in self._fake_to_value:
                    self._max_fake_len = max(self._max_fake_len, len(f))
                    for i in range(1, len(f)):
                        self._fake_prefixes.add(f[:i])
                self._restore_re = None
            # A cached MaskResult for identical future text would otherwise
            # hand back the just-deleted token/fake (see `allow()`, same fix).
            self._cache.clear()
            self._save_registry()
            return True

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

    def _rebuild(self, text: str, spans: list[dict], style: str) -> tuple[str, list[str], bool]:
        """Rebuild the masked text from spans, in the style asked for.

        Returns (masked, labels, registry_changed). Whitespace at either edge of
        a span stays outside the replacement, so line structure survives.

        The numbered token is minted for every span whatever the style: it is
        the identifier receipts count, and it is the fallback when no realistic
        value can be made.
        """
        out: list[str] = []
        labels: list[str] = []
        pos = 0
        changed_before = (len(self._token_to_value), len(self._fake_to_value), self._fake_salt)
        meta_touched = False
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
                # Secrets never take the realistic path: a fake API key that
                # looks real is the worst output this program could produce.
                tok = self._secret_token(kind, core) if self.restore_secrets else sp["token"]
                if TOKEN_RE.fullmatch(tok):
                    labels.append(tok[1:-1])
            else:
                label = self._stable_token(kind, core)
                self._real_values.add(core)
                labels.append(label[1:-1])
                tok = label
                if style == REALISTIC:
                    tok = self._stable_fake(kind, sp.get("entity") or kind, core, text) or label
                meta_key = f"{kind}\x00{core}"
                meta = self._meta.setdefault(meta_key, {"created": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
                meta["layer"] = sp.get("layer") or meta.get("layer") or "?"
                meta["validated"] = bool(sp.get("validated"))
                meta["style"] = style
                meta_touched = True
            out.append(text[pos:start])
            out.append(value[:lead])
            out.append(name)
            out.append(tok)
            if trail:
                out.append(value[len(value) - trail:])
            pos = end
        out.append(text[pos:])
        now = (len(self._token_to_value), len(self._fake_to_value), self._fake_salt)
        return "".join(out), labels, now != changed_before or meta_touched

    def mask_text(self, text: str, style: str = TOKENS) -> MaskResult:
        if len(text) < 3:
            return MaskResult(text)
        # The style is part of the cache key: the same text masks to two
        # different things, and handing one style the other's answer would send
        # a realistic fake value to a door that refused it.
        key = style + "\x00" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
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
            masked, labels, changed = (self._rebuild(text, raw["spans"], style)
                                       if raw["spans"] else (text, [], False))
            if changed:
                self._save_registry()
            result = MaskResult(masked, counts, n_secret, n_pii, by_layer, n_validated, labels)
            self._cache[key] = result
            if len(self._cache) > _CACHE_SIZE:
                self._cache.popitem(last=False)
        return result

    def lookup(self, token: str) -> str | None:
        v = self._token_to_value.get(token)
        if v is None:
            v = self._secret_token_to_value.get(token)
        if v is None:
            v = self._fake_to_value.get(token)
        return v

    def _pattern(self) -> re.Pattern:
        """Tokens, plus every fake value we have minted.

        A fake has no brackets, so there is nothing to recognise it by except
        the registry itself. The literals go longest first so a fake that starts
        with another fake cannot be matched half-way.
        """
        with self._lock:
            if self._restore_re is None:
                parts = [TOKEN_RE.pattern]
                parts += [re.escape(f) for f in sorted(self._fake_to_value, key=len, reverse=True)]
                self._restore_re = re.compile("|".join(parts))
            return self._restore_re

    def restore_text(self, text: str, json_escape: bool = False) -> str:
        """Put the real values back. ``json_escape`` for text that is being
        spliced into a JSON string (streamed tool-call arguments)."""
        if not text or ("[" not in text and not self._fake_to_value):
            return text

        def sub(m: re.Match) -> str:
            v = self.lookup(m.group(0))
            if v is None:
                return m.group(0)
            return json.dumps(v)[1:-1] if json_escape else v

        return self._pattern().sub(sub, text)

    def hold_from(self, buf: str) -> int:
        """Where text that might still become a token or a fake value starts.

        ``len(buf)`` means "nothing to hold back". A stream can split a value
        anywhere, and a fake value has no brackets to recognise a partial one
        by, so we keep every proper prefix of every fake we have minted and hold
        back the longest suffix of the buffer that is one of them.
        """
        best = len(buf)
        m = _TOKEN_PREFIX_RE.search(buf)
        if m and len(buf) - m.start() <= _MAX_TOKEN_HOLD:
            best = m.start()
        if self._fake_prefixes:
            # Never cut through a value that has already arrived in full. A
            # complete fake can END with the first character of another one
            # ("...@example.com" followed by a fake starting with "m"), and
            # holding that character back would split the complete value across
            # two releases — so neither half would ever be recognised and the
            # fake would reach the person unrestored. Only the tail AFTER the
            # last complete match is a candidate for holding back.
            safe = 0
            for done in self._pattern().finditer(buf):
                safe = done.end()
            for i in range(max(safe, len(buf) - self._max_fake_len + 1), best):
                if buf[i:] in self._fake_prefixes:
                    return i
        return best


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
