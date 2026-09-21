# Masking Styles (tokens | realistic) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a second masking style that substitutes a realistic fake value instead of a numbered token, choosable in `policy.json` and via `omna style`, with tokens the default everywhere and the realistic style REFUSED at the API door and the deep door.

**Architecture:** One new tiny module (`style.py`) owns the whole door rule — every door asks it, nobody compares style strings themselves. A second new module (`fakes.py`) turns (entity, real value) into a deterministic realistic value. `engine.MaskingSession` grows a second registry (`fakes`) beside the token registry, persisted in the same `registry.json`, plus a restore path that no longer depends on brackets. Secrets (layer L2) never enter the fake path at all.

**Tech Stack:** Python 3.12, pytest, the compiled `omna_pii_mask` wheel, starlette/httpx (API door), mitmproxy (system/deep door).

---

## Why both styles exist (read before touching anything)

Numbered tokens fail **loudly**: a leftover `[EMAIL_` `1]` is visibly wrong and somebody notices.
A realistic fake value fails **silently**: a leftover `robert.jones@example.org` looks like ordinary
data and gets committed to a repository forever.

So the two styles are a safety trade, not a cosmetic preference:

- realistic values give the model better output for chat and prose;
- numbered tokens are the only safe choice for any tool that WRITES FILES.

Every tool behind the **API door** (Claude Code, aider, Codex, Continue, VS Code) writes files.
The **deep door** captures arbitrary desktop apps by name — which includes editors — so it is on
the refusing side of the line too. Only the **system door** (the browser / chat websites) may use
realistic values.

**If implementing this makes the refusal inconvenient, do not relax it.** Write down why in the
report instead.

---

## File structure

| File | Responsibility |
|---|---|
| `src/omna_plugin/style.py` (new) | The style names and THE door rule — one function, `style_for_door()`. Nothing else decides. |
| `src/omna_plugin/fakes.py` (new) | (entity, value, salt, attempt) → a deterministic realistic value, or `None` when we have no generator. Knows nothing about doors, policy or the registry. |
| `src/omna_plugin/engine.py` | Second registry (fake ↔ real), style-aware `mask_text`, bracket-free `restore_text`, `hold_from()` for streams. |
| `src/omna_plugin/stream.py` | Hold-back now asks the session where a partial token **or fake value** starts. |
| `src/omna_plugin/body.py` | Threads `style` through the JSON walk; returns the minted labels. |
| `src/omna_plugin/pipeline.py` | Threads `style` through mask entry points; `MaskStats.tokens` now comes from the labels, not a regex over the output; receipt records the effective style. |
| `src/omna_plugin/proxy.py` | API door: resolves its style through `style_for_door("api", …)` and logs a refusal once at start-up. |
| `src/omna_plugin/system_door.py` | System/deep door: resolves per flow through `style_for_door(door, …)`. |
| `src/omna_plugin/adapters/{base,generic}.py` | `mask()` takes the style. |
| `src/omna_plugin/policy.py` | `style` field, default `"tokens"`, unknown values fall back to `"tokens"`. |
| `src/omna_plugin/cli.py` | `omna style [tokens|realistic]`, a line in `omna status`, the module docstring. |
| `tests/test_style.py` (new) | The door rule, including the "no call site bypasses it" guard. |
| `tests/test_fakes.py` (new) | Determinism, shape, reserved ranges, secrets excluded. |
| `tests/test_engine.py` | Round-trip, persistence, collision regeneration, secrets excluded end-to-end. |
| `tests/test_stream.py` | A fake value split across SSE chunks, and inside tool-call arguments. |
| `tests/test_proxy.py` | API door still sends numbered tokens with `style=realistic` in policy. |
| `tests/test_system_door.py` | System door sends a fake value and restores the reply. |
| `tests/test_policy.py`, `tests/test_cli.py`, `tests/test_body.py`, `tests/test_pipeline.py` | Config, command, signatures. |

---

## Task 1: The door rule

**Files:**
- Create: `src/omna_plugin/style.py`
- Test: `tests/test_style.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_style.py
import pathlib

from omna_plugin.style import (
    REALISTIC, STYLES, TOKENS, StyleDecision, style_for_door,
)


def test_tokens_are_allowed_at_every_door():
    for door in ("api", "system", "deep", "something-new"):
        d = style_for_door(door, TOKENS)
        assert d.style == TOKENS and not d.refused


def test_realistic_is_allowed_only_at_the_system_door():
    d = style_for_door("system", REALISTIC)
    assert d.style == REALISTIC and not d.refused and d.reason == ""


def test_realistic_is_refused_at_the_api_door_with_a_printable_reason():
    d = style_for_door("api", REALISTIC)
    assert d.style == TOKENS          # downgraded...
    assert d.refused is True          # ...but never silently
    assert "writes files" in d.reason
    assert "Claude Code" in d.reason


def test_realistic_is_refused_at_the_deep_door():
    d = style_for_door("deep", REALISTIC)
    assert d.style == TOKENS and d.refused is True and d.reason


def test_an_unknown_door_refuses_realistic():
    d = style_for_door("brand-new-door", REALISTIC)
    assert d.style == TOKENS and d.refused is True


def test_an_unknown_style_falls_back_to_tokens_and_says_so():
    d = style_for_door("system", "fancy")
    assert d.style == TOKENS and d.refused is True and "fancy" in d.reason


def test_only_style_py_decides_what_realistic_means():
    """The rule lives in ONE function. A door that compared the style string
    itself would be a second copy of the rule, free to drift from this one."""
    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "omna_plugin"
    for name in ("proxy.py", "system_door.py", "body.py", "pipeline.py", "engine.py"):
        text = (src / name).read_text()
        assert '"realistic"' not in text and "'realistic'" not in text, name
    for name in ("proxy.py", "system_door.py"):
        assert "style_for_door" in (src / name).read_text(), name


def test_styles_tuple_is_the_two_we_document():
    assert STYLES == (TOKENS, REALISTIC)
    assert isinstance(style_for_door("api", TOKENS), StyleDecision)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `.venv/bin/pytest tests/test_style.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'omna_plugin.style'`

- [ ] **Step 3: Write `src/omna_plugin/style.py`**

```python
"""Which masking style a door is allowed to use — the whole rule, in one place.

Two styles exist:

- **tokens** (the default everywhere): every masked value becomes a numbered
  token. A token that is ever left behind is *visibly* wrong, so somebody
  notices.
- **realistic**: every masked value becomes a realistic-looking fake value, the
  way Kiji does it. The model reads ordinary-looking prose, which it handles
  better — but a fake value that is ever left behind looks exactly like real
  data, so nobody notices, and it gets committed to a repository forever.

That is why this is a safety rule and not a preference. Any tool that WRITES
FILES must keep numbered tokens:

- the **api** door is Claude Code, aider, Codex, Continue and VS Code — all of
  them edit files;
- the **deep** door captures a named desktop app, which includes editors;
- the **system** door is the browser and the chat websites, which do not write
  your files. Only it may use realistic values.

A refusal here NEVER silently downgrades: the caller gets `refused=True` and a
sentence to print, and every door does print it.
"""

from __future__ import annotations

from dataclasses import dataclass

TOKENS = "tokens"
REALISTIC = "realistic"
STYLES = (TOKENS, REALISTIC)

#: The only door where a realistic fake value may be sent.
DOORS_ALLOWING_REALISTIC = frozenset({"system"})

_WHY = ("the {door} door reaches tools that write files (Claude Code, aider, Codex, "
        "Continue, VS Code), and a realistic fake value left behind in a file looks "
        "like real data instead of an obvious mistake")


@dataclass(frozen=True)
class StyleDecision:
    """What a door will actually do, and why."""

    style: str        # the style that will really be used
    requested: str    # what the policy asked for
    refused: bool     # the request was not honoured (never silently)
    reason: str       # one printable sentence; "" when nothing was refused

    def line(self) -> str:
        """One line for a human: what is in force at this door."""
        return f"omna: {self.reason}" if self.refused else ""


def style_for_door(door: str, requested: str) -> StyleDecision:
    """The one function that decides. Every door calls this; nobody else decides."""
    if requested not in STYLES:
        return StyleDecision(TOKENS, requested, True,
                             f"{requested!r} is not a masking style; using numbered tokens "
                             f"(the styles are: {', '.join(STYLES)})")
    if requested == TOKENS:
        return StyleDecision(TOKENS, TOKENS, False, "")
    if door in DOORS_ALLOWING_REALISTIC:
        return StyleDecision(REALISTIC, REALISTIC, False, "")
    return StyleDecision(TOKENS, REALISTIC, True,
                         "realistic fake values are refused at the " + door + " door: "
                         + _WHY.format(door=door) + "; it keeps numbered tokens")
```

- [ ] **Step 4: Run the tests**

Run: `.venv/bin/pytest tests/test_style.py -q`
Expected: PASS (8 passed)

- [ ] **Step 5: Break the rule on purpose, watch red, restore it**

Temporarily change `DOORS_ALLOWING_REALISTIC` to `frozenset({"system", "api"})`,
run `.venv/bin/pytest tests/test_style.py -q`, confirm
`test_realistic_is_refused_at_the_api_door_with_a_printable_reason` FAILS, then put
`frozenset({"system"})` back and confirm green.

- [ ] **Step 6: Commit**

```bash
git add src/omna_plugin/style.py tests/test_style.py
git commit -m "The masking-style door rule, in one function"
```

---

## Task 2: The realistic-value generator

**Files:**
- Create: `src/omna_plugin/fakes.py`
- Test: `tests/test_fakes.py`

The generator is a pure function. It never touches the registry, the policy or a door.
It takes the canonical entity name (`"EMAIL"`, `"SSN"`, …), the real value, a per-machine
salt, and an attempt number (bumped by the caller when a candidate collides).

Design notes to honour while writing it:

- **Reserved ranges only**, so a fake can never be a real person's anything:
  `example.org` / `example.com` / `example.net` for e-mail and URLs (RFC 2606),
  `555-01xx` for phone numbers, `192.0.2.x` / `198.51.100.x` / `203.0.113.x` for IP
  addresses (RFC 5737), SSN area numbers `900-999` (never issued).
- **Shape-preserving scramble** for the ID-shaped entities: digits become digits, upper
  case becomes upper case, lower case becomes lower case, punctuation is kept. That is what
  makes `MRN-4471-B` come back as `MRN-8130-Q` instead of something the model trips over.
- **A fake card number must NOT pass the Luhn checksum.** A fake card number that passes
  is a card number that might belong to somebody. The scramble leaves it failing, deliberately.
- **Dates stay valid:** only digit runs are replaced, 4-digit runs become a year in
  1950–1999 and 2-digit runs become 01–12 (valid as either a month or a day), so
  `DOB 1984-05-12` becomes `DOB 1971-03-09` and never `1984-99-99`.
- **Secrets get nothing.** Every entity whose display group is `CREDENTIAL` returns `None`.
  A fake API key that looks real is the worst possible output.
- `None` means "no generator" and the caller falls back to the numbered token — failing
  loudly is always the safe direction.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_fakes.py
import re

from omna_plugin import fakes

SALT = b"\x01" * 16


def fake(entity, value, attempt=0):
    return fakes.fake_for(entity, value, salt=SALT, attempt=attempt)


def test_the_same_value_always_gives_the_same_fake():
    a = fake("EMAIL", "jane.doe@acme.com")
    b = fake("EMAIL", "jane.doe@acme.com")
    assert a == b and a is not None


def test_a_different_value_gives_a_different_fake():
    assert fake("EMAIL", "jane.doe@acme.com") != fake("EMAIL", "john.roe@acme.com")


def test_a_different_attempt_gives_a_different_fake():
    assert fake("EMAIL", "jane.doe@acme.com", 0) != fake("EMAIL", "jane.doe@acme.com", 1)


def test_a_different_salt_gives_a_different_fake():
    other = fakes.fake_for("EMAIL", "jane.doe@acme.com", salt=b"\x02" * 16, attempt=0)
    assert other != fake("EMAIL", "jane.doe@acme.com")


def test_email_looks_like_an_email_in_a_reserved_domain():
    v = fake("EMAIL", "jane.doe@acme.com")
    assert re.fullmatch(r"[a-z]+\.[a-z]+\d*@example\.(org|com|net)", v), v


def test_person_keeps_the_number_of_words():
    assert len(fake("PERSON", "Sarah").split()) == 1
    assert len(fake("PERSON", "Sarah Connor").split()) == 2


def test_phone_uses_the_reserved_fictional_range():
    assert "555-01" in fake("PHONE", "415 555 0132")


def test_ip_address_is_in_a_documentation_range():
    v = fake("IP_ADDRESS", "8.8.8.8")
    assert v.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), v


def test_ssn_area_number_is_never_issued_in_real_life():
    v = fake("SSN", "123-45-6789")
    assert re.fullmatch(r"9\d\d-\d\d-\d\d\d\d", v), v


def test_a_scrambled_id_keeps_its_shape():
    v = fake("MEDICAL_RECORD_NUMBER", "MRN-4471-B")
    assert re.fullmatch(r"[A-Z]{3}-\d{4}-[A-Z]", v), v
    assert v != "MRN-4471-B"


def test_a_fake_card_number_does_not_pass_the_luhn_check():
    v = fake("CREDIT_CARD", "4111 1111 1111 1111")
    digits = [int(c) for c in v if c.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    assert total % 10 != 0, f"{v} passes Luhn — a valid fake card could be somebody's real one"


def test_a_date_of_birth_stays_a_valid_looking_date():
    v = fake("DATE_OF_BIRTH", "DOB 1984-05-12")
    m = re.fullmatch(r"DOB (\d{4})-(\d\d)-(\d\d)", v)
    assert m, v
    assert 1950 <= int(m.group(1)) <= 1999
    assert 1 <= int(m.group(2)) <= 12 and 1 <= int(m.group(3)) <= 12
    assert v != "DOB 1984-05-12"


def test_every_secret_entity_gets_no_fake_at_all():
    for entity in ("AWS_KEY", "GITHUB_TOKEN", "API_KEY", "JWT", "PASSWORD",
                   "PRIVATE_KEY", "DATABASE_CONNECTION_STRING", "GENERIC_SECRET"):
        assert fake(entity, "AKIAIOSFODNN7EXAMPLE") is None, entity


def test_an_entity_we_have_no_generator_for_returns_none():
    assert fake("SOMETHING_NEW", "whatever") is None


def test_a_fake_never_contains_a_bracket():
    for entity in ("EMAIL", "PERSON", "PHONE", "ADDRESS", "SSN", "IP_ADDRESS",
                   "CREDIT_CARD", "IBAN", "DATE_OF_BIRTH", "PERSONAL_URL"):
        v = fake(entity, "Jane Doe 123-45-6789 jane@acme.com")
        assert v is None or ("[" not in v and "]" not in v), entity


def test_a_fake_is_never_equal_to_the_real_value():
    for entity, value in (("EMAIL", "jane.doe@acme.com"), ("PERSON", "Sarah Connor"),
                          ("SSN", "123-45-6789"), ("IP_ADDRESS", "8.8.8.8")):
        assert fake(entity, value) != value
```

- [ ] **Step 2: Run it and watch it fail**

Run: `.venv/bin/pytest tests/test_fakes.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'omna_plugin.fakes'`

- [ ] **Step 3: Write `src/omna_plugin/fakes.py`**

```python
"""Turn a real value into a realistic-looking fake one, deterministically.

A pure function: same (entity, value, salt, attempt) in, same fake out, on every
run and after every restart. That stability is not cosmetic — the provider caches
on the exact prompt text, so a value that changed between turns would throw the
cache away and leave the model reading a conversation that keeps changing.

Everything it invents comes from a range that can never belong to anybody:
``example.org`` (RFC 2606), ``555-01xx`` phone numbers, ``192.0.2.x`` /
``198.51.100.x`` / ``203.0.113.x`` (RFC 5737), and Social Security area numbers
900–999, which are never issued. For the ID-shaped entities it scrambles the
value in place instead, keeping the shape (digit for digit, letter for letter)
so the model sees something that still looks like an order number.

Two deliberate refusals:

- **Secrets get nothing.** Any entity whose group is CREDENTIAL returns ``None``.
  A fake API key that looks real is the worst output this program could produce.
- **A fake card number is left failing its checksum.** A fake card number that
  passes the Luhn check is a card number that might be somebody's real one.

``None`` means "no generator for this" and the caller falls back to the numbered
token. Failing loudly is always the safe direction here.
"""

from __future__ import annotations

import hashlib

# L2 secrets. Listed rather than inferred so that adding an entity to the engine
# cannot quietly open a fake-value path for a credential.
SECRET_ENTITIES = frozenset({
    "AWS_KEY", "GITHUB_TOKEN", "API_KEY", "JWT", "PASSWORD", "PRIVATE_KEY",
    "DATABASE_CONNECTION_STRING", "GENERIC_SECRET",
})

FIRST_NAMES = ("robert", "linda", "james", "maria", "david", "susan", "michael", "karen",
               "daniel", "nancy", "thomas", "patricia", "george", "helen", "peter", "alice")
LAST_NAMES = ("jones", "miller", "davis", "wilson", "moore", "taylor", "brooks", "reed",
              "hayes", "porter", "bennett", "shaw", "walsh", "grant", "murray", "doyle")
STREETS = ("Maple", "Cedar", "Walnut", "Birch", "Chestnut", "Linden", "Juniper", "Willow")
STREET_KINDS = ("Street", "Avenue", "Road", "Lane", "Drive", "Court")
CITY_DOMAINS = ("example.org", "example.com", "example.net")
AREA_CODES = ("415", "212", "312", "503", "617", "206")
DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")

_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"   # no I/O: they read as 1/0 in an ID
_LOWER = "abcdefghijkmnopqrstuvwxyz"
_DIGITS = "0123456789"


class _Rand:
    """A deterministic stream of numbers from one hash. Not for cryptography."""

    def __init__(self, *parts: object, salt: bytes) -> None:
        h = hashlib.blake2b(salt, digest_size=32)
        for p in parts:
            h.update(b"\x00")
            h.update(str(p).encode("utf-8", "surrogatepass"))
        self._buf = bytearray(h.digest())
        self._seed = h.digest()
        self._i = 0

    def byte(self) -> int:
        if self._i >= len(self._buf):                      # extend, never run dry
            self._seed = hashlib.blake2b(self._seed, digest_size=32).digest()
            self._buf.extend(self._seed)
        b = self._buf[self._i]
        self._i += 1
        return b

    def below(self, n: int) -> int:
        return (self.byte() * 256 + self.byte()) % n if n > 256 else self.byte() % n

    def pick(self, seq):
        return seq[self.below(len(seq))]

    def digits(self, n: int) -> str:
        return "".join(self.pick(_DIGITS) for _ in range(n))


def _scramble(value: str, r: _Rand) -> str:
    """Same shape, different characters. Punctuation and spacing are kept."""
    out = []
    for ch in value:
        if ch.isdigit():
            out.append(r.pick(_DIGITS))
        elif ch.isupper():
            out.append(r.pick(_UPPER))
        elif ch.islower():
            out.append(r.pick(_LOWER))
        else:
            out.append(ch)
    return "".join(out)


def _digits_only(value: str, r: _Rand, *, dates: bool) -> str:
    """Replace runs of digits, keep every letter. Used where the letters carry
    meaning ("DOB", a currency code) and only the numbers are private."""
    out, run = [], []

    def flush() -> None:
        if not run:
            return
        n = len(run)
        if dates and n == 4:
            out.append(str(1950 + r.below(50)))
        elif dates and n == 2:
            out.append(f"{1 + r.below(12):02d}")
        else:
            out.append(r.digits(n))
        run.clear()

    for ch in value:
        if ch.isdigit():
            run.append(ch)
        else:
            flush()
            out.append(ch)
    flush()
    return "".join(out)


def _person(value: str, r: _Rand) -> str:
    first = r.pick(FIRST_NAMES).capitalize()
    if len(value.split()) < 2:
        return first
    return f"{first} {r.pick(LAST_NAMES).capitalize()}"


def _email(r: _Rand) -> str:
    tail = "" if r.byte() % 2 else str(10 + r.below(80))
    return f"{r.pick(FIRST_NAMES)}.{r.pick(LAST_NAMES)}{tail}@{r.pick(CITY_DOMAINS)}"


def _url(r: _Rand) -> str:
    return f"https://www.{r.pick(CITY_DOMAINS)}/{r.pick(LAST_NAMES)}-{r.digits(3)}"


def fake_for(entity: str, value: str, *, salt: bytes, attempt: int = 0) -> str | None:
    """A realistic stand-in for ``value``, or ``None`` when we have no generator.

    ``attempt`` is bumped by the caller when the previous candidate collided with
    something already in the text or in the registry — see ``engine._stable_fake``.
    """
    entity = (entity or "").upper()
    if not value or entity in SECRET_ENTITIES:
        return None
    r = _Rand(entity, value, attempt, salt=salt)

    if entity == "PERSON":
        return _person(value, r)
    if entity == "EMAIL":
        return _email(r)
    if entity == "PERSONAL_URL":
        return _url(r)
    if entity == "PHONE":
        return f"{r.pick(AREA_CODES)}-555-{100 + r.below(100):04d}"
    if entity == "ADDRESS":
        return f"{100 + r.below(800)} {r.pick(STREETS)} {r.pick(STREET_KINDS)}"
    if entity == "SSN":
        return f"9{r.digits(2)}-{r.digits(2)}-{r.digits(4)}"
    if entity == "IP_ADDRESS":
        return f"{r.pick(DOC_NETS)}{1 + r.below(250)}"
    if entity == "DATE_OF_BIRTH":
        return _digits_only(value, r, dates=True)
    if entity == "SALARY":
        return _digits_only(value, r, dates=False)
    if entity in ("NATIONAL_ID", "PASSPORT", "DRIVER_LICENSE", "TAX_ID",
                  "CREDIT_CARD", "IBAN", "BANK_ACCOUNT", "CRYPTO_ADDRESS",
                  "MEDICAL_LICENSE", "MEDICAL_RECORD_NUMBER", "INSURANCE_ID",
                  "EMPLOYEE_ID", "DEVICE_ID", "MAC_ADDRESS", "DIAGNOSIS_CODE",
                  "CUSTOM"):
        return _scramble(value, r)
    return None
```

- [ ] **Step 4: Run the tests**

Run: `.venv/bin/pytest tests/test_fakes.py -q`
Expected: PASS. If `test_a_fake_card_number_does_not_pass_the_luhn_check` is flaky for
one particular input, do NOT relax the assertion — change the fixed input in the test to
another card number and keep the assertion, or make the scramble force a Luhn failure.

- [ ] **Step 5: Break the secrets exclusion, watch red, restore it**

Temporarily change `SECRET_ENTITIES` to `frozenset()`, run
`.venv/bin/pytest tests/test_fakes.py -q`, confirm
`test_every_secret_entity_gets_no_fake_at_all` FAILS, restore, confirm green.

- [ ] **Step 6: Commit**

```bash
git add src/omna_plugin/fakes.py tests/test_fakes.py
git commit -m "Deterministic realistic fake values, reserved ranges only, never for secrets"
```

---

## Task 3: The second registry in the engine

**Files:**
- Modify: `src/omna_plugin/engine.py`
- Test: `tests/test_engine.py`

What changes:

1. `MaskResult` gains `labels: list[str]` — the numbered token names minted for this
   text (`["EMAIL_1"]`), whatever style was used. Receipts count these, so the audit
   trail is identical under both styles.
2. `mask_text(text, style=TOKENS)`; the cache key includes the style.
3. `_rebuild(text, spans, style)` mints the stable token ALWAYS (that is the label, and
   the fallback), and additionally a fake when the style is realistic and the span is
   not a secret.
4. `_stable_fake(kind, entity, value, text)` — generation with collision retry.
5. `registry.json` gains `"fakes": {fake: real}` and `"fake_salt": "<hex>"`.
6. `restore_text(text, json_escape=False)` replaces tokens AND fake values.
7. `hold_from(buf)` — where a partial token or partial fake value begins.

- [ ] **Step 1: Write the failing tests (append to `tests/test_engine.py`)**

```python
from omna_plugin.style import REALISTIC, TOKENS


def test_realistic_style_substitutes_a_fake_value_and_restores_it(home):
    s = MaskingSession()
    r = s.mask_text("email jane.doe@acme.com today", style=REALISTIC)
    assert "jane.doe@acme.com" not in r.masked
    assert "[" not in r.masked and "]" not in r.masked
    assert "@example." in r.masked
    assert s.restore_text(r.masked) == "email jane.doe@acme.com today"


def test_the_same_value_gets_the_same_fake_every_time(home):
    s = MaskingSession()
    a = s.mask_text("write to jane.doe@acme.com", style=REALISTIC).masked
    b = s.mask_text("again: jane.doe@acme.com please", style=REALISTIC).masked
    fake = a.split("write to ")[1]
    assert fake in b


def test_a_fake_survives_a_restart_because_it_is_in_the_registry(home):
    s1 = MaskingSession()
    masked = s1.mask_text("mail jane.doe@acme.com", style=REALISTIC).masked
    fake = masked.split("mail ")[1]
    s2 = MaskingSession()
    assert s2.restore_text("wrote to " + fake) == "wrote to jane.doe@acme.com"
    assert s2.mask_text("mail jane.doe@acme.com", style=REALISTIC).masked == masked


def test_a_secret_never_gets_a_fake_value_even_in_realistic_style(home):
    s = MaskingSession()
    r = s.mask_text("key AKIAIOSFODNN7EXAMPLE here", style=REALISTIC)
    assert "AKIAIOSFODNN7EXAMPLE" not in r.masked
    assert "[SECRET_AWS_KEY_" "1]" in r.masked   # two pieces, per CLAUDE.md; the loud form on purpose
    assert s.restore_text(r.masked) == "key AKIAIOSFODNN7EXAMPLE here"
    # and nothing about it reached the disk
    assert "AKIA" not in (home / "registry.json").read_text()


def test_a_colliding_fake_is_regenerated(home, monkeypatch):
    """A fake that already appears in the text would make restore corrupt the
    wrong thing, so the generator is asked again with the next attempt."""
    from omna_plugin import engine as engine_mod

    seen = []

    def fake_for(entity, value, *, salt, attempt):
        seen.append(attempt)
        return "taken@example.org" if attempt == 0 else "free@example.org"

    monkeypatch.setattr(engine_mod.fakes, "fake_for", fake_for)
    s = MaskingSession()
    r = s.mask_text("mail jane.doe@acme.com and taken@example.org", style=REALISTIC)
    assert "free@example.org" in r.masked
    assert seen[:2] == [0, 1]
    assert s.restore_text(r.masked).startswith("mail jane.doe@acme.com and ")


def test_a_fake_that_cannot_be_made_unique_falls_back_to_the_loud_token(home, monkeypatch):
    from omna_plugin import engine as engine_mod

    monkeypatch.setattr(engine_mod.fakes, "fake_for",
                        lambda entity, value, *, salt, attempt: "jane.doe@acme.com")
    s = MaskingSession()
    r = s.mask_text("mail jane.doe@acme.com", style=REALISTIC)
    assert TOKEN_RE.search(r.masked), r.masked


def test_labels_are_the_same_under_both_styles(home):
    s = MaskingSession()
    a = s.mask_text("mail jane.doe@acme.com", style=TOKENS)
    b = s.mask_text("mail jane.doe@acme.com", style=REALISTIC)
    assert a.labels == b.labels == ["EMAIL_1"]


def test_restore_can_json_escape_a_fake_value(home):
    s = MaskingSession()
    masked = s.mask_text('from "Ann Jones" <ann@acme.com>', style=REALISTIC).masked
    out = s.restore_text(masked, json_escape=True)
    assert '\\"Ann Jones\\"' in out


def test_hold_from_finds_a_partial_fake_value(home):
    s = MaskingSession()
    masked = s.mask_text("mail jane.doe@acme.com", style=REALISTIC).masked
    fake = masked.split("mail ")[1]
    buf = "hello " + fake[:4]
    assert s.hold_from(buf) == len("hello ")
    assert s.hold_from("hello there") == len("hello there")
```

- [ ] **Step 2: Run them and watch them fail**

Run: `.venv/bin/pytest tests/test_engine.py -q`
Expected: FAIL — `TypeError: mask_text() got an unexpected keyword argument 'style'`

- [ ] **Step 3: Implement in `src/omna_plugin/engine.py`**

Add the imports and module constant:

```python
from . import config, fakes, vault
from .style import REALISTIC, TOKENS

#: How many times a colliding fake value is regenerated before we give up and
#: use the numbered token instead. Giving up is safe: a token is the loud form.
_FAKE_ATTEMPTS = 8
```

Add to `MaskResult`:

```python
    # The numbered token names minted for this text ("EMAIL_1"), whatever style
    # was used. Receipts count these, so the audit trail does not change when
    # the output stops containing brackets.
    labels: list[str] = field(default_factory=list)
```

In `__init__`, beside the PII registry state:

```python
        # Realistic style: fake value <-> real value. Persisted with the tokens
        # (same file, same encryption) because a fake must stay the same across
        # restarts or the provider's prompt cache is thrown away every time.
        self._value_to_fake: dict[str, str] = {}   # "KIND\x00value" -> fake
        self._fake_to_value: dict[str, str] = {}
        self._fake_prefixes: set[str] = set()      # every proper prefix, for stream hold-back
        self._real_values: set[str] = set()        # what a fake must never collide with
        self._fake_salt: bytes = b""
        self._restore_re: re.Pattern | None = None
```

In `_load_registry`, after `self._counters = dict(data.get("counters", {}))`:

```python
        for fk, val in dict(data.get("fakes", {})).items():
            self._remember_fake(fk, val, kind=data.get("fake_kinds", {}).get(fk, ""))
        salt_hex = str(data.get("fake_salt", ""))
        try:
            self._fake_salt = bytes.fromhex(salt_hex)
        except ValueError:
            self._fake_salt = b""
```

and in the same loop that rebuilds `_value_to_token`, also fill `_real_values`:

```python
        for tok, val in self._token_to_value.items():
            m = TOKEN_RE.fullmatch(tok)
            if m:
                self._value_to_token[f"{m.group(1)}\x00{val}"] = tok
                self._real_values.add(val)
```

> Keying the fake map by kind needs the kind on disk, so persist `fake_kinds` too:
> `{fake: "EMAIL"}`. Simpler alternative if that feels heavy: persist
> `"fakes": {"KIND\x00value": fake}` and derive both directions on load. Pick ONE
> and keep the reload test green either way.

`_save_registry` payload becomes:

```python
        payload = {"tokens": self._token_to_value, "counters": self._counters,
                   "fakes": self._fake_to_value,
                   "fake_kinds": {fk: k for k, fk in self._fake_kind.items()},
                   "fake_salt": self._fake_salt.hex()}
```

The salt, minted once:

```python
    def _salt(self) -> bytes:
        """Per-machine, random, persisted. Without it the fake is a pure function
        of the real value, so anyone holding the fake could confirm a guess at the
        real one by running the same function. Minted on first use."""
        if not self._fake_salt:
            self._fake_salt = os.urandom(16)
        return self._fake_salt
```

Generation with the collision retry — the heart of the task:

```python
    def _stable_fake(self, kind: str, entity: str, value: str, text: str) -> str | None:
        """A realistic stand-in for ``value``, reused for ever once minted.

        Returns None when there is no generator for this entity (secrets always)
        or when every attempt collided — the caller then uses the numbered token,
        which is the loud, safe form.
        """
        key = f"{kind}\x00{value}"
        have = self._value_to_fake.get(key)
        if have:
            return have
        for attempt in range(_FAKE_ATTEMPTS):
            cand = fakes.fake_for(entity, value, salt=self._salt(), attempt=attempt)
            if cand is None:
                return None
            if cand == value:
                continue                      # not a mask at all
            if cand in text:
                continue                      # already in the text we are masking:
                                              # restore would corrupt the wrong thing
            if cand in self._real_values:
                continue                      # it IS somebody's real value
            other = self._fake_to_value.get(cand)
            if other is not None and other != value:
                continue                      # already stands for something else
            self._value_to_fake[key] = cand
            self._remember_fake(cand, value, kind=kind)
            return cand
        return None

    def _remember_fake(self, fake: str, value: str, kind: str) -> None:
        self._fake_to_value[fake] = value
        self._fake_kind[fake] = kind
        self._value_to_fake[f"{kind}\x00{value}"] = fake
        for i in range(1, len(fake)):
            self._fake_prefixes.add(fake[:i])
        self._restore_re = None               # the combined pattern must be rebuilt
```

`_rebuild` gains the style and returns labels:

```python
    def _rebuild(self, text: str, spans: list[dict], style: str) -> tuple[str, list[str], bool]:
        out: list[str] = []
        labels: list[str] = []
        pos = 0
        changed_before = (len(self._token_to_value), len(self._fake_to_value), self._fake_salt)
        for sp in sorted(spans, key=lambda s: (s["start"], -s["end"])):
            ...                                # unchanged up to the token choice
            if is_secret:
                m = _ASSIGN_RE.match(core)
                if m:
                    name, core = m.group(1), m.group(2)
                tok = self._secret_token(kind, core) if self.restore_secrets else sp["token"]
                if TOKEN_RE.fullmatch(tok):
                    labels.append(tok[1:-1])
            else:
                label = self._stable_token(kind, core)       # always: the audit id + the fallback
                self._real_values.add(core)
                labels.append(label[1:-1])
                tok = label
                if style == REALISTIC:
                    tok = self._stable_fake(kind, sp.get("entity") or kind, core, text) or label
            ...                                # appending is unchanged
        out.append(text[pos:])
        now = (len(self._token_to_value), len(self._fake_to_value), self._fake_salt)
        return "".join(out), labels, now != changed_before
```

`mask_text` gains the style and the style-aware cache key:

```python
    def mask_text(self, text: str, style: str = TOKENS) -> MaskResult:
        if len(text) < 3:
            return MaskResult(text)
        key = style + "\x00" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        ...
            masked, labels, changed = self._rebuild(text, raw["spans"], style) if raw["spans"] else (text, [], False)
            if changed:
                self._save_registry()
            result = MaskResult(masked, counts, n_secret, n_pii, by_layer, n_validated, labels)
```

Restore, no longer bracket-dependent:

```python
    def _pattern(self) -> re.Pattern | None:
        """Tokens plus every known fake value, longest literal first so a fake
        that starts with another fake cannot be half-matched."""
        if self._restore_re is None:
            parts = [TOKEN_RE.pattern]
            parts += [re.escape(f) for f in sorted(self._fake_to_value, key=len, reverse=True)]
            self._restore_re = re.compile("|".join(parts))
        return self._restore_re

    def restore_text(self, text: str, json_escape: bool = False) -> str:
        if "[" not in text and not self._fake_to_value:
            return text

        def sub(m: re.Match) -> str:
            v = self.lookup(m.group(0))
            if v is None:
                return m.group(0)
            return json.dumps(v)[1:-1] if json_escape else v

        return self._pattern().sub(sub, text)

    def lookup(self, token: str) -> str | None:
        v = self._token_to_value.get(token)
        if v is None:
            v = self._secret_token_to_value.get(token)
        if v is None:
            v = self._fake_to_value.get(token)
        return v
```

Stream hold-back support:

```python
    def hold_from(self, buf: str) -> int:
        """Index where text that might still become a token or a fake value starts.

        ``len(buf)`` means "nothing to hold back". A fake value has no brackets, so
        a stream can split it anywhere: we keep every proper prefix of every fake we
        have minted and hold back the longest suffix that is one of them.
        """
        best = len(buf)
        m = _TOKEN_PREFIX_RE.search(buf)
        if m and len(buf) - m.start() <= _MAX_TOKEN_HOLD:
            best = m.start()
        if self._fake_prefixes:
            start = max(0, len(buf) - self._max_fake_len + 1)
            for i in range(start, best):
                if buf[i:] in self._fake_prefixes:
                    return i
        return best
```

with `_TOKEN_PREFIX_RE = re.compile(r"\[[A-Z0-9_]*$")` and `_MAX_TOKEN_HOLD = 48` moved
from `stream.py` into `engine.py`, and `self._max_fake_len` kept up to date in
`_remember_fake`.

`forget()` must clear the new state too: `_value_to_fake`, `_fake_to_value`, `_fake_kind`,
`_fake_prefixes`, `_real_values`, `_fake_salt = b""`, `_restore_re = None`, `_max_fake_len = 0`.

- [ ] **Step 4: Run the engine tests**

Run: `.venv/bin/pytest tests/test_engine.py -q`
Expected: PASS, including every pre-existing test (the token style must be byte-identical
to what it was before).

- [ ] **Step 5: Break each new guard, watch red, restore**

1. Collision check: delete the `if cand in text: continue` line →
   `test_a_colliding_fake_is_regenerated` FAILS. Restore.
2. Persistence: stop writing `"fakes"` into the payload →
   `test_a_fake_survives_a_restart_because_it_is_in_the_registry` FAILS. Restore.
3. Secrets: in `_rebuild`, route secrets down the fake path →
   `test_a_secret_never_gets_a_fake_value_even_in_realistic_style` FAILS. Restore.

- [ ] **Step 6: Commit**

```bash
git add src/omna_plugin/engine.py tests/test_engine.py
git commit -m "Engine: a fake-value registry beside the token registry"
```

---

## Task 4: Streams restore fake values too

**Files:**
- Modify: `src/omna_plugin/stream.py`
- Test: `tests/test_stream.py`

`TextRestorer` stops owning the hold-back rule and the token regex; it asks the session.

- [ ] **Step 1: Write the failing tests (append to `tests/test_stream.py`)**

```python
from omna_plugin.style import REALISTIC


def fake_for(session, value):
    masked = session.mask_text(f"x {value} x", style=REALISTIC).masked
    return masked[2:-2]


def test_a_fake_value_split_across_chunks_is_restored(session):
    fake = fake_for(session, EMAIL)
    r = StreamRestorer(session)
    out = b""
    for piece in (fake[:3], fake[3:7], fake[7:] + " sent"):
        out += r.feed(a_delta(piece))
    out += r.flush()
    assert EMAIL in "".join(texts(out))
    assert fake not in "".join(texts(out))


def test_a_fake_value_in_tool_call_arguments_is_restored_and_json_escaped(session):
    masked = session.mask_text('to "Ann Jones" now', style=REALISTIC).masked
    fake = masked[4:-5].strip('"')
    r = StreamRestorer(session)
    out = r.feed(a_json_delta('{"to": "' + fake)) + r.feed(a_json_delta('"}')) + r.flush()
    joined = b"".join(out.split()) if isinstance(out, bytes) else out
    assert b"Ann" in out


def test_a_stream_with_no_fakes_is_unchanged(session):
    r = StreamRestorer(session)
    out = r.feed(a_delta("nothing to see")) + r.flush()
    assert "nothing to see" in "".join(texts(out))
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/bin/pytest tests/test_stream.py -q`
Expected: FAIL — the fake value passes through unrestored (`assert EMAIL in ...`).

- [ ] **Step 3: Implement**

```python
class TextRestorer:
    def __init__(self, session: MaskingSession, json_escape: bool = False):
        self.session = session
        self.json_escape = json_escape
        self.pending = ""

    def _restore(self, text: str) -> str:
        return self.session.restore_text(text, json_escape=self.json_escape)

    def feed(self, text: str) -> str:
        buf = self.pending + text
        cut = self.session.hold_from(buf)
        self.pending, out = buf[cut:], buf[:cut]
        return self._restore(out) if out else ""
```

`flush()` is unchanged. Delete the now-unused `_MAX_HOLD`/`_PREFIX_RE` and the
`TOKEN_RE`/`json` imports if nothing else in the file uses them.

- [ ] **Step 4: Run the stream and pipeline tests**

Run: `.venv/bin/pytest tests/test_stream.py tests/test_pipeline.py -q`
Expected: PASS.

- [ ] **Step 5: Break it, watch red, restore**

Make `hold_from` return `len(buf)` always → `test_a_fake_value_split_across_chunks_is_restored`
FAILS (the halves are released separately, so the fake is never matched). Restore.

- [ ] **Step 6: Commit**

```bash
git add src/omna_plugin/stream.py tests/test_stream.py
git commit -m "Streams: hold back partial fake values, not just partial tokens"
```

---

## Task 5: Thread the style through body and pipeline

**Files:**
- Modify: `src/omna_plugin/body.py`, `src/omna_plugin/pipeline.py`
- Test: `tests/test_body.py`, `tests/test_pipeline.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_pipeline.py — append
from omna_plugin.style import REALISTIC, TOKENS


def test_mask_json_honours_the_style_it_is_given(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    masked, stats = p.mask_json({"t": EMAIL}, style=REALISTIC)
    assert "[" not in masked["t"] and EMAIL not in masked["t"]
    assert stats.tokens == ["EMAIL_1"], "the receipt's identifiers must not change with the style"
    assert p.restore_json({"reply": masked["t"]}) == {"reply": EMAIL}


def test_mask_json_defaults_to_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    masked, _ = p.mask_json({"t": EMAIL})
    assert "[EMAIL_" in masked["t"]


def test_mask_bytes_passes_the_style_down(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    out = p.mask_bytes(b'{"prompt": "mail jane.doe@acme.com"}', "application/json", style=REALISTIC)
    assert b"[" not in out.body and b"jane.doe@acme.com" not in out.body
```

```python
# tests/test_body.py — update the two existing call sites to the 3-tuple
masked, counts, labels = mask_body(session, body)
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/bin/pytest tests/test_pipeline.py tests/test_body.py -q`
Expected: FAIL — `mask_json() got an unexpected keyword argument 'style'`.

- [ ] **Step 3: Implement**

`body.py`:

```python
def mask_body(session: MaskingSession, obj, style: str = TOKENS):
    """Return (masked_copy, counts, labels). ``obj`` is not modified.

    ``labels`` are the numbered token names minted for this body ("EMAIL_1"),
    whatever the style — receipts count those, so the audit trail is the same
    under both styles even when the output carries no brackets.
    """
    counts: dict[str, int] = {}
    labels: list[str] = []

    def fn(s: str, c: dict[str, int]) -> str:
        r = session.mask_text(s, style=style)
        labels.extend(r.labels)
        ...
        return r.masked

    return _walk(obj, fn, counts), counts, sorted(set(labels))
```

`pipeline.py`: `mask_json(obj, style=TOKENS)`, `mask_text(text, style=TOKENS)`,
`mask_bytes(body, content_type, style=TOKENS)` (passing `style` to both inner calls),
`MaskStats.tokens` set from the labels, and `_tokens_in` deleted along with the now-unused
`TOKEN_RE` import. `restore_text(text, json_escape=False)` forwards the flag.

`receipt()` gains `style: str = TOKENS` and writes `rec["style"] = style`.

- [ ] **Step 4: Run**

Run: `.venv/bin/pytest tests/test_pipeline.py tests/test_body.py -q` → PASS

- [ ] **Step 5: Commit**

```bash
git add src/omna_plugin/body.py src/omna_plugin/pipeline.py tests/test_body.py tests/test_pipeline.py
git commit -m "Thread the masking style through the mail room"
```

---

## Task 6: Policy field

**Files:**
- Modify: `src/omna_plugin/policy.py`
- Test: `tests/test_policy.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_policy.py — append
from omna_plugin.style import REALISTIC, TOKENS


def test_style_defaults_to_tokens(home):
    assert Policy().style == TOKENS


def test_style_round_trips(home):
    p = Policy()
    p.style = REALISTIC
    p.save()
    assert Policy.load().style == REALISTIC


def test_an_unknown_style_on_disk_falls_back_to_tokens(home):
    p = Policy()
    p.save()
    path = config.policy_path()
    data = json.loads(path.read_text())
    data["style"] = "fancy"
    path.write_text(json.dumps(data))
    assert Policy.load().style == TOKENS
```

- [ ] **Step 2: Run and watch fail** — `AttributeError: 'Policy' object has no attribute 'style'`

- [ ] **Step 3: Implement** — in the dataclass, next to `restore_browser`:

```python
    # How a masked value is written: "tokens" (numbered, the default) or
    # "realistic" (a fake value). The realistic style is refused at the API and
    # deep doors — see style.py, which owns that rule. Kept here because this is
    # also the file an organisation ships to every machine.
    style: str = TOKENS
```

in `load()`:

```python
            st = str(data.get("style", TOKENS))
            pol.style = st if st in STYLES else TOKENS
```

and `"style": self.style,` in the `save()` payload.

- [ ] **Step 4: Run** → PASS

- [ ] **Step 5: Commit**

```bash
git add src/omna_plugin/policy.py tests/test_policy.py
git commit -m "policy.json: the masking style, tokens by default"
```

---

## Task 7: The API door refuses realistic

**Files:**
- Modify: `src/omna_plugin/proxy.py`
- Test: `tests/test_proxy.py`

- [ ] **Step 1: Write the failing test (append to `tests/test_proxy.py`)**

```python
@pytest.mark.anyio
async def test_the_api_door_keeps_numbered_tokens_even_when_policy_says_realistic(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    pol = Policy()
    pol.style = "realistic"
    pol.save()
    async with client_for(tmp_path, policy=pol) as (client, calls):
        await client.post("/v1/messages", json={"messages": [{"role": "user",
                                                              "content": "mail jane.doe@acme.com"}]})
    raw = calls[0]["raw"]
    assert "jane.doe@acme.com" not in raw
    assert TOKEN_RE.findall(raw), "the API door must send numbered tokens"
    assert "@example." not in raw, "a realistic fake value reached a file-writing tool"
    out = capsys.readouterr()
    assert "refused" in (out.out + out.err), "the refusal must be printed, never silent"
```

(Use the file's existing fake-upstream helper; add a `policy=` argument to it if it does
not already take one, defaulting to the current behaviour.)

- [ ] **Step 2: Run and watch fail** — the assertion on the printed refusal fails first.

- [ ] **Step 3: Implement — in `create_app`, after the policy is resolved:**

```python
    # The API door's style is decided once, by the one function that owns the
    # rule. This door reaches tools that WRITE FILES, so a realistic fake value
    # is refused here and the refusal is printed — never a silent downgrade.
    _decision = style_for_door("api", (policy or Policy.load()).style)
    if _decision.refused:
        print(_decision.line(), flush=True)
```

and in `relay`:

```python
                out = await run_in_threadpool(pipeline.mask_bytes, body, ctype, _decision.style)
```

and pass `style=_decision.style` through `_receipt` into `pipeline.receipt`.

- [ ] **Step 4: Run** → `.venv/bin/pytest tests/test_proxy.py -q` PASS

- [ ] **Step 5: Break it, watch red, restore**

Change the call to `style_for_door("system", …)` → the new test FAILS on
`"@example." not in raw`. Restore.

- [ ] **Step 6: Commit**

```bash
git add src/omna_plugin/proxy.py tests/test_proxy.py
git commit -m "API door: numbered tokens always, refusal printed"
```

---

## Task 8: The system door honours realistic

**Files:**
- Modify: `src/omna_plugin/system_door.py`, `src/omna_plugin/adapters/base.py`, `src/omna_plugin/adapters/generic.py`
- Test: `tests/test_system_door.py`, `tests/test_adapters.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_system_door.py — append, using the file's existing flow helper
def test_the_system_door_sends_a_fake_value_when_the_policy_says_realistic(addon_for):
    pol = Policy()
    pol.style = "realistic"
    addon, pipeline = addon_for(pol, door="system")
    flow = a_flow(host="claude.ai", path="/api/messages",
                  body=b'{"prompt": "mail jane.doe@acme.com"}')
    run(addon.request(flow))
    sent = flow.request.get_content().decode()
    assert "jane.doe@acme.com" not in sent and "[" not in sent and "@example." in sent


def test_the_deep_door_refuses_realistic(addon_for):
    pol = Policy()
    pol.style = "realistic"
    addon, pipeline = addon_for(pol, door="deep")
    flow = a_flow(host="claude.ai", path="/api/messages",
                  body=b'{"prompt": "mail jane.doe@acme.com"}')
    run(addon.request(flow))
    sent = flow.request.get_content().decode()
    assert "[EMAIL_" in sent and "@example." not in sent


def test_the_reply_is_restored_after_a_realistic_request(addon_for):
    pol = Policy()
    pol.style = "realistic"
    addon, pipeline = addon_for(pol, door="system")
    flow = a_flow(host="claude.ai", path="/api/messages",
                  body=b'{"prompt": "mail jane.doe@acme.com"}')
    run(addon.request(flow))
    fake = json.loads(flow.request.get_content())["prompt"].split("mail ")[1]
    flow.response = http.Response.make(200, json.dumps({"reply": "wrote to " + fake}).encode(),
                                       {"content-type": "application/json"})
    addon.response(flow)
    assert "jane.doe@acme.com" in flow.response.get_content().decode()
```

- [ ] **Step 2: Run and watch fail** — the request still carries `[EMAIL_` on the system door.

- [ ] **Step 3: Implement**

`adapters/base.py` Protocol: `def mask(self, pipeline: Pipeline, req: RequestView, style: str = TOKENS) -> MaskOutcome: ...`

`adapters/generic.py`: same signature, and pass `style` into both `pipeline.mask_bytes` calls.

`system_door.py` in `request()`:

```python
        # The style is decided per flow by the one function that owns the rule:
        # the deep door captures a named desktop app (editors included), so it is
        # on the refusing side of the line with the API door.
        decision = style_for_door(self._door_for(flow), self.policy.style)
        if decision.refused and not self._said_refused:
            print(decision.line(), flush=True)
            self._said_refused = True
        out = adapter.mask(self.pipeline, req, decision.style)
```

with `self._said_refused = False` in `__init__` (say it once per run, not per request),
and `flow.metadata["omna_style"] = decision.style` so `_receipt` can pass
`style=flow.metadata.get("omna_style", TOKENS)` to `pipeline.receipt`.

`websocket_message()` masks with the same per-flow decision.

- [ ] **Step 4: Run** → `.venv/bin/pytest tests/test_system_door.py tests/test_adapters.py -q` PASS

- [ ] **Step 5: Break it, watch red, restore**

Hardcode `decision = style_for_door("system", self.policy.style)` → `test_the_deep_door_refuses_realistic`
FAILS. Restore.

- [ ] **Step 6: Commit**

```bash
git add src/omna_plugin/system_door.py src/omna_plugin/adapters tests/test_system_door.py tests/test_adapters.py
git commit -m "System door: realistic values allowed; deep door refuses like the API door"
```

---

## Task 9: `omna style`

**Files:**
- Modify: `src/omna_plugin/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing tests (append to `tests/test_cli.py`)**

```python
def test_style_with_no_argument_shows_the_current_style(capsys):
    assert main(["style"]) == 0
    out, _ = capsys.readouterr()
    assert "tokens" in out and "realistic" in out


def test_style_realistic_saves_and_names_the_doors(capsys, no_restart):
    assert main(["style", "realistic"]) == 0
    out, _ = capsys.readouterr()
    assert Policy.load().style == "realistic"
    assert "browser" in out.lower()
    assert "Claude Code" in out          # the refusal is spelled out, not implied
    assert "numbered tokens" in out
    assert no_restart, "a style change must restart the proxy"


def test_style_tokens_goes_back_to_the_default(capsys, no_restart):
    main(["style", "realistic"])
    capsys.readouterr()
    assert main(["style", "tokens"]) == 0
    assert Policy.load().style == "tokens"
    assert "everywhere" in capsys.readouterr().out


def test_an_unknown_style_is_rejected(capsys):
    assert main(["style", "fancy"]) == 2   # argparse choices
```

- [ ] **Step 2: Run and watch fail** — `invalid choice: 'style'`.

- [ ] **Step 3: Implement**

```python
def cmd_style(a) -> int:
    """Show or change how a masked value is written.

    Worth its own command because the two styles are a safety trade, not a
    preference: a leftover token is visibly wrong, a leftover fake value is not.
    """
    from .style import REALISTIC, STYLES, TOKENS, style_for_door

    pol = Policy.load()
    if not a.value:
        print(f"masking style: {pol.style}")
        for door, what in (("api", "API door (Claude Code, aider, Codex, Continue, VS Code)"),
                           ("system", "system door (your browser and the chat websites)"),
                           ("deep", "deep door (a named desktop app)")):
            d = style_for_door(door, pol.style)
            print(f"  {what}: {d.style}" + ("   <- refused, see below" if d.refused else ""))
        d = style_for_door("api", pol.style)
        if d.refused:
            print("\n" + d.reason)
        print("\n  omna style tokens      every masked value becomes a numbered token (the default)")
        print("  omna style realistic   a realistic fake value instead — browser only")
        return 0

    before = pol.style
    pol.style = a.value
    _save_policy(pol, a)
    if a.value == TOKENS:
        print("omna: masking style is now numbered tokens, everywhere."
              + ("" if before == TOKENS else "\n      Values already masked keep the fake they were given."))
        return 0
    print("omna: masking style is now realistic fake values.")
    print("      Where it applies: the system door only — your browser and the chat")
    print("      websites. An e-mail becomes something like robert.jones@example.org.")
    print("      Where it does NOT: " + style_for_door("api", REALISTIC).reason)
    print("      Why: a leftover token is obviously wrong and someone notices; a")
    print("      leftover fake value looks like real data and gets committed.")
    if not pol.restore_browser:
        print("\nomna: browser restore is OFF, so you will read the fake values yourself")
        print("      and they will look real. `omna` menu bar → Restore in browser.")
    return 0
```

Parser: `s = sub.add_parser("style", help="how a masked value is written: numbered tokens (default) or a realistic fake value"); s.add_argument("value", nargs="?", choices=list(STYLES)); add_port(s); s.set_defaults(fn=cmd_style)`

Module docstring: add `omna style [tokens|realistic]     how a masked value is written (tokens everywhere by default)`.

`cmd_status`: add a line under the doors line —

```python
    d_api = style_for_door("api", pol.style)
    d_sys = style_for_door("system", pol.style)
    if d_api.style == d_sys.style:
        print(f"style:   {d_api.style} (every door)")
    else:
        print(f"style:   {d_sys.style} in the browser, {d_api.style} for coding tools (they write files)")
```

`cmd_mask` gains `--realistic` so a person can see the difference without a proxy:
`s.add_argument("--realistic", action="store_true", help="show the realistic style instead of numbered tokens")`
and `r = s.mask_text(text, style=REALISTIC if a.realistic else TOKENS)`.

- [ ] **Step 4: Run** → `.venv/bin/pytest tests/test_cli.py -q` PASS

- [ ] **Step 5: Commit**

```bash
git add src/omna_plugin/cli.py tests/test_cli.py
git commit -m "omna style: choose the masking style, and say which doors it reaches"
```

---

## Task 10: Full suite, docs, ship

- [ ] **Step 1: Full suite**

Run: `.venv/bin/pytest -q`
Expected: every test green, count ≥ 333 + the new ones.

- [ ] **Step 2: A real end-to-end check of both styles**

```bash
.venv/bin/python -m omna_plugin.cli mask "email jane.doe@acme.com ssn 123-45-6789 key AKIAIOSFODNN7EXAMPLE"
.venv/bin/python -m omna_plugin.cli mask --realistic "email jane.doe@acme.com ssn 123-45-6789 key AKIAIOSFODNN7EXAMPLE"
```
Expected: the first prints numbered tokens; the second prints a fake e-mail and a fake SSN
but STILL prints the numbered `[SECRET_AWS_KEY_` `1]` for the key.

- [ ] **Step 3: README.md**

Add a "Two masking styles" section: the table from the top of this plan, the one-line
`omna style` usage, and the explicit sentence that the realistic style is refused for
coding tools with the reason.

- [ ] **Step 4: MASTER.md (omna-workspace)**

Add the shipped row to the plugin's state line and to §7's archive-bound list per that
repo's rules (closed rows go to `MASTER_ARCHIVE.md`, §7 is open-only).

- [ ] **Step 5: Commit and push**

```bash
git add -A && git commit -m "Two masking styles: numbered tokens (default) and realistic fake values"
git push origin main
```

**Do NOT:** bump the version in `pyproject.toml`, create a tag or a GitHub release, run
`uv publish` / `twine`, rebuild or re-notarize the Homebrew cask, or create any repository.

---

## Self-review against the spec

- tokens default everywhere → Task 6 (policy default), Task 5 (function defaults), Task 7.
- realistic refused at the API door, printed, never silent → Task 1 + Task 7 (test asserts the print).
- rule in ONE function with a test → Task 1, including the "no call site compares the string" guard.
- STABILITY → Task 2 (pure function) + Task 3 (persisted, salted) + tests in both.
- UNIQUENESS → Task 3 `_stable_fake` (four collision checks) + regeneration test + fallback test.
- REVERSIBILITY → Task 3 `restore_text` via the registry, Task 4 for streams and tool-call arguments.
- SECRETS EXCLUDED → Task 2 (`SECRET_ENTITIES` → `None`) + Task 3 (`_rebuild` routes secrets first) + tests in both.
- config in policy.json + `omna style` printing what changed and which doors → Tasks 6 and 9.
- tests first, no network, no full token literals in any file → every task; the plan itself writes
  `[SECRET_AWS_KEY_` `1]` in two pieces for the same reason.
