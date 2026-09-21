"""Turn a real value into a realistic-looking fake one, deterministically.

A pure function: the same (entity, value, salt, attempt) gives the same fake
value on every run and after every restart. That stability is not cosmetic —
the provider caches on the exact text of the prompt, so a stand-in that changed
between turns would throw the cache away and leave the model reading a
conversation that keeps rewriting itself.

Everything it invents comes from a range that can never belong to anybody:

- ``example.org`` / ``example.com`` / ``example.net`` — reserved for
  documentation by RFC 2606, so a fake e-mail can never reach a real inbox;
- ``555-01xx`` phone numbers — the range reserved for fiction;
- ``192.0.2.x`` / ``198.51.100.x`` / ``203.0.113.x`` — RFC 5737, reserved for
  documentation, so a fake IP address can never be a real host;
- Social Security area numbers 900–999, which are never issued.

For the ID-shaped entities there is nothing to invent from, so it scrambles the
value in place instead: digit for digit, letter for letter, punctuation kept.
``MRN-4471-B`` comes back as ``MRN-8130-Q`` — still obviously an order number
to the model, but not that person's.

Two deliberate refusals:

- **Secrets get nothing.** Any entity in ``SECRET_ENTITIES`` returns ``None``.
  A fake API key that looks real is the worst output this program could
  produce, so credentials always stay numbered tokens.
- **A fake card number is forced to FAIL its checksum.** A fake card number
  that passes the Luhn check is a card number that might be somebody's real
  one.

``None`` means "no generator for this" and the caller falls back to the
numbered token. Failing loudly is always the safe direction here.
"""

from __future__ import annotations

import hashlib

# The L2 secret entities. Listed rather than inferred, so that adding an entity
# to the engine can never quietly open a fake-value path for a credential.
SECRET_ENTITIES = frozenset({
    "AWS_KEY", "GITHUB_TOKEN", "API_KEY", "JWT", "PASSWORD", "PRIVATE_KEY",
    "DATABASE_CONNECTION_STRING", "GENERIC_SECRET",
})

# Entities that keep their shape and only get new characters.
_SCRAMBLED = frozenset({
    "NATIONAL_ID", "PASSPORT", "DRIVER_LICENSE", "TAX_ID", "CREDIT_CARD", "IBAN",
    "BANK_ACCOUNT", "CRYPTO_ADDRESS", "MEDICAL_LICENSE", "MEDICAL_RECORD_NUMBER",
    "INSURANCE_ID", "EMPLOYEE_ID", "DEVICE_ID", "MAC_ADDRESS", "DIAGNOSIS_CODE",
    "CUSTOM",
})

# Every entity this module has an opinion about. `test_fakes.py` checks this
# against the engine's taxonomy, so a new entity shows up as a failing test
# rather than as a value that silently keeps its numbered token.
KNOWN_ENTITIES = SECRET_ENTITIES | _SCRAMBLED | {
    "PERSON", "EMAIL", "PHONE", "ADDRESS", "PERSONAL_URL", "SSN", "IP_ADDRESS",
    "DATE_OF_BIRTH", "SALARY",
}

FIRST_NAMES = ("robert", "linda", "james", "maria", "david", "susan", "michael", "karen",
               "daniel", "nancy", "thomas", "patricia", "george", "helen", "peter", "alice")
LAST_NAMES = ("jones", "miller", "davis", "wilson", "moore", "taylor", "brooks", "reed",
              "hayes", "porter", "bennett", "shaw", "walsh", "grant", "murray", "doyle")
STREETS = ("Maple", "Cedar", "Walnut", "Birch", "Chestnut", "Linden", "Juniper", "Willow")
STREET_KINDS = ("Street", "Avenue", "Road", "Lane", "Drive", "Court")
RESERVED_DOMAINS = ("example.org", "example.com", "example.net")
AREA_CODES = ("415", "212", "312", "503", "617", "206")
DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")

_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"   # no I or O: they read as 1 and 0 in an ID
_LOWER = "abcdefghijkmnopqrstuvwxyz"
_DIGITS = "0123456789"


class _Rand:
    """A deterministic stream of numbers derived from one hash.

    Not a random generator and not for cryptography: it exists only so that the
    same inputs always walk the same path through the word lists below.
    """

    def __init__(self, *parts: object, salt: bytes) -> None:
        h = hashlib.blake2b(salt, digest_size=32)
        for p in parts:
            h.update(b"\x00")
            h.update(str(p).encode("utf-8", "surrogatepass"))
        self._seed = h.digest()
        self._buf = bytearray(self._seed)
        self._i = 0

    def byte(self) -> int:
        if self._i >= len(self._buf):          # extend rather than ever run dry
            self._seed = hashlib.blake2b(self._seed, digest_size=32).digest()
            self._buf.extend(self._seed)
        b = self._buf[self._i]
        self._i += 1
        return b

    def below(self, n: int) -> int:
        if n <= 0:
            return 0
        if n > 256:
            return (self.byte() * 256 + self.byte()) % n
        return self.byte() % n

    def pick(self, seq):
        return seq[self.below(len(seq))]

    def digits(self, n: int) -> str:
        return "".join(self.pick(_DIGITS) for _ in range(n))


def _luhn_passes(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not digits:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _break_luhn(value: str) -> str:
    """Nudge the last digit so the number cannot pass the card checksum.

    Deliberate: a fake card number that validates is a card number that might
    belong to a real person, and a tool that checks the checksum would then
    treat our invention as a live card.
    """
    if not _luhn_passes(value):
        return value
    out = list(value)
    for i in range(len(out) - 1, -1, -1):
        if out[i].isdigit():
            out[i] = str((int(out[i]) + 1) % 10)
            break
    return "".join(out)


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
    """Replace runs of digits and keep every letter.

    Used where the letters carry the meaning ("DOB", a currency code) and only
    the numbers are private. With ``dates=True`` a four-digit run becomes a year
    in 1950–1999 and a two-digit run becomes 01–12, which is valid as either a
    month or a day — so a date of birth never comes back as 1984-99-99.
    """
    out: list[str] = []
    run: list[str] = []

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
    return f"{r.pick(FIRST_NAMES)}.{r.pick(LAST_NAMES)}{tail}@{r.pick(RESERVED_DOMAINS)}"


def _url(r: _Rand) -> str:
    return f"https://www.{r.pick(RESERVED_DOMAINS)}/{r.pick(LAST_NAMES)}-{r.digits(3)}"


def fake_for(entity: str, value: str, *, salt: bytes, attempt: int = 0) -> str | None:
    """A realistic stand-in for ``value``, or ``None`` when we have no generator.

    ``attempt`` is bumped by the caller when the previous candidate collided with
    something already in the text or in the registry — see ``engine._stable_fake``.
    """
    entity = (entity or "").upper()
    if not value or not entity or entity in SECRET_ENTITIES:
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
    if entity == "IBAN":
        # Keep the two-letter country code: it is what makes an IBAN read as an
        # IBAN, and it says nothing about the person.
        return value[:2] + _scramble(value[2:], r)
    if entity == "CREDIT_CARD":
        return _break_luhn(_scramble(value, r))
    if entity in _SCRAMBLED:
        return _scramble(value, r)
    return None
