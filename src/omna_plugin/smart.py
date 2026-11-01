"""Smart masking: which on-device model reads a text — chosen automatically.

Owner, 2026-11-01: people never pick a model; they only turn smart masking on
or off (`omna smart on|off`, ON by default since 0.6.15: "go messages, on with
the compact model").

- The compact model (open source, Apache-2.0, ~64 MB, ~300 MB of memory):
  fast (~15 ms a message); strong on ID numbers, addresses and links.
- The OpenAI privacy filter (~809 MB, ~2 GB of memory while running): best at
  names and anything written as a sentence; ~0.3–0.45 s a typed message.

Which run (``models_here()``):

- Every Mac/PC with smart masking on gets the compact model.
- The OpenAI privacy filter joins on machines with at least
  ``FULL_MODEL_MIN_RAM_GB`` of memory; there both read every text and their
  finds are merged (they leak far less together — measured 2026-11-01, numbers
  private, MASTER #141).
- Both download in the BACKGROUND (``start_downloads``): starting Omna never
  waits on a download. Until a model has arrived and passed its pinned-hash
  check it is not used — text gets fast masking (L1/L2) meanwhile.
- **Omna for Chrome** (``/omna/detect-l3``, it waits at send): both up to
  ``BOTH_UP_TO_CHARS``, the compact model alone above (64 KB ~2.5 s).
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading

import omna_pii_mask

from . import receipts

# Omna for Chrome only: texts up to this many characters are read by both
# models, longer ones by the compact model alone. Measured 2026-11-01 (4 cores, real
# text): 8 KB = ~1.5 s with both; 64 KB = ~2.5 s with the compact model.
BOTH_UP_TO_CHARS = 8 * 1024

# The OpenAI privacy filter needs ~2 GB while running; below this much memory
# it would squeeze everything else on the machine.
FULL_MODEL_MIN_RAM_GB = 16

BOTH = "both"
COMPACT = "compact"
PRIVACY_FILTER = "privacy-filter"
# What a user reads (`omna verify-model`): each model by its publisher.
SHOWN_AS = {PRIVACY_FILTER: "openai-privacy-filter", COMPACT: "compact"}


_ready = {"compact": threading.Event(), "privacy-filter": threading.Event()}
_failed: dict[str, str] = {}


def ram_gb() -> float:
    """This machine's memory in GB (``OMNA_RAM_GB`` overrides, for tests)."""
    if os.environ.get("OMNA_RAM_GB"):
        return float(os.environ["OMNA_RAM_GB"])
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=5)
            return int(out.stdout.strip()) / 2**30
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30
    except Exception:
        return 0.0


def full_model_fits() -> bool:
    """Does the OpenAI privacy filter join on this machine?"""
    return ram_gb() >= FULL_MODEL_MIN_RAM_GB


def models_here() -> list[str]:
    """The smart models this machine runs, in download order (compact first)."""
    return [COMPACT, PRIVACY_FILTER] if full_model_fits() else [COMPACT]


def ready_models() -> list[str]:
    """The models downloaded and hash-checked so far, this run."""
    return [m for m in models_here() if _ready[m].is_set()]


def _choice(chrome_text: str | None = None) -> str | None:
    """The engine's smart_model value for a text, or None = no model ready yet."""
    ready = ready_models()
    if not ready:
        return None
    if ready == [COMPACT]:
        return COMPACT
    if PRIVACY_FILTER in ready and COMPACT not in ready:
        return PRIVACY_FILTER
    if chrome_text is not None and len(chrome_text) > BOTH_UP_TO_CHARS:
        return COMPACT
    return BOTH


_FINGERPRINT: list[str] = []


def engine_fingerprint() -> str:
    """The masking engine's (omna-pii-mask) build fingerprint, for records."""
    if not _FINGERPRINT:
        try:
            _FINGERPRINT.append(str(omna_pii_mask.mask("omna")["engine_fingerprint"]))
        except (KeyError, TypeError, RuntimeError):
            _FINGERPRINT.append(omna_pii_mask.version())
    return _FINGERPRINT[0]


def model_for_chrome(text: str) -> str | None:
    """Omna for Chrome: both models for a short text, the compact model for a long one."""
    return _choice(text)


def mask(text: str, smart: bool, ruleset: str | None = None) -> dict:
    """omna_pii_mask.mask for the curl command's doors, with this machine's models."""
    which = _choice() if smart else None
    key = receipts.fingerprint_key()
    if which is None:
        return omna_pii_mask.mask(text, model=False, ruleset=ruleset, audit_key=key)
    return omna_pii_mask.mask(text, model=True, ruleset=ruleset, smart_model=which, audit_key=key)


def detect(text: str, smart: bool, ruleset: str | None = None, for_chrome: bool = False) -> list[dict]:
    """omna_pii_mask.detect with this machine's models; ``for_chrome`` uses
    the size rule (the compact model alone above BOTH_UP_TO_CHARS)."""
    which = (_choice(text) if for_chrome else _choice()) if smart else None
    key = receipts.fingerprint_key()
    if which is None:
        return omna_pii_mask.detect(text, model=False, ruleset=ruleset, audit_key=key)
    return omna_pii_mask.detect(text, model=True, ruleset=ruleset, smart_model=which, audit_key=key)


def download_models() -> None:
    """Fetch this machine's smart models now, compact first. Each file is
    checked against its pinned fingerprint; a model counts as ready only after."""
    for name in models_here():
        try:
            omna_pii_mask.download_model(smart_model=name)
            _ready[name].set()
        except Exception as e:  # offline, disk full, hash mismatch: stay on what is ready
            _failed[name] = str(e)
            print(f"omna: smart model {SHOWN_AS[name]} not available yet ({e}); "
                  "masking continues without it", file=sys.stderr, flush=True)


def start_downloads() -> threading.Thread:
    """``download_models`` in the background: starting Omna never waits on it."""
    t = threading.Thread(target=download_models, name="omna-smart-models", daemon=True)
    t.start()
    return t


def verify_models() -> list[dict]:
    """Every smart-model file re-hashed against its pinned fingerprint, both models."""
    rows = []
    for name in (PRIVACY_FILTER, COMPACT):
        for r in omna_pii_mask.verify_model(smart_model=name):
            rows.append({**r, "model": SHOWN_AS[name]})
    return rows
