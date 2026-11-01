"""Smart masking: which on-device model reads a text — chosen automatically.

Owner, 2026-11-01: two models at most, chosen automatically; people never pick
a model. They only turn smart masking on or off.

- The smart-masking model (OpenAI privacy filter, ~809 MB): best at names and
  anything written as a sentence. Slow: ~0.3–0.45 s for a typed message.
- Kiji's model (Dataiku, DistilBERT, Apache-2.0, ~64 MB): ~30–45× faster and
  strong on ID numbers, addresses and links, weaker on names.

The rule (measured 2026-11-01, see MASTER #141):

- **The curl command's own doors** (AI tools, agents, files, chat sites):
  BOTH models at every size, merged by the masking engine's fusion layer (L4)
  — together they leak far less than either alone (measured; numbers kept
  private until published). Kiji's model alone was tried for long texts and
  dropped: on a 19 KB live test it missed a first name the privacy filter
  catches, and 0.6.13 already read every text with the privacy filter —
  never worse than before. Speed (4 cores, real text): 8 KB ~1.5 s, 32 KB ~7 s, 64 KB ~14 s.
- **Omna for Chrome** (``/omna/detect-l3``, it waits at send): both up to
  ``BOTH_UP_TO_CHARS``, Kiji's model alone above (64 KB ~2.5 s). Before
  2026-11-01 Chrome got no smart masking above 8 KB at all, so this is gain.
"""

from __future__ import annotations

import omna_pii_mask

# Omna for Chrome only: texts up to this many characters are read by both
# models, longer ones by Kiji's model alone. Measured 2026-11-01 (4 cores, real
# text): 8 KB = ~1.5 s with both; 64 KB = ~2.5 s with Kiji's model.
BOTH_UP_TO_CHARS = 8 * 1024

BOTH = "both"
KIJI = "kiji"
PRIVACY_FILTER = "privacy-filter"


def model_for_chrome(text: str) -> str:
    """Omna for Chrome: both models for a short text, Kiji's for a long one."""
    return BOTH if len(text) <= BOTH_UP_TO_CHARS else KIJI


def mask(text: str, smart: bool, ruleset: str | None = None) -> dict:
    """omna_pii_mask.mask for the curl command's doors: both models when smart is on."""
    if not smart:
        return omna_pii_mask.mask(text, model=False, ruleset=ruleset)
    return omna_pii_mask.mask(text, model=True, ruleset=ruleset, smart_model=BOTH)


def detect(text: str, smart: bool, ruleset: str | None = None, for_chrome: bool = False) -> list[dict]:
    """omna_pii_mask.detect: both models when smart is on; ``for_chrome`` uses
    the size rule (Kiji's model alone above BOTH_UP_TO_CHARS)."""
    if not smart:
        return omna_pii_mask.detect(text, model=False, ruleset=ruleset)
    which = model_for_chrome(text) if for_chrome else BOTH
    return omna_pii_mask.detect(text, model=True, ruleset=ruleset, smart_model=which)


def download_models() -> None:
    """Fetch both smart models (Kiji's first: it is small). Each file is
    checked against its pinned fingerprint."""
    omna_pii_mask.download_model(smart_model=KIJI)
    omna_pii_mask.download_model(smart_model=PRIVACY_FILTER)


def verify_models() -> list[dict]:
    """Every smart-model file re-hashed against its pinned fingerprint, both models."""
    rows = []
    for name in (PRIVACY_FILTER, KIJI):
        for r in omna_pii_mask.verify_model(smart_model=name):
            rows.append({**r, "model": name})
    return rows
