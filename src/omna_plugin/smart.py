"""Smart masking: which on-device model reads a text — chosen automatically.

Owner, 2026-11-01: two models at most, chosen automatically; people never pick
a model. They only turn smart masking on or off.

- The smart-masking model (OpenAI privacy filter, ~809 MB): best at names and
  anything written as a sentence. Slow: ~0.3–0.45 s for a typed message.
- Kiji's model (Dataiku, DistilBERT, Apache-2.0, ~64 MB): ~30–45× faster and
  strong on ID numbers, addresses and links, weaker on names.

The rule (measured 2026-11-01, see MASTER #141): a text up to
``BOTH_UP_TO_CHARS`` — a typed message, a short paste — is read by BOTH models
(their finds are merged by the masking engine's fusion layer, L4); a longer
text — a file, a long paste, an agent's tool output — by Kiji's model alone,
so it stays fast. The masking engine (omna-pii-mask) does the work; this
module only names the model.
"""

from __future__ import annotations

import omna_pii_mask

# Texts up to this many characters are read by both models. Set from the
# 2026-11-01 speed measurements (4 cores, real text): 8 KB = ~1.5 s with both
# models; longer text with Kiji's model alone: 64 KB = ~2.5 s.
BOTH_UP_TO_CHARS = 8 * 1024

BOTH = "both"
KIJI = "kiji"
PRIVACY_FILTER = "privacy-filter"


def model_for(text: str) -> str:
    """The smart model(s) for ``text``: both for a short text, Kiji's for a long one."""
    return BOTH if len(text) <= BOTH_UP_TO_CHARS else KIJI


def mask(text: str, smart: bool, ruleset: str | None = None) -> dict:
    """omna_pii_mask.mask with the automatic model choice when smart is on."""
    if not smart:
        return omna_pii_mask.mask(text, model=False, ruleset=ruleset)
    return omna_pii_mask.mask(text, model=True, ruleset=ruleset, smart_model=model_for(text))


def detect(text: str, smart: bool, ruleset: str | None = None) -> list[dict]:
    """omna_pii_mask.detect with the automatic model choice when smart is on."""
    if not smart:
        return omna_pii_mask.detect(text, model=False, ruleset=ruleset)
    return omna_pii_mask.detect(text, model=True, ruleset=ruleset, smart_model=model_for(text))


def download_models() -> None:
    """Fetch both smart models (Kiji's first: it is small, so short texts gain
    its finds sooner). Each file is checked against its pinned fingerprint."""
    omna_pii_mask.download_model(smart_model=KIJI)
    omna_pii_mask.download_model(smart_model=PRIVACY_FILTER)


def verify_models() -> list[dict]:
    """Every smart-model file re-hashed against its pinned fingerprint, both models."""
    rows = []
    for name in (PRIVACY_FILTER, KIJI):
        for r in omna_pii_mask.verify_model(smart_model=name):
            rows.append({**r, "model": name})
    return rows
