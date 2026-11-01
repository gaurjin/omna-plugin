"""Smart masking for Omna for Chrome, done by the curl command.

The Chrome extension masks with fast rules inside the browser; the on-device
model (L3, the ~809 MB "Contextual" model) is far too big for a browser. Until
2026-10-31 only the Omna Mac app could lend it its model. This lets the curl
command do the same job: the extension sends a message's text here, gets back
where the MODEL found something, and merges that with its own rules exactly
as it merges the Mac app's answer (`wasm_fuse_spans_rs`).

The reply copies the Mac app's `Reply::L3Spans` contract to the letter
(native/src/handlers.rs in omna-workspace):
  * offsets are UTF-16 code units (what JavaScript strings count), not the
    engine's UTF-8 bytes;
  * labels are the model's own names (`private_person`, …), which the
    extension's merge step maps to entities itself;
  * only spans the MODEL produced (layer L3) — the extension already runs the
    rules (L1/L2) on its side.

Measured 2026-10-31 (M5 MacBook Air, model warm): ~0.25 s per KB of text —
1 KB 0.8 s, 16 KB 4.4 s, 64 KB 16 s, 256 KB 65 s. So the extension asks only
for short texts (a typed message), and this refuses anything over
`MAX_CHARS` so a stuck caller can't tie the model up for minutes.
"""

from __future__ import annotations

from collections.abc import Callable

# The engine's entity name -> the model label the extension's merge step
# expects (core/src/detection/l3.rs, privacy_filter_label_to_entity and
# kiji_label_to_entity, reversed — the merge step accepts both label sets).
# The last four only come from Kiji's model (DistilBERT): without them its ID
# finds would be dropped on the way to Omna for Chrome.
ENTITY_TO_LABEL = {
    "PERSON": "private_person",
    "EMAIL": "private_email",
    "PHONE": "private_phone",
    "ADDRESS": "private_address",
    "DATE_OF_BIRTH": "private_date",
    "PERSONAL_URL": "private_url",
    "BANK_ACCOUNT": "account_number",
    "GENERIC_SECRET": "secret",
    "SSN": "SSN",
    "NATIONAL_ID": "NATIONALID",
    "PASSPORT": "PASSPORTID",
    "DRIVER_LICENSE": "DRIVERLICENSENUM",
}

# Hard stop per request: 64 KB of text is ~16 s of model time.
MAX_CHARS = 64 * 1024


def byte_to_utf16(text: str, byte_offset: int) -> int:
    """UTF-8 byte offset into `text` -> UTF-16 code-unit offset.

    The engine reports byte offsets; JavaScript counts UTF-16 units. A dash,
    accent or emoji before a value moves them apart (memory:
    feedback_engine_spans_are_byte_offsets)."""
    prefix = text.encode("utf-8")[:byte_offset].decode("utf-8", errors="ignore")
    return len(prefix.encode("utf-16-le")) // 2


def model_spans(text: str, detect: Callable[..., list[dict]], ruleset: str | None = None) -> list[dict]:
    """Spans the model found in `text`, in the extension's L3 reply shape."""
    out: list[dict] = []
    for sp in detect(text, model=True, ruleset=ruleset):
        if sp.get("layer") != "L3":
            continue
        label = ENTITY_TO_LABEL.get(sp.get("entity", ""))
        start, end = sp.get("start"), sp.get("end")
        if label is None or not isinstance(start, int) or not isinstance(end, int) or start >= end:
            continue
        out.append({
            "start": byte_to_utf16(text, start),
            "end": byte_to_utf16(text, end),
            "label": label,
            "score": float(sp.get("confidence", 0.0)),
        })
    return out
