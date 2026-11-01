"""The automatic smart-model choice (smart.py): people never pick a model.

No real model here: the engine's functions are replaced by fakes that record
what they were asked for."""

from __future__ import annotations

import omna_pii_mask
import pytest

from omna_plugin import smart


@pytest.fixture
def calls(monkeypatch):
    seen: list[tuple] = []

    def fake_mask(text, model=False, ruleset=None, **kw):
        seen.append(("mask", model, kw.get("smart_model")))
        return {"masked": text, "spans": [], "tokens": {}}

    def fake_detect(text, model=False, ruleset=None, **kw):
        seen.append(("detect", model, kw.get("smart_model")))
        return []

    monkeypatch.setattr(omna_pii_mask, "mask", fake_mask)
    monkeypatch.setattr(omna_pii_mask, "detect", fake_detect)
    return seen


def test_a_typed_message_is_read_by_both_models():
    assert smart.model_for("Priya Raman, 42 Elm Road") == smart.BOTH
    assert smart.model_for("x" * smart.BOTH_UP_TO_CHARS) == smart.BOTH


def test_a_long_text_is_read_by_kijis_model_alone():
    assert smart.model_for("x" * (smart.BOTH_UP_TO_CHARS + 1)) == smart.KIJI


def test_smart_on_passes_the_chosen_model(calls):
    smart.mask("short", True)
    smart.detect("y" * (smart.BOTH_UP_TO_CHARS + 1), True)
    assert calls == [("mask", True, smart.BOTH), ("detect", True, smart.KIJI)]


def test_smart_off_never_names_a_model(calls):
    smart.mask("short", False)
    smart.detect("short", False)
    assert calls == [("mask", False, None), ("detect", False, None)]


def test_download_and_verify_cover_both_models(monkeypatch):
    got: list[str] = []
    monkeypatch.setattr(omna_pii_mask, "download_model", lambda smart_model=None: got.append(smart_model))
    monkeypatch.setattr(omna_pii_mask, "verify_model",
                        lambda smart_model=None: [{"file": "f", "ok": True, "detail": "h"}])
    smart.download_models()
    assert got == [smart.KIJI, smart.PRIVACY_FILTER]
    assert [r["model"] for r in smart.verify_models()] == [smart.PRIVACY_FILTER, smart.KIJI]
