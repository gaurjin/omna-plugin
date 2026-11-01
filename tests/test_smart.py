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


def test_the_curl_commands_own_doors_use_both_models_at_every_size(calls):
    # Kiji's model alone missed a first name on a 19 KB live test (2026-11-01),
    # and 0.6.13 read every text with the privacy filter: never worse than that.
    smart.mask("short", True)
    smart.mask("x" * 200_000, True)
    smart.detect("y" * 200_000, True)
    assert calls == [("mask", True, smart.BOTH), ("mask", True, smart.BOTH), ("detect", True, smart.BOTH)]


def test_chrome_gets_both_for_short_text_and_kijis_model_for_long(calls):
    assert smart.model_for_chrome("Priya Raman, 42 Elm Road") == smart.BOTH
    assert smart.model_for_chrome("x" * smart.BOTH_UP_TO_CHARS) == smart.BOTH
    assert smart.model_for_chrome("x" * (smart.BOTH_UP_TO_CHARS + 1)) == smart.KIJI
    smart.detect("short", True, for_chrome=True)
    smart.detect("y" * (smart.BOTH_UP_TO_CHARS + 1), True, for_chrome=True)
    assert calls == [("detect", True, smart.BOTH), ("detect", True, smart.KIJI)]


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
