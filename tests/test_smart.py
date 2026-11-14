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


@pytest.fixture(autouse=True)
def fresh_models(monkeypatch):
    """Each test starts with no model downloaded on a 16 GB machine."""
    monkeypatch.setenv("OMNA_RAM_GB", "16")
    for e in smart._ready.values():
        e.clear()
    yield
    for e in smart._ready.values():
        e.clear()


def _arrive(*names):
    for n in names:
        smart._ready[n].set()


def test_the_curl_commands_own_doors_use_both_models_at_every_size(calls):
    _arrive(smart.COMPACT, smart.PRIVACY_FILTER)
    # The compact model alone missed a first name on a 19 KB live test (2026-11-01),
    # and 0.6.13 read every text with the privacy filter: never worse than that.
    smart.mask("short", True)
    smart.mask("x" * 200_000, True)
    smart.detect("y" * 200_000, True)
    assert calls == [("mask", True, smart.BOTH), ("mask", True, smart.BOTH), ("detect", True, smart.BOTH)]


def test_chrome_gets_both_for_short_text_and_the_compact_model_for_long(calls):
    _arrive(smart.COMPACT, smart.PRIVACY_FILTER)
    assert smart.model_for_chrome("Priya Raman, 42 Elm Road") == smart.BOTH
    assert smart.model_for_chrome("x" * smart.BOTH_UP_TO_CHARS) == smart.BOTH
    assert smart.model_for_chrome("x" * (smart.BOTH_UP_TO_CHARS + 1)) == smart.COMPACT
    smart.detect("short", True, for_chrome=True)
    smart.detect("y" * (smart.BOTH_UP_TO_CHARS + 1), True, for_chrome=True)
    assert calls == [("detect", True, smart.BOTH), ("detect", True, smart.COMPACT)]


def test_smart_off_never_names_a_model(calls):
    smart.mask("short", False)
    smart.detect("short", False)
    assert calls == [("mask", False, None), ("detect", False, None)]


def test_a_smaller_machine_runs_the_compact_model_only(calls, monkeypatch):
    # The OpenAI privacy filter needs ~2 GB while running: below 16 GB it never
    # downloads or runs, and every text gets the compact model.
    monkeypatch.setenv("OMNA_RAM_GB", "8")
    assert smart.models_here() == [smart.COMPACT]
    _arrive(smart.COMPACT)
    smart.mask("Priya Raman", True)
    smart.detect("short", True, for_chrome=True)
    assert calls == [("mask", True, smart.COMPACT), ("detect", True, smart.COMPACT)]


def test_nothing_waits_on_a_download_fast_masking_until_a_model_arrives(calls):
    # Smart is on but no model has arrived yet: fast masking, never a blocking download.
    smart.mask("Priya Raman", True)
    _arrive(smart.COMPACT)              # the 64 MB one lands first
    smart.mask("Priya Raman", True)
    _arrive(smart.PRIVACY_FILTER)       # then the big one joins
    smart.mask("Priya Raman", True)
    assert calls == [("mask", False, None), ("mask", True, smart.COMPACT), ("mask", True, smart.BOTH)]


def test_a_failed_download_leaves_the_other_model_working(monkeypatch, calls):
    def flaky(smart_model=None):
        if smart_model == smart.PRIVACY_FILTER:
            raise OSError("network down")
    monkeypatch.setattr(omna_pii_mask, "download_model", flaky)
    smart.download_models()
    assert smart.ready_models() == [smart.COMPACT]
    smart.mask("Priya Raman", True)
    assert calls == [("mask", True, smart.COMPACT)]


def test_download_and_verify_cover_both_models(monkeypatch):
    got: list[str] = []
    monkeypatch.setattr(omna_pii_mask, "download_model", lambda smart_model=None: got.append(smart_model))
    monkeypatch.setattr(omna_pii_mask, "verify_model",
                        lambda smart_model=None: [{"file": "f", "ok": True, "detail": "h"}])
    smart.download_models()
    assert got == [smart.COMPACT, smart.PRIVACY_FILTER]
    assert [r["model"] for r in smart.verify_models()] == ["openai-privacy-filter", "compact"]


# --- security review 2026-11-11: "no sign of whether fast or smart masking was used"
def test_the_record_says_which_masking_a_request_really_got(tmp_path, monkeypatch):
    from omna_plugin import menubar, receipts, report, smart
    from omna_plugin.engine import MaskingSession
    from omna_plugin.pipeline import MaskStats, Pipeline

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))

    def receipt(session_smart, ready):
        monkeypatch.setattr(smart, "ready_models", lambda: ready)
        pipe = Pipeline(MaskingSession())
        pipe.session.smart = session_smart
        pipe.receipt(door="api", route="/v1/messages", host="x", status=200, stats=MaskStats(), nbytes=1, ms=1,
                     stream=False, app=None, note=None, session_id=None)
        return receipts.tail(1)[0]["masking"]

    assert receipt(False, []) == "fast"
    assert receipt(True, []) == "fast-smart-not-ready"        # on, but the model has not arrived: said, not silent
    assert receipt(True, [smart.COMPACT]) == "smart"
    d = report.build(7)
    assert d["by_masking"] == {"fast": 1, "fast-smart-not-ready": 1, "smart": 1}
    text = report.render_text(d)
    assert "masking used: smart (rules + the on-device model) ×1 · fast (rules only) ×1" in text
    assert "FAST ONLY ×1 — smart masking was on, but its model had not arrived yet" in text
    lines = menubar.status_lines({"masking": "fast-smart-not-ready", "smart": True})
    assert lines[-1] == "Masking: FAST ONLY — the smart model is still loading"
    assert menubar.status_lines({"masking": "smart"})[-1].startswith("Masking: smart")
