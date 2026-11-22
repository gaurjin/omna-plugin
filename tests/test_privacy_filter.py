"""The OpenAI privacy-filter model: OFF by default, one command to turn it on
(owner 2026-11-22: speed and leaks are the two winning metrics; on a Mac the
curl command runs the compact model + fast rules). Kept as an opt-in, never
deleted: its download, its checks and its "both models" path stay working."""

from __future__ import annotations

import omna_pii_mask
import pytest

from omna_plugin import smart
from omna_plugin.cli import main
from omna_plugin.policy import Policy


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    monkeypatch.setenv("OMNA_RAM_GB", "16")
    for e in smart._ready.values():
        e.clear()
    yield tmp_path
    for e in smart._ready.values():
        e.clear()


@pytest.fixture(autouse=True)
def no_restart(monkeypatch):
    calls = []
    monkeypatch.setattr("omna_plugin.cli._restart_daemon", lambda a=None, **kw: calls.append((a, kw)))
    return calls


@pytest.fixture
def calls(monkeypatch):
    seen: list[tuple] = []

    def fake_mask(text, model=False, ruleset=None, **kw):
        seen.append(("mask", model, kw.get("smart_model")))
        return {"masked": text, "spans": [], "tokens": {}}

    monkeypatch.setattr(omna_pii_mask, "mask", fake_mask)
    return seen


def test_a_fresh_install_has_the_privacy_filter_off():
    assert Policy.load().privacy_filter == "off"


def test_off_by_default_even_on_a_big_mac(monkeypatch):
    monkeypatch.setenv("OMNA_RAM_GB", "64")
    assert smart.models_here() == [smart.COMPACT]


def test_off_means_it_is_never_downloaded_and_never_runs(monkeypatch, calls):
    got: list[str] = []
    monkeypatch.setattr(omna_pii_mask, "download_model", lambda smart_model=None: got.append(smart_model))
    smart.download_models()
    assert got == [smart.COMPACT]
    smart.mask("x" * 40_000, True)          # a long text NOT wrapped in request() — the #24 way in
    smart.mask("Maria Lopez", True)
    assert calls == [("mask", True, smart.COMPACT), ("mask", True, smart.COMPACT)]


def test_an_old_settings_file_without_the_setting_gets_it_off(home):
    (home / "policy.json").write_text('{"version": 1, "smart": "on"}')
    assert Policy.load().privacy_filter == "off"


def test_a_broken_value_means_off(home):
    (home / "policy.json").write_text('{"version": 1, "privacy_filter": "yes please"}')
    assert Policy.load().privacy_filter == "off"


def test_omna_privacy_filter_on_and_off(capsys, no_restart):
    assert main(["privacy-filter"]) == 0
    assert "OFF" in capsys.readouterr().out
    assert main(["privacy-filter", "on"]) == 0
    out = capsys.readouterr().out
    assert Policy.load().privacy_filter == "on"
    assert "`omna privacy-filter off`" in out
    assert no_restart, "the running service must restart to pick it up"
    assert smart.models_here() == [smart.COMPACT, smart.PRIVACY_FILTER]
    assert main(["privacy-filter", "off"]) == 0
    assert Policy.load().privacy_filter == "off"
    assert "`omna privacy-filter on`" in capsys.readouterr().out
    assert smart.models_here() == [smart.COMPACT]


def test_on_but_a_small_mac_says_it_will_not_run_here(capsys, monkeypatch):
    monkeypatch.setenv("OMNA_RAM_GB", "8")
    assert main(["privacy-filter", "on"]) == 0
    assert "16 GB" in capsys.readouterr().out
    assert smart.models_here() == [smart.COMPACT]


def test_turned_on_both_models_read_short_texts_again(calls):
    p = Policy.load(); p.privacy_filter = "on"; p.save()
    smart._ready[smart.COMPACT].set(); smart._ready[smart.PRIVACY_FILTER].set()
    smart.mask("Maria Lopez", True)
    assert calls == [("mask", True, smart.BOTH)]


def test_its_model_files_are_still_checked_when_off(monkeypatch):
    # Never deleted: `omna verify-model` still covers it.
    monkeypatch.setattr(omna_pii_mask, "verify_model", lambda smart_model=None: [{"file": "f", "ok": True, "detail": "h"}])
    assert [r["model"] for r in smart.verify_models()] == ["openai-privacy-filter", "compact"]


def _health(port):
    return {"ok": True, "smart": True, "smart_models": ["compact"], "requests_this_run": 0,
            "restore_secrets": True, "ocr": True}


def test_status_shows_the_privacy_filter_line(capsys, monkeypatch):
    monkeypatch.setattr("omna_plugin.cli._health", _health)
    main(["status", "--details"])
    out = capsys.readouterr().out
    assert "privacy filter: OFF" in out and "`omna privacy-filter on`" in out
    p = Policy.load(); p.privacy_filter = "on"; p.save()
    main(["status", "--details"])
    out = capsys.readouterr().out
    assert "privacy filter: ON" in out and "`omna privacy-filter off`" in out
