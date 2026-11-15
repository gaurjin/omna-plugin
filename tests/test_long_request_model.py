"""A long request (Claude Code, Codex, Cursor) is read by the compact model
alone; a short one by both (smart.request). Found 2026-11-15: Claude Code's
first request took ~25 s with both models and looked stuck."""

from omna_plugin import smart
from omna_plugin.body import mask_body
from omna_plugin.engine import MaskingSession


def _both_ready(monkeypatch):
    monkeypatch.setattr(smart, "ready_models", lambda: [smart.COMPACT, smart.PRIVACY_FILTER])


def _models_used(monkeypatch, body):
    used = []
    real = smart.mask

    def spy(text, on, ruleset=None):
        used.append(smart._choice() if on else None)
        return real(text, False, ruleset)       # rules only: no model download in tests

    monkeypatch.setattr(smart, "mask", spy)
    s = MaskingSession(smart=True)
    mask_body(s, body)
    return set(used)


def test_short_request_gets_both_models(monkeypatch, tmp_path):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    _both_ready(monkeypatch)
    body = {"model": "x", "messages": [{"role": "user", "content": "Email jane.doe@example.com about Friday"}]}
    assert _models_used(monkeypatch, body) == {smart.BOTH}


def test_long_request_gets_compact_alone(monkeypatch, tmp_path):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    _both_ready(monkeypatch)
    tools = [{"name": f"t{i}", "description": "Reads a file and returns its lines. " * 20} for i in range(20)]
    body = {"model": "x", "tools": tools,
            "messages": [{"role": "user", "content": "Email jane.doe@example.com about Friday"}]}
    assert _models_used(monkeypatch, body) == {smart.COMPACT}


def test_rule_ends_with_the_request(monkeypatch):
    _both_ready(monkeypatch)
    with smart.request(smart.BOTH_UP_TO_CHARS + 1):
        assert smart._choice() == smart.COMPACT
    assert smart._choice() == smart.BOTH


def test_cached_answer_is_per_model(monkeypatch, tmp_path):
    """A text first seen in a long request (compact alone) is read again,
    with both models, when it comes in a short one."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    _both_ready(monkeypatch)
    calls = []
    real = smart.mask
    monkeypatch.setattr(smart, "mask", lambda t, on, r=None: calls.append(smart._choice()) or real(t, False, r))
    s = MaskingSession(smart=True)
    with smart.request(10**6):
        s.mask_text("call Jane Doe tomorrow")
    s.mask_text("call Jane Doe tomorrow")
    assert calls == [smart.COMPACT, smart.BOTH]
