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
    pasted = "Row: Jane Doe, 12 Main St, jane.doe@example.com\n" * 200
    body = {"model": "x", "messages": [{"role": "user", "content": pasted}]}
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


def test_earlier_turns_are_checked_again(monkeypatch, tmp_path):
    """Owner rule 2026-11-15: message 5 carries messages 1-4. The AI's earlier
    reply holds the real value (Omna put it back for the person), and the
    agent's own earlier turns are data too: both are masked when resent."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    from omna_plugin.body import mask_body as mb
    s = MaskingSession()
    body = {"model": "x", "system": "You help.", "messages": [
        {"role": "user", "content": "my email is jane.doe@example.com"},
        {"role": "assistant", "content": [{"type": "text", "text": "Noted: jane.doe@example.com"},
                                          {"type": "tool_use", "id": "t1", "name": "Bash",
                                           "input": {"command": "grep jane.doe@example.com crm.csv"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                      "content": "jane.doe@example.com,Gold"}]},
        {"role": "user", "content": "thanks"}]}
    out, _, _ = mb(s, body)
    assert "jane.doe@example.com" not in str(out["messages"])
    assert out["system"] == "You help."


def test_a_background_agents_report_in_a_system_turn_is_masked(monkeypatch, tmp_path):
    """Security review 2026-11-15: Claude Code 2.1.325 sends a background
    agent's final report as a role "system" turn. It is the agent's data and
    is masked; hook text and tool additions in system turns are the app's."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    from omna_plugin.body import mask_body as mb
    card, gh = "4111 1111 1111 1111", "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    hook = "SessionStart hook additional context: Jane Doe wrote this plugin."
    addition = {"type": "tool_addition", "tool": {"type": "tool_definition",
                "definition": {"name": "crm", "description": "Ask Jane Doe"}}}
    body = {"model": "x", "system": [{"type": "text", "text": "You help."}], "messages": [
        {"role": "user", "content": "go"},
        {"role": "system", "content": [{"type": "text", "text": hook}, addition]},
        {"role": "system", "content": [{"type": "text", "text":
            "[SYSTEM NOTIFICATION - NOT USER INPUT]\n<task-notification><result>"
            f"customer Mary Major card {card} {gh}</result></task-notification>"}]}]}
    out, _, _ = mb(MaskingSession(), body)
    assert card not in str(out) and gh not in str(out)
    assert out["messages"][1]["content"][1] == addition          # a tool definition: the app's
    # Claude Code glues notes together: data behind an app note is still masked.
    glued = {"model": "x", "system": "You help.", "messages": [{"role": "system", "content": [{"type": "text", "text":
        "SessionStart hook additional context: be brief.\n\nThe user selected the lines 1 to 1 from .env:\n"
        f"GITHUB_TOKEN={gh}"}]}]}
    out, _, _ = mb(MaskingSession(), glued)
    assert gh not in str(out)


def test_claude_code_system_turns_get_fast_masking(monkeypatch, tmp_path):
    """Owner 2026-11-15: text Omna cannot tell apart from app notes gets fast
    masking (rules), not the smart models; the conversation gets smart."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    _both_ready(monkeypatch)
    used = []
    real = smart.mask
    monkeypatch.setattr(smart, "mask", lambda t, on, r=None: used.append((t[:12], smart._choice())) or real(t, False, r))
    body = {"model": "x", "system": "You help.", "messages": [
        {"role": "user", "content": "hello Jane"},
        {"role": "system", "content": [{"type": "text", "text": "SessionStart hook additional context: skills"}]}]}
    mask_body(MaskingSession(smart=True), body)
    assert ("hello Jane", smart.BOTH) in used
    assert ("SessionStart", None) in used
