"""A chat WEBSITE's own request body (not an AI API request): only the fields
that hold the person's text get smart masking; the site's own fields get fast
masking; its tool list goes as it is.

Owner rule 2026-11-15: Omna masks only the data a person sends. Recorded live
2026-11-15 on claude.ai (one message, signed in): with smart masking on, the
curl command edited 35 of the site's own fields in ONE request — every
connector's name ("Docs" read as a person), id and address, the message ids
and the request id. The shapes below are that request's, with made-up ids."""

import copy

from omna_plugin import smart
from omna_plugin.body import mask_body
from omna_plugin.engine import MaskingSession

GH = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
TOOL = {"name": "batch", "description": "Create a doc. Ask Jane Doe, token " + GH,
        "input_schema": {"type": "object", "properties": {"modules": {"items": {"enum": ["dataviz"]}}}},
        "integration_name": "Claude Docs", "mcp_server_uuid": "1a59c906-04da-521d-bda7-7f71b9f9e01c",
        "mcp_server_url": "https://api.anthropic.com/v1/pages/mcp", "needs_approval": False}
BUILT_IN = {"type": "widget", "name": "weather_fetch"}


def _claude_ai_body():
    return {"prompt": "hello Jane Doe, mail jane.doe@example.com", "timezone": "America/New_York", "locale": "en-US",
            "model": "claude-sonnet-5-5", "tools": [copy.deepcopy(TOOL), dict(BUILT_IN)],
            "turn_message_uuids": {"human_message_uuid": "01a1e1bb-b214-723a-bcd6-cd9bdd5b131e"},
            "attachments": [{"file_name": "notes.txt", "extracted_content": "call Mary Major tomorrow"}],
            "files": [], "completion_request_id": "9b7d5456-ea95-4fb0-b80b-fd328ec3ea25",
            "create_conversation_params": {"name": "", "model": "claude-sonnet-5-5"}}


def _spy(monkeypatch):
    """Which texts the smart models were asked to read, and which got rules only."""
    monkeypatch.setattr(smart, "ready_models", lambda: [smart.COMPACT, smart.PRIVACY_FILTER])
    seen = {}
    real = smart.mask

    def spy(text, on, ruleset=None):
        seen[text] = smart._choice() if on else None
        return real(text, False, ruleset)       # rules only: no model download in tests

    monkeypatch.setattr(smart, "mask", spy)
    return seen


def _mask(site, body):
    s = MaskingSession(smart=True)
    with s.sending_to(site):
        return mask_body(s, body)[0]


def test_on_claude_ai_only_the_persons_text_gets_smart_masking(monkeypatch, tmp_path):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    seen = _spy(monkeypatch)
    out = _mask("Claude", _claude_ai_body())
    assert seen["hello Jane Doe, mail jane.doe@example.com"] is not None      # the message: smart
    assert seen["call Mary Major tomorrow"] is not None                       # the attached file: smart
    assert seen["notes.txt"] is not None                                      # its name: smart
    # the site's own fields: fast masking (the rule's tiebreaker), never the smart models
    for own in ("America/New_York", "01a1e1bb-b214-723a-bcd6-cd9bdd5b131e", "9b7d5456-ea95-4fb0-b80b-fd328ec3ea25"):
        assert seen.get(own) is None, own
    assert "jane.doe@example.com" not in str(out)


def test_on_claude_ai_the_sites_tool_list_goes_as_it_is(monkeypatch, tmp_path):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    seen = _spy(monkeypatch)
    out = _mask("Claude", _claude_ai_body())
    assert out["tools"] == [TOOL, BUILT_IN]
    assert not any("Docs" in t or "mcp" in t for t in seen)


def test_a_secret_in_a_sites_own_field_is_still_masked(monkeypatch, tmp_path):
    """The tiebreaker: a field Omna does not know is checked with the rules."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    _spy(monkeypatch)
    body = _claude_ai_body()
    body["something_new"] = {"note": f"token {GH} mail jane.doe@example.com"}
    body["tools"] = "run it with " + GH               # not a tool list: somebody's text
    out = _mask("Claude", body)
    assert GH not in str(out) and "jane.doe@example.com" not in str(out)


def test_a_site_with_no_table_is_masked_as_before(monkeypatch, tmp_path):
    """Only sites recorded live have a table; every other site keeps smart
    masking on its whole body, tool-shaped parts included."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    seen = _spy(monkeypatch)
    out = _mask("some-other-site.example", _claude_ai_body())
    assert seen["America/New_York"] is not None
    assert GH not in str(out["tools"])


def test_an_ai_api_request_is_not_a_website_body(monkeypatch, tmp_path):
    """api.anthropic.com traffic keeps the conversation-only rule (_app_parts)."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    seen = _spy(monkeypatch)
    body = {"model": "x", "system": "You help.", "messages": [{"role": "user", "content": "hello Jane Doe"}]}
    _mask("Anthropic API", body)
    assert seen["hello Jane Doe"] is not None
