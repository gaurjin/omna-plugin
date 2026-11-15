"""Security review 2026-11-11, finding 4: a field is skipped only at its own
place, never by name anywhere in the body.

Field names like id, type, name, model, parameters, tools, thinking,
container and mcp_servers used to be skipped wherever they appeared, so a real
email under "id" in a tool call's input, a key in a tool's description and an
MCP server's access token all reached the provider. Now: request settings are
skipped at the top only; message/block structure on messages and blocks only;
a tool call's input is the person's data (everything masked); a tool's
definition keeps its names, types and schema words and masks the rest.
"""

import copy

import pytest

from omna_plugin.body import mask_body, restore_body
from omna_plugin.engine import MaskingSession

EMAIL = "maria.gonzalez@fakecorp.example"
GH = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"[:36]
STRIPE = "sk_" + "live_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7"
PG = "postgres://app:Tr0ub4dorXq9zW@db.internal:5432/prod"
PASSWORD = "S3cure-Horse-Battery-99"


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return MaskingSession()


def test_a_tool_calls_input_is_masked_whatever_its_field_names(session):
    inp = {"id": EMAIL, "type": STRIPE, "model": GH, "container": PG, "stream": GH,
           "parameters": {"password": PASSWORD}, "thinking": f"mail {EMAIL}",
           "signature": EMAIL, "tools": [f"key {STRIPE}"]}
    body = {"model": "m", "messages": [
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "crm", "input": inp}]}]}
    masked, _, _ = mask_body(session, body)
    out = str(masked["messages"][0]["content"][0]["input"])
    for real in (EMAIL, STRIPE, GH, "Tr0ub4dorXq9zW", PASSWORD):
        assert real not in out, real
    block = masked["messages"][0]["content"][0]
    assert block["id"] == "toolu_1" and block["name"] == "crm" and block["type"] == "tool_use"


def test_the_apps_tool_list_and_connector_settings_go_as_they_are(session):
    """Owner rule 2026-11-15: only what the person sends is checked. A tool's
    definition, an MCP connector's address and token and the app's output
    schema are the app's (a developer put them there on purpose): they go
    exactly as they came. (Security review 2026-11-11 finding 4 had them
    masked; reversed by the owner.) The person's own message is still masked."""
    body = {"model": "m", "input": f"mail {EMAIL}",
            "instructions": f"key {GH}",
            "tools": [{"type": "function", "name": "f", "description": f"token {GH}",
                       "parameters": {"type": "object", "properties": {"db": {"default": PG}}}},
                      {"type": "mcp", "server_label": "crm", "server_url": f"https://mcp.example/sse?api_key={STRIPE}",
                       "headers": {"Authorization": f"Bearer {GH}"}}],
            "functions": [{"name": "old", "description": f"key {STRIPE}"}],
            "mcp_servers": [{"type": "url", "url": f"https://mcp.example/sse?key={STRIPE}", "name": "m",
                             "authorization_token": GH}]}
    original = copy.deepcopy(body)
    masked, _, _ = mask_body(session, body)
    for k in ("instructions", "tools", "functions", "mcp_servers"):
        assert masked[k] == original[k], k
    assert EMAIL not in masked["input"]


def test_request_settings_and_block_structure_stay_byte_identical(session):
    body = {"model": "claude-x", "stream": True, "stop_sequences": ["[END]"], "tool_choice": {"type": "auto"},
            "messages": [{"role": "assistant", "content": [
                {"type": "thinking", "thinking": "the user asked [EMAIL_" "1]", "signature": "abc=="},
                {"type": "text", "text": f"hi {EMAIL}", "cache_control": {"type": "ephemeral"}}]}]}
    original = copy.deepcopy(body)
    masked, _, _ = mask_body(session, body)
    for k in ("model", "stream", "stop_sequences", "tool_choice"):
        assert masked[k] == original[k]
    assert masked["messages"][0]["content"][0] == original["messages"][0]["content"][0]   # signed: untouched
    assert masked["messages"][0]["content"][1]["cache_control"] == {"type": "ephemeral"}
    assert EMAIL not in masked["messages"][0]["content"][1]["text"]


def test_a_value_named_as_a_credential_is_masked_and_an_ordinary_one_is_not(session):
    body = {"messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "x", "input": {
        "password": PASSWORD, "db_password": PASSWORD, "author": "jsmith", "title": "Quarterly report"}}]}]}
    masked, _, _ = mask_body(session, body)
    inp = masked["messages"][0]["content"][0]["input"]
    assert PASSWORD not in inp["password"] and PASSWORD not in inp["db_password"]
    assert inp["author"] == "jsmith" and inp["title"] == "Quarterly report"


def test_restore_puts_back_what_masking_masked_and_never_writes_into_thinking(session):
    """Whatever is masked under a tool call's "id" comes back there; a
    thinking block is signed by the provider, so Omna never puts a real value
    into it — the only way a real value reaches a thinking block is the agent
    app writing it there itself (review finding 4, group G)."""
    body = {"messages": [{"role": "user", "content": f"look up {EMAIL}"}]}
    masked, _, labels = mask_body(session, body)
    tok = masked["messages"][0]["content"].split("look up ")[1]
    reply = {"content": [{"type": "thinking", "thinking": f"user wants {tok}", "signature": "s"},
                         {"type": "tool_use", "id": "toolu_9", "name": "crm", "input": {"id": tok}},
                         {"type": "text", "text": f"found {tok}"}]}
    out = restore_body(session.scoped(labels), reply)
    assert out["content"][0]["thinking"] == f"user wants {tok}"       # untouched: signed by the provider
    assert out["content"][1]["input"]["id"] == EMAIL                   # data under "id" comes back
    assert out["content"][1]["id"] == "toolu_9"
    assert out["content"][2]["text"] == f"found {EMAIL}"


# ---- found by /security-review of the finding-4 fix (2026-11-12) ----

@pytest.mark.parametrize("body", [
    # request fields that were masked before finding 4 and must stay masked
    # a web link under image_url (only embedded picture bytes are skipped)
    {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": f"https://x.example/a.png?token={GH}"}}]}]},
    {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": f"https://x.example/a.png?token={GH}"}]}]},
])
def test_no_secret_hides_behind_a_keep_word_or_a_setting_name(session, body):
    masked, _, _ = mask_body(session, body)
    assert GH not in str(masked)


def test_embedded_picture_bytes_stay_byte_identical(session):
    pic = "data:image/png;base64," + "iVBORw0KGgo" + "A" * 400
    body = {"messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": pic}}, {"type": "image_url", "image_url": pic}]}]}
    masked, _, _ = mask_body(session, body)
    assert masked == body


# --- security review 2026-11-11, delete list: the last of "skip by name" ----
def test_text_under_an_identifier_name_is_masked_on_a_chat_website(tmp_path, monkeypatch):
    from omna_plugin.engine import MaskingSession
    from omna_plugin.pipeline import Pipeline

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    pipe = Pipeline(MaskingSession())
    token = "ghp_" + "fgYFNmLOZlhOWtmhi0EwWcTCEsLvKQdOrH3k"
    text = f"my email is priya.raman@northwind-traders.co, token {token}"
    for key in ("id", "type", "model", "role", "file_id", "media_type", "container", "stream", "tool_choice", "service_tier"):
        masked, _ = pipe.mask_json({key: text, "note": "x"})
        assert "priya.raman" not in masked[key] and token not in masked[key], key
    masked, _ = pipe.mask_json({"messages": [{"role": "user", "id": "jane.doe@example.com", "content": "hi"}]})
    assert masked["messages"][0]["id"] != "jane.doe@example.com"


def test_real_identifiers_and_byte_exact_fields_are_still_never_touched(tmp_path, monkeypatch):
    from omna_plugin import body
    from omna_plugin.engine import MaskingSession
    from omna_plugin.pipeline import Pipeline

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    pipe = Pipeline(MaskingSession())
    req = {"model": "claude-sonnet-5", "messages": [
        {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "write to jane.doe@example.com now", "signature": "c2ln bmF0dXJl jane.doe@example.com"},
            {"type": "tool_use", "id": "toolu_01A09q90qw90lq917835lq9", "name": "Write", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01A09q90qw90lq917835lq9", "content": "ok"}]}]}
    assert pipe.mask_json(req)[0] == req
    assert not hasattr(body, "SKIP_KEYS")
