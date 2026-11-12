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


def test_a_tools_definition_keeps_its_names_and_masks_its_prose(session):
    tools = [{"name": "deploy", "description": f"Deploys. Token {GH}, notify {EMAIL}.",
              "input_schema": {"type": "object", "required": ["db"],
                               "properties": {"db": {"type": "string", "default": PG, "enum": [PG],
                                                     "description": f"owner {EMAIL}"}}}}]
    body = {"model": "m", "tools": tools, "messages": [{"role": "user", "content": "hi"}]}
    masked, _, _ = mask_body(session, body)
    t = masked["tools"][0]
    assert GH not in str(t) and EMAIL not in str(t) and "Tr0ub4dorXq9zW" not in str(t)
    assert t["name"] == "deploy"
    s = t["input_schema"]
    assert s["type"] == "object" and s["required"] == ["db"] and s["properties"]["db"]["type"] == "string"


def test_openai_functions_and_responses_mcp_tools_are_masked(session):
    body = {"model": "m",
            "tools": [{"type": "function", "function": {"name": "deploy", "description": f"token {GH}",
                                                        "parameters": {"type": "object", "properties": {"db": {"default": PG}}}}},
                      {"type": "mcp", "server_label": "crm", "server_url": f"https://mcp.example/sse?api_key={STRIPE}",
                       "headers": {"Authorization": f"Bearer {GH}"}}],
            "functions": [{"name": "old", "description": f"key {STRIPE}"}],
            "input": "hi"}
    masked, _, _ = mask_body(session, body)
    s = str(masked)
    for real in (GH, STRIPE, "Tr0ub4dorXq9zW"):
        assert real not in s, real
    assert masked["tools"][0]["function"]["name"] == "deploy" and masked["tools"][0]["type"] == "function"
    assert masked["tools"][1]["server_label"] == "crm" and masked["functions"][0]["name"] == "old"


def test_anthropic_mcp_servers_token_and_url_are_masked(session):
    body = {"model": "m", "mcp_servers": [{"type": "url", "name": "crm", "url": f"https://mcp.example/sse?key={STRIPE}",
                                           "authorization_token": GH}],
            "container": {"id": "c_1", "skills": []}, "messages": [{"role": "user", "content": "hi"}]}
    masked, _, _ = mask_body(session, body)
    m = masked["mcp_servers"][0]
    assert STRIPE not in m["url"] and GH not in m["authorization_token"]
    assert m["type"] == "url" and m["name"] == "crm"
    assert masked["container"] == {"id": "c_1", "skills": []}          # a request setting, left alone


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
    # a schema PROPERTY named like a keep-word is a definition, not a value
    {"tools": [{"name": "t", "input_schema": {"type": "object", "properties": {
        "name": {"type": "string", "description": f"use {GH}"}}}}]},
    {"tools": [{"name": "t", "input_schema": {"type": "object", "properties": {
        "q": {"type": "string", "pattern": GH}}}}]},
    # request fields that were masked before finding 4 and must stay masked
    {"model": "m", "input": "hi", "prompt_cache_key": GH},
    {"model": "m", "input": "hi", "text": {"format": {"type": "json_schema", "name": "x", "schema": {"description": f"key {GH}"}}}},
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
