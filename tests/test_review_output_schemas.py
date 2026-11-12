"""Found by /security-review of the finding-4 fixes (2026-11-12): output
schemas in "response_format" (OpenAI chat) and "output_config" (Anthropic)
went out unmasked; plus the shapes that held up, kept as guards.
(Reviewer's tests, kept as written.)
"""
import json, base64, pytest
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"[:36]
EMAIL = "jane.doe@acme.com"

@pytest.fixture(autouse=True)
def iso(monkeypatch, tmp_path):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))

def masked(obj):
    m, _ = Pipeline(MaskingSession()).mask_json(obj)
    return json.dumps(m)

def test_response_format_schema():
    s = masked({"model": "gpt", "messages": [{"role": "user", "content": "hi"}],
        "response_format": {"type": "json_schema", "json_schema": {"name": "x", "schema": {"type": "object",
            "properties": {"k": {"type": "string", "description": f"use {GH}", "enum": [EMAIL]}}}}}})
    assert GH not in s and EMAIL not in s, s

def test_output_config_schema():
    s = masked({"model": "claude", "messages": [{"role": "user", "content": "hi"}],
        "output_config": {"format": {"type": "json_schema", "schema": {"type": "object",
            "properties": {"k": {"type": "string", "description": f"use {GH}", "default": EMAIL}}}}}})
    assert GH not in s and EMAIL not in s, s

def test_tooldef_lists_and_keys():
    s = masked({"tools": [{"type": "function", "name": "f", "description": "d", "parameters": {"type": "object",
        "properties": {"name": {"type": "string", "description": f"x {GH}"}, "id": {"enum": [EMAIL]}},
        "required": ["name"], "additionalProperties": {"description": f"{GH}"}}}],
        "mcp_servers": [{"type": "url", "url": f"https://m.example/?t={GH}", "name": "m", "authorization_token": GH,
                         "tool_configuration": {"allowed_tools": ["a"]}}]})
    assert GH not in s and EMAIL not in s, s

def test_text_and_cache_key():
    s = masked({"input": "hi", "prompt_cache_key": EMAIL, "text": {"format": {"type": "json_schema", "schema": {"description": GH}}}})
    assert GH not in s and EMAIL not in s, s

PNG = "data:image/png;base64," + base64.b64encode(b"\x89PNG" + (f"{GH} {EMAIL} ".encode() * 20)).decode()
SHORT = "data:image/png;base64,iVBORw0KGgo=" + "/jane.doe@acme.com"

@pytest.mark.parametrize("pic", [PNG, SHORT])
def test_data_pictures_identical(pic):
    bodies = [
        {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": pic}}]}]},
        {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": pic}]}]},
        {"input": [{"role": "user", "content": [{"type": "input_image", "image_url": pic}]}]},
        {"input": [{"type": "function_call_output", "call_id": "c", "output": [{"type": "input_image", "image_url": pic}]}]},
    ]
    for b in bodies:
        assert pic in masked(b), b

def test_web_image_url_masked():
    s = masked({"input": [{"role": "user", "content": [{"type": "input_image", "image_url": f"https://x.example/a.png?token={GH}"}]}]})
    assert GH not in s


def test_a_top_level_text_message_is_not_read_as_a_schema(tmp_path, monkeypatch):
    """Only the Responses shape {"format": …} is an output schema; a chat
    site's top-level "text" object keeps message rules (a name in it is
    masked, as before)."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    body = {"text": {"name": "Maria Gonzalez", "message": "mail maria.gonzalez@fakecorp.example"}}
    m, _ = Pipeline(MaskingSession()).mask_json(body)
    assert "maria.gonzalez@fakecorp.example" not in json.dumps(m)
