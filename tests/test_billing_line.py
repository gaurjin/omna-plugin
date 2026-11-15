"""Claude Code's billing line goes to Anthropic byte-for-byte.

Found 2026-11-15 (Claude Code 2.1.325, curl command 0.6.21, smart masking on —
the default): the compact smart model read ``cc_`` and ``cli`` in
``x-anthropic-billing-header: cc_version=…; cc_entrypoint=sdk-cli;`` as names,
the line went out with name stand-ins in place of "cc_" and "cli", and Anthropic
refused every request: 400 "x-anthropic-billing-header is a reserved keyword".
The line is Claude Code's own billing check, not anything the person typed —
Omna never edits an AI company's security or billing layer.
"""

from omna_plugin.body import mask_body
from omna_plugin.engine import MaskResult

P1, P2 = "[" + "PERSON_1]", "[" + "PERSON_2]"   # two pieces: never a full token in a file
LINE = "x-anthropic-billing-header: cc_version=2.1.325.ff3; cc_entrypoint=sdk-cli;"


class Mangler:
    """Stands in for a smart model that finds a 'name' in every string."""

    def mask_text(self, s, style=None, only=None):
        masked = s.replace("cc_", P1).replace("Jane Doe", P2)
        n = int(masked != s)
        return MaskResult(masked=masked, counts={"PERSON": n} if n else {}, labels=["PERSON_1"] if n else [])


def body(first):
    return {
        "model": "claude-opus-5-5",
        "system": [
            {"type": "text", "text": first},
            {"type": "text", "text": "Notes: the customer is Jane Doe.", "cache_control": {"type": "ephemeral"}},
        ],
        "messages": [{"role": "user", "content": "hi Jane Doe"}],
    }


def test_billing_line_is_sent_unchanged():
    out, _, _ = mask_body(Mangler(), body(LINE))
    assert out["system"][0]["text"] == LINE


def test_the_rest_of_the_system_prompt_and_messages_are_still_masked():
    out, counts, _ = mask_body(Mangler(), body(LINE))
    assert out["system"][1]["text"] == f"Notes: the customer is {P2}."
    assert out["messages"][0]["content"] == f"hi {P2}"
    assert counts["PERSON"] == 2


def test_a_lookalike_carrying_more_than_settings_is_masked():
    # Anything that is not exactly "name=value;" settings is somebody's text.
    for text in (LINE + " my friend Jane Doe", "x-anthropic-billing-header: note=Jane Doe;",
                 "Jane Doe\n" + LINE):
        out, _, _ = mask_body(Mangler(), body(text))
        assert "Jane Doe" not in out["system"][0]["text"], text


def test_the_line_is_spared_only_as_its_own_system_block():
    # Inside a longer system string it is masked with the rest.
    out, _, _ = mask_body(Mangler(), {**body(LINE), "system": LINE + "\nYou help Jane Doe."})
    assert "Jane Doe" not in out["system"]


def test_only_the_system_prompt_is_spared():
    # The same line typed into a message is masked like any other text.
    b = body("You help.")
    b["messages"][0]["content"] = LINE
    out, _, _ = mask_body(Mangler(), b)
    assert out["messages"][0]["content"] != LINE


ID = ('{"device_id":"' + "a" * 64 + '","account_uuid":"6258d7e0-bc30-4995-bf22-7f9a2a6e9e0a",'
      '"session_id":"c56c344f-5c16-4f0d-b35a-6cfcd86c0567"}')


class MaskAll:
    """A checker that flags every string: shows what is spared and what is not."""

    def mask_text(self, s, style=None, only=None):
        return MaskResult(masked="[X]", counts={"PERSON": 1}, labels=["PERSON_1"])


def test_anthropic_safety_check_and_claude_code_ids_go_as_they_are():
    safeguards = [{"type": "dangerous_tool_use", "classifier_context": {"v": 1, "home_dir": "/Users/jane"}}]
    b = {**body(LINE), "safeguards": safeguards, "metadata": {"user_id": ID}}
    out, _, _ = mask_body(MaskAll(), b)
    assert out["safeguards"] == safeguards
    assert out["metadata"]["user_id"] == ID
    assert out["messages"][0]["content"] == "[X]"


def test_any_other_user_id_is_masked():
    for uid in ("jane.doe@example.com", ID.replace("}", ',"name":"Jane Doe"}'), ID[:-2] + 'x"}'):
        out, _, _ = mask_body(MaskAll(), {**body(LINE), "metadata": {"user_id": uid}})
        assert out["metadata"]["user_id"] == "[X]", uid
