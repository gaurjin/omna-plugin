import pathlib

from omna_plugin.style import (REALISTIC, STYLES, TOKENS, StyleDecision, style_for_door,
                               style_for_extension)


def test_tokens_are_allowed_at_every_door():
    for door in ("api", "system", "deep", "something-new"):
        d = style_for_door(door, TOKENS)
        assert d.style == TOKENS and not d.refused


def test_realistic_is_allowed_only_at_the_system_door():
    d = style_for_door("system", REALISTIC)
    assert d.style == REALISTIC and not d.refused and d.reason == ""


def test_realistic_is_refused_at_the_api_door_with_a_printable_reason():
    d = style_for_door("api", REALISTIC)
    assert d.style == TOKENS          # downgraded...
    assert d.refused is True          # ...but never silently
    assert "writes files" in d.reason or "write files" in d.reason
    assert "Claude Code" in d.reason
    assert d.line()


def test_realistic_is_refused_at_the_deep_door():
    d = style_for_door("deep", REALISTIC)
    assert d.style == TOKENS and d.refused is True and d.reason


def test_an_unknown_door_refuses_realistic():
    d = style_for_door("brand-new-door", REALISTIC)
    assert d.style == TOKENS and d.refused is True


def test_an_unknown_style_falls_back_to_tokens_and_says_so():
    d = style_for_door("system", "fancy")
    assert d.style == TOKENS and d.refused is True and "fancy" in d.reason


def test_nothing_is_refused_quietly():
    """Every refusal carries a sentence a person can read. A refusal with an
    empty reason would be a silent downgrade wearing a flag."""
    for door in ("api", "system", "deep", "?"):
        for requested in (TOKENS, REALISTIC, "fancy"):
            d = style_for_door(door, requested)
            assert d.refused == bool(d.reason)
            assert d.style in STYLES


def test_only_style_py_decides_what_realistic_means():
    """The rule lives in ONE function. A door that compared the style string
    itself would be a second copy of the rule, free to drift from this one."""
    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "omna_plugin"
    for name in ("proxy.py", "system_door.py", "body.py", "pipeline.py", "engine.py",
                 "adapters/generic.py", "adapters/base.py"):
        text = (src / name).read_text()
        assert '"realistic"' not in text and "'realistic'" not in text, name
    # ...and every door asks this module instead.
    for name in ("proxy.py", "system_door.py"):
        assert "style_for_door" in (src / name).read_text(), name


def test_styles_tuple_is_the_two_we_document():
    assert STYLES == (TOKENS, REALISTIC)
    assert isinstance(style_for_door("api", TOKENS), StyleDecision)


# ----------------------------------------------- the Chrome extension (#143)
# The extension masks inside the browser, so it never reaches style_for_door
# on its own — the plugin answers for it on /omna/health.

def test_the_extension_may_use_realistic_when_the_system_door_is_off():
    d = style_for_extension(REALISTIC, system_door_on=False)
    assert d.style == REALISTIC and not d.refused


def test_the_extension_keeps_tokens_while_the_system_door_is_on():
    """Masked twice, a realistic fake value is gone for good: the second pass
    cannot tell it from real data. A numbered token survives, so that is what
    the extension keeps."""
    d = style_for_extension(REALISTIC, system_door_on=True)
    assert d.style == TOKENS
    assert d.refused is True
    assert "masks the same request a second time" in d.reason
    assert d.line()


def test_the_extension_follows_the_policy_when_it_asks_for_tokens():
    for on in (True, False):
        d = style_for_extension(TOKENS, system_door_on=on)
        assert d.style == TOKENS and not d.refused


def test_the_extension_refuses_an_unknown_style_the_same_way_a_door_does():
    for on in (True, False):
        d = style_for_extension("fancy", system_door_on=on)
        assert d.style == TOKENS and d.refused is True and "fancy" in d.reason


def test_the_extension_is_never_refused_quietly_either():
    for requested in (TOKENS, REALISTIC, "fancy"):
        for on in (True, False):
            d = style_for_extension(requested, system_door_on=on)
            assert d.refused == bool(d.reason)
            assert d.style in STYLES
