"""Which masking style a door is allowed to use — the whole rule, in one place.

Two styles exist:

- **tokens** (the default, everywhere): every masked value becomes a numbered
  token. A token left behind by accident is *visibly* wrong, so somebody
  notices.
- **realistic**: every masked value becomes a realistic-looking fake value.
  The model reads ordinary prose, which it handles better — but a fake value
  left behind looks exactly like real data, so nobody notices, and it gets
  committed to a repository for ever.

That is why this is a safety rule and not a preference. Anything that WRITES
FILES must keep numbered tokens:

- the **api** door is Claude Code, aider, Codex, Continue and VS Code — every
  one of them edits files;
- the **deep** door captures a named desktop app, and that list can hold an
  editor just as easily as a chat app, so it sits on the same side of the line;
- the **system** door is the browser and the chat websites. They do not write
  your files. It is the only door that may use realistic values.

A refusal here is NEVER a silent downgrade: the caller gets ``refused=True``
and a sentence to print, and every door prints it.

Nothing else in the codebase compares a style string — ``tests/test_style.py``
fails if a door grows its own copy of this rule.
"""

from __future__ import annotations

from dataclasses import dataclass

TOKENS = "tokens"
REALISTIC = "realistic"
STYLES = (TOKENS, REALISTIC)

#: The only door where a realistic fake value may be sent.
DOORS_ALLOWING_REALISTIC = frozenset({"system"})

_WHY = ("it reaches tools that write files (Claude Code, aider, Codex, Continue, "
        "VS Code), and a realistic fake value left behind in a file looks like real "
        "data instead of an obvious mistake")


@dataclass(frozen=True)
class StyleDecision:
    """What a door will really do, and why."""

    style: str        # the style that will actually be used
    requested: str    # what the policy asked for
    refused: bool     # the request was not honoured (and never quietly)
    reason: str       # one printable sentence; "" when nothing was refused

    def line(self) -> str:
        """One line for a human: what this door refused, and why."""
        return f"omna: {self.reason}" if self.refused else ""


def style_for_door(door: str, requested: str) -> StyleDecision:
    """The one function that decides. Every door calls this; nobody else decides."""
    if requested not in STYLES:
        return StyleDecision(
            TOKENS, requested, True,
            f"{requested!r} is not a masking style, so numbered tokens are in use "
            f"(the styles are: {', '.join(STYLES)})",
        )
    if requested == TOKENS:
        return StyleDecision(TOKENS, TOKENS, False, "")
    if door in DOORS_ALLOWING_REALISTIC:
        return StyleDecision(REALISTIC, REALISTIC, False, "")
    return StyleDecision(
        TOKENS, REALISTIC, True,
        f"realistic fake values are refused at the {door} door because {_WHY}; "
        f"it keeps numbered tokens",
    )


def style_for_extension(requested: str, system_door_on: bool) -> StyleDecision:
    """What the Chrome extension may write. The browser IS the system door, so
    this starts from that door's decision — and then adds the one extra
    condition that only applies to the extension.

    The extension masks inside the browser, before the request leaves it. When
    the system door is ALSO running, that same request is masked a second time
    on its way out, and the second pass cannot tell a stand-in from real data:

    - a numbered token has brackets, so the detector walks straight past it and
      the extension gets it back unchanged and puts the real value back;
    - a realistic fake value looks exactly like a real e-mail or a real name —
      which is the whole point of it — so the second pass masks it again, and
      then nothing can put the real value back for the person.

    So while the system door is on, the extension keeps numbered tokens. The
    refusal is returned, never applied quietly, for the same reason every other
    refusal here is.
    """
    decision = style_for_door("system", requested)
    if decision.style == REALISTIC and system_door_on:
        return StyleDecision(
            TOKENS, requested, True,
            "the browser extension keeps numbered tokens while the system door is on, "
            "because that door masks the same request a second time and a realistic "
            "fake value cannot survive being masked twice — a numbered token can",
        )
    return decision
