"""Wire Codex CLI to the proxy by editing its ``config.toml``.

Codex CLI reads a top-level ``openai_base_url`` key from ``~/.codex/config.toml``
(https://learn.chatgpt.com/docs/config-file/config-reference) to override the
built-in ``openai`` provider's address — verified 2026-09-19, since a wrong guess
here would mean Codex silently keeps talking to OpenAI directly, unmasked.

Edited as a single line, not round-tripped through a TOML library: a person may
have their own ``model_providers`` blocks and comments in this file, and a
generic parse-and-dump would reformat or drop them. Same shape as
``claude_code.py``: mark our line, back up the file once, uninstall removes only
what we added.

WHERE the line goes matters (security review 2026-11-11, finding 8). It used
to be appended at the end; when the file ended with a ``[section]`` the line
landed inside that section, Codex ignored it and talked to OpenAI directly,
and ``omna status`` still said "wired". TOML keys are top-level only before
the first ``[section]`` header, and line 1 always is — so our line goes first,
and the result is read back with ``tomllib`` (what Codex sees) before it is
kept. ``status`` reads the file the same way, and also says when Codex uses a
provider other than the built-in ``openai`` one, which ``openai_base_url``
does not cover.
"""

from __future__ import annotations

import re
import shutil
import tomllib
from pathlib import Path

from . import config

MARK = "# added by omna"
# Any line we added, wherever an older version put it.
_OURS_RE = re.compile(r'^[ \t]*openai_base_url[ \t]*=[^\n]*' + re.escape(MARK) + r'[^\n]*\n?', re.MULTILINE)
# The provider ``openai_base_url`` applies to (Codex's built-in default).
BUILTIN_PROVIDER = "openai"


def settings_file() -> Path:
    return Path.home() / ".codex" / "config.toml"


def _our_line(port: int) -> str:
    return f'openai_base_url = "{config.base_url(port)}/v1"  {MARK}'


def _without_ours(text: str) -> str:
    return _OURS_RE.sub("", text)


def _parse(text: str) -> dict | None:
    """The file as Codex reads it, or None when it is not valid TOML."""
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None


def _provider(doc: dict) -> str:
    """The provider Codex will use: the selected profile's, else the
    top-level ``model_provider``, else the built-in ``openai``."""
    profile = doc.get("profile")
    if isinstance(profile, str):
        p = (doc.get("profiles") or {}).get(profile) or {}
        if isinstance(p, dict) and isinstance(p.get("model_provider"), str):
            return p["model_provider"]
    mp = doc.get("model_provider")
    return mp if isinstance(mp, str) else BUILTIN_PROVIDER


def init(path: Path, port: int = config.DEFAULT_PORT) -> dict:
    """Put our ``openai_base_url`` line at the top level. Returns what changed;
    ``problem`` says why nothing was written when the file can't be wired."""
    changes = {"base_url": False, "backup": None, "problem": None}
    text = path.read_text() if path.exists() else ""
    if _parse(text) is None:
        changes["problem"] = f"{path} is not valid TOML (Codex cannot read it either); left as it is"
        return changes
    rest = _without_ours(text)
    if "openai_base_url" in (_parse(rest) or {}):
        return changes  # someone set the top-level value deliberately; don't fight it silently
    new_line = _our_line(port)
    new_text = f"{new_line}\n{rest}"
    if new_text == text:
        return changes  # idempotent: already exactly this, in the right place
    doc = _parse(new_text)
    if doc is None or doc.get("openai_base_url") != f"{config.base_url(port)}/v1":
        changes["problem"] = f"could not place openai_base_url at the top level of {path}; left as it is"
        return changes
    if path.exists():
        backup = path.with_name(path.name + ".omna-backup")
        if not backup.exists():
            shutil.copyfile(path, backup)
            changes["backup"] = str(backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new_text)
    changes["base_url"] = True
    return changes


def uninstall(path: Path) -> dict:
    """Remove exactly what ``init`` added; leave everything else untouched."""
    changes = {"base_url": False, "backup": False}
    backup = path.with_name(path.name + ".omna-backup")
    if backup.exists():
        backup.unlink()
        changes["backup"] = True
    if not path.exists():
        return changes
    text = path.read_text()
    rest = _without_ours(text)
    if rest != text:
        rest = re.sub(r"\n{3,}", "\n\n", rest)  # collapse the blank line left behind
        path.write_text(rest)
        changes["base_url"] = True
    return changes


def status(path: Path) -> dict:
    """What Codex will actually do, read the way Codex reads the file.

    ``base_url``: the top-level ``openai_base_url`` (None when absent).
    ``ours``: that value is the line Omna wrote. ``provider``: the provider
    Codex uses. ``routed``: Codex's requests go through the address in
    ``base_url``. ``problem``: why not, in one sentence, else None."""
    out = {"file": str(path), "base_url": None, "ours": False,
           "provider": BUILTIN_PROVIDER, "routed": False, "problem": None}
    if not path.exists():
        out["problem"] = "no Codex config file"
        return out
    text = path.read_text()
    doc = _parse(text)
    if doc is None:
        out["problem"] = "the Codex config file is not valid TOML, so Codex cannot read it"
        return out
    value = doc.get("openai_base_url")
    out["base_url"] = value if isinstance(value, str) else None
    out["provider"] = _provider(doc)
    ours = _OURS_RE.search(text)
    out["ours"] = bool(ours) and out["base_url"] is not None and f'"{out["base_url"]}"' in ours.group(0)
    if out["base_url"] is None:
        out["problem"] = ("omna's line is inside a [section], where Codex ignores it"
                          if ours else "no openai_base_url at the top level")
    elif out["provider"] != BUILTIN_PROVIDER:
        out["problem"] = (f'Codex uses the "{out["provider"]}" provider, which talks to its own '
                          f"address — openai_base_url only covers the built-in openai provider")
    else:
        out["routed"] = True
    return out
