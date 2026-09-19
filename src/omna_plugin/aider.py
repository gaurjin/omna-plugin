"""Wire aider to the proxy by editing its own config files.

aider reads two different places depending on which provider you're using:
- OpenAI: the ``openai-api-base`` key in ``~/.aider.conf.yml``, aider's own
  dedicated config file (https://aider.chat/docs/config/aider_conf.html).
- Anthropic/Claude: aider runs on litellm underneath, which honours the
  standard ``ANTHROPIC_BASE_URL`` environment variable directly; aider itself
  has no YAML key for this. Rather than touch the person's shell profile
  (which affects every program in every terminal — the exact mistake that
  caused real, hours-long confusion earlier today, 2026-09-19), we set it in
  aider's own auto-loaded ``~/.env`` instead
  (https://aider.chat/docs/config/dotenv.html) — the officially documented
  mechanism for exactly this, and scoped to aider (and anything else that
  chooses to read that file), not every terminal session on the machine.

Both files are edited as marked lines, not round-tripped through a YAML or
dotenv library, so any other settings a person already has stay untouched.
The ``.env`` edit puts its marker on its own comment line above the value
(rather than a trailing inline comment) since dotenv parsers vary on whether
an inline ``#`` after an unquoted value is treated as a comment or as part of
the value — getting that wrong here would silently point aider at a broken
address instead of Omna, an easy way to end up sending things unmasked.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from . import config

MARK = "# added by omna"
_YAML_KEY_RE = re.compile(r'^openai-api-base:.*$', re.MULTILINE)
_ENV_BLOCK_RE = re.compile(rf'^{re.escape(MARK)}\nANTHROPIC_BASE_URL=.*$', re.MULTILINE)
_ENV_KEY_RE = re.compile(r'^ANTHROPIC_BASE_URL=.*$', re.MULTILINE)


def conf_file() -> Path:
    return Path.home() / ".aider.conf.yml"


def env_file() -> Path:
    return Path.home() / ".env"


def _backup(path: Path, changes: dict, key: str) -> None:
    if path.exists():
        backup = path.with_name(path.name + ".omna-backup")
        if not backup.exists():
            shutil.copyfile(path, backup)
            changes[key] = str(backup)


def _set_yaml_key(port: int, changes: dict) -> None:
    path = conf_file()
    text = path.read_text() if path.exists() else ""
    new_line = f'openai-api-base: "{config.base_url(port)}/v1"  {MARK}'
    existing = _YAML_KEY_RE.search(text)
    if existing and MARK not in existing.group(0):
        return  # someone set this deliberately; don't fight it silently
    _backup(path, changes, "openai_backup")
    if existing:
        if existing.group(0).strip() == new_line.strip():
            return
        text = _YAML_KEY_RE.sub(new_line, text, count=1)
    else:
        sep = "" if not text or text.endswith("\n") else "\n"
        text = f"{text}{sep}{new_line}\n"
    path.write_text(text)
    changes["openai_base"] = True


def _set_env_block(port: int, changes: dict) -> None:
    path = env_file()
    text = path.read_text() if path.exists() else ""
    _backup(path, changes, "anthropic_backup")
    new_block = f"{MARK}\nANTHROPIC_BASE_URL={config.base_url(port)}"
    existing = _ENV_BLOCK_RE.search(text)
    if existing:
        if existing.group(0).strip() == new_block.strip():
            return
        text = _ENV_BLOCK_RE.sub(new_block, text, count=1)
    elif _ENV_KEY_RE.search(text):
        # a value we didn't set (no marker line above it) — leave it alone,
        # someone configured this deliberately; don't fight it silently.
        return
    else:
        sep = "" if not text or text.endswith("\n") else "\n"
        text = f"{text}{sep}{new_block}\n"
    path.write_text(text)
    changes["anthropic_base"] = True


def init(port: int = config.DEFAULT_PORT) -> dict:
    changes = {"openai_base": False, "anthropic_base": False, "openai_backup": None, "anthropic_backup": None}
    _set_yaml_key(port, changes)
    _set_env_block(port, changes)
    return changes


def uninstall() -> dict:
    """Remove exactly what ``init`` added; leave everything else untouched."""
    changes = {"openai_base": False, "anthropic_base": False, "openai_backup": False, "anthropic_backup": False}

    conf = conf_file()
    conf_backup = conf.with_name(conf.name + ".omna-backup")
    if conf_backup.exists():
        conf_backup.unlink()
        changes["openai_backup"] = True
    if conf.exists():
        text = conf.read_text()
        m = _YAML_KEY_RE.search(text)
        if m and MARK in m.group(0):
            text = _YAML_KEY_RE.sub("", text, count=1)
            text = re.sub(r"\n{3,}", "\n\n", text)
            conf.write_text(text)
            changes["openai_base"] = True

    env = env_file()
    env_backup = env.with_name(env.name + ".omna-backup")
    if env_backup.exists():
        env_backup.unlink()
        changes["anthropic_backup"] = True
    if env.exists():
        text = env.read_text()
        m = _ENV_BLOCK_RE.search(text)
        if m:
            text = _ENV_BLOCK_RE.sub("", text, count=1)
            text = re.sub(r"\n{3,}", "\n\n", text)
            env.write_text(text)
            changes["anthropic_base"] = True

    return changes


def status() -> dict:
    conf_text = conf_file().read_text() if conf_file().exists() else ""
    env_text = env_file().read_text() if env_file().exists() else ""
    m1 = _YAML_KEY_RE.search(conf_text)
    m2 = _ENV_BLOCK_RE.search(env_text)
    return {
        "openai_base_file": str(conf_file()),
        "openai_base": m1.group(0).split(":", 1)[1].split(MARK)[0].strip().strip('"') if m1 else None,
        "anthropic_base_file": str(env_file()),
        "anthropic_base": m2.group(0).splitlines()[1].split("=", 1)[1].strip() if m2 else None,
    }
