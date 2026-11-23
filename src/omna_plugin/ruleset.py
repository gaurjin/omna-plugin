"""``~/.omna/ruleset.json``: the allowlist, custom rules and switched-off categories.

This one file decides what is NOT masked, so (security review 2026-11-11,
finding 15):

* it is written owner-only (0600) and tightened if found looser — other
  users of the Mac could read which values a company marked safe;
* every receipt carries its fingerprint, so "the rules changed here" is on
  the record (one ``.+`` line used to switch all masking off with no trace);
* the masking engine (omna-pii-mask) refuses an allowlist pattern that
  matches everything and never lets a pattern spare a secret — this module
  only reports what the engine refused, so ``omna status`` can say it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

import omna_pii_mask

from . import config

_cache: dict[str, tuple[tuple[int, int] | None, dict]] = {}


def write(data: dict) -> None:
    """Save the ruleset, owner-only, in one step."""
    config.ensure_home()
    p = config.ruleset_path()
    tmp = p.with_suffix(".json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(data, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def secure() -> None:
    """Tighten a ruleset file that someone else on this Mac could read or
    write (written 0644 before 0.6.21)."""
    p = config.ruleset_path()
    try:
        if p.stat().st_mode & 0o077:
            os.chmod(p, 0o600)
    except OSError:
        pass


def _stamp() -> tuple[int, int] | None:
    try:
        st = config.ruleset_path().stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def summary() -> dict:
    """What the ruleset holds right now: its fingerprint (first 16 hex of the
    file's SHA-256; "" when there is no file), how many entries of each kind,
    and the allowlist patterns the engine refused. Re-read only when the
    file changed."""
    home = str(config.home())
    stamp = _stamp()
    hit = _cache.get(home)
    if hit and hit[0] == stamp:
        return hit[1]
    out = {"fingerprint": "", "allowlist": 0, "custom_rules": 0, "mask_off": [], "ignored_allowlist": [], "error": "",
           "never": [], "always": []}
    p = config.ruleset_path()
    if stamp is not None:
        try:
            raw = p.read_bytes()
            out["fingerprint"] = hashlib.sha256(raw).hexdigest()[:16]
            data = json.loads(raw)
            if isinstance(data, dict):
                out["allowlist"] = len(data.get("allowlist") or [])
                out["custom_rules"] = len(data.get("custom_rules") or [])
                out["mask_off"] = [str(c) for c in (data.get("mask_off") or [])]
                out["never"] = [_shown(str(x)) for x in data.get("allowlist") or [] if str(x) not in _BUILT_IN]
                out["always"] = [_shown(str(r.get("pattern", ""))) + ("" if r.get("label") == "CLIENT" else f" (as {r.get('label')})")
                                 for r in data.get("custom_rules") or [] if isinstance(r, dict)]
        except (OSError, ValueError):
            out["error"] = "cannot be read"
        check = getattr(omna_pii_mask, "ruleset_check", None)
        if check is not None and not out["error"]:
            try:
                out["ignored_allowlist"] = [str(x) for x in check(str(p)).get("ignored_allowlist", [])]
            except ValueError as e:
                out["error"] = str(e)
    _cache[home] = (stamp, out)
    return out


# The entries every install starts with (engine.DEFAULT_ALLOWLIST): not the person's list.
_BUILT_IN = {r"127\.0\.0\.1", r"0\.0\.0\.0", r"::1", r"localhost"}


def _shown(pattern: str) -> str:
    """A list entry as the person typed it (``omna allow``/``mask-always``
    escape it); a hand-written pattern is shown as it is."""
    p = pattern.removeprefix("(?i)").removeprefix(r"\b").removesuffix(r"\b")
    plain = re.sub(r"\\(.)", r"\1", p)
    return plain if re.escape(plain) == p else pattern


def fingerprint() -> str:
    return summary()["fingerprint"]


def status_lines() -> list[str]:
    """For ``omna status``: one calm line, plus a loud one per problem."""
    s = summary()
    if not s["fingerprint"]:
        return ["ruleset:      none (built-in rules only)"]
    lines = [f"ruleset:      {s['allowlist']} allowlist entr{'y' if s['allowlist'] == 1 else 'ies'}, "
             f"{s['custom_rules']} custom rule(s)"
             + (f", switched off: {', '.join(s['mask_off'])}" if s["mask_off"] else "")
             + f"  ·  fingerprint {s['fingerprint']} (on every receipt)"]
    if s["always"]:
        lines.append(f"              always mask: {', '.join(s['always'])}")
    if s["never"]:
        lines.append(f"              never mask:  {', '.join(s['never'])}")
    for pat in s["ignored_allowlist"]:
        lines.append(f"              IGNORED allowlist entry {pat!r}: it matches everything, so it would switch masking off. "
                     f"Remove it from {config.ruleset_path()}")
    if s["error"]:
        lines.append(f"              PROBLEM: {config.ruleset_path()} {s['error']} — requests are refused until it is fixed or removed")
    return lines
