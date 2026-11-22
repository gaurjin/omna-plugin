"""Start-up of ``/Applications/Omna Plugin.app`` (#35, 2026-11-21).

macOS 27 shows a menu-bar icon from an app only when the running program IS
the app's main program file — a launcher that hands over to another program
(a shell script, or a compiled one, even a program inside the app) left no
icon at all (13 variants tested on macOS 27.2.1). So the app's main program is
a copy of the curl command's own Python. Started with no arguments, Python
runs nothing by itself; the app's ``.pth`` file imports this module, which
then runs the menu bar and never returns.

With any arguments (the menu bar's own ``omna ensure`` runs this same Python
with ``-m omna_plugin.cli``) it does nothing. ``sys.argv`` is not filled in
yet while ``.pth`` files run, so ``sys.orig_argv`` decides.
"""

from __future__ import annotations

import os
import sys

APP_MAIN = "/Contents/MacOS/omna-menubar"


def opened_as_the_app(orig_argv: list[str], executable: str) -> bool:
    """True only for the app's own Python started with no arguments."""
    return len(orig_argv) == 1 and executable.endswith(APP_MAIN)


def _run() -> None:
    from .. import config

    log = config.menubar_log_path()
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
    except OSError:
        pass  # no log is better than no menu bar
    from .. import cli

    code = 1
    try:
        code = cli.main(["menubar"]) or 0
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)


if opened_as_the_app(list(getattr(sys, "orig_argv", [])), sys.executable):
    _run()
