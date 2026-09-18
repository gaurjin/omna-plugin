"""Which app opened this connection? mitmproxy gives us the client's (ip, port);
`lsof` tells us which process owns that port. Only called for AI hosts, cached per port."""

from __future__ import annotations

import os
import subprocess
from collections import OrderedDict
from typing import Callable

_CACHE = 512


def _run_lsof(port: int) -> bytes:
    try:
        return subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:ESTABLISHED", "-Fpc"],
            capture_output=True, timeout=1.5, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return b""


def parse_lsof(out: bytes, own_pid: int) -> tuple[int, str] | None:
    pid, name = None, None
    for line in out.decode("utf-8", "replace").splitlines():
        if line.startswith("p"):
            if pid is not None and pid != own_pid and name:
                return pid, name
            pid, name = int(line[1:] or 0), None
        elif line.startswith("c"):
            name = line[1:]
    if pid is not None and pid != own_pid and name:
        return pid, name
    return None


def _display_name(pid: int) -> str | None:
    """The .app name for a pid (``/Applications/Google Chrome.app/...`` → ``Google Chrome``), else the command name."""
    try:
        exe = subprocess.run(["ps", "-o", "comm=", "-p", str(pid)], capture_output=True, timeout=1.0, check=False).stdout.decode().strip()
    except (OSError, subprocess.SubprocessError):
        return None
    if ".app/" in exe:
        return exe.split(".app/")[0].rsplit("/", 1)[-1]
    return exe.rsplit("/", 1)[-1] or None


class ProcessResolver:
    def __init__(self, runner: Callable[[int], bytes] = _run_lsof, own_pid: int | None = None,
                 display_name: Callable[[int], str | None] = _display_name):
        self._run = runner
        self._own = own_pid or os.getpid()
        self._name = display_name
        self._cache: OrderedDict[int, tuple[int, str] | None] = OrderedDict()

    def resolve(self, peername: tuple[str, int] | None) -> tuple[int, str] | None:
        if not peername:
            return None
        port = peername[1]
        if port in self._cache:
            return self._cache[port]
        got = parse_lsof(self._run(port), self._own)
        if got:
            pid, comm = got
            got = (pid, self._name(pid) or comm)
        self._cache[port] = got
        if len(self._cache) > _CACHE:
            self._cache.popitem(last=False)
        return got
