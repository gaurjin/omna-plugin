"""Which app opened this connection? mitmproxy gives us the client's (ip, port);
`lsof` tells us which process owns that port. Only called for AI hosts.

One `lsof` run lists EVERY connection into the door at once, so connections
that open together (a page loading) share it, and an app's name is looked up
with `ps` once per app, not once per connection. Before this (client test
2026-11-21, bug list row 3) the answer was remembered per port and every new
connection has a new port, so `lsof` + `ps` ran for nearly every connection.
A connection the listing does not show (the deep door's never touch the door
port) still gets its own one-port lookup."""

from __future__ import annotations

import os
import subprocess
import threading
import time
from collections import OrderedDict
from typing import Callable

from . import config

_CACHE = 512
_LOOPBACK = frozenset({"127.0.0.1", "::1", "::ffff:127.0.0.1"})


def _run_lsof(port: int) -> bytes:
    try:
        return subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:ESTABLISHED", "-Fpcn"],
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
            try:
                pid, name = int(line[1:] or 0), None
            except ValueError:
                pid, name = None, None    # a stray non-numeric line (e.g. a warning) — skip it
        elif line.startswith("c"):
            name = line[1:]
    if pid is not None and pid != own_pid and name:
        return pid, name
    return None


def parse_door_listing(out: bytes, own_pid: int, door_port: int) -> dict[int, tuple[int, str]]:
    """``lsof -iTCP:<door> -Fpcn`` → {client port: (pid, command)} for every app
    connected to the door (lines ``n127.0.0.1:50001->127.0.0.1:7789``)."""
    got: dict[int, tuple[int, str]] = {}
    pid, name = None, None
    for line in out.decode("utf-8", "replace").splitlines():
        if line.startswith("p"):
            try:
                pid, name = int(line[1:] or 0), None
            except ValueError:
                pid, name = None, None
        elif line.startswith("c"):
            name = line[1:]
        elif line.startswith("n") and "->" in line and pid is not None and pid != own_pid and name:
            local, remote = line[1:].split("->", 1)
            try:
                if int(remote.rsplit(":", 1)[1]) == door_port:
                    got[int(local.rsplit(":", 1)[1])] = (pid, name)
            except (IndexError, ValueError):
                continue
    return got


def _display_name(pid: int) -> str | None:
    """The .app name for a pid (``/Applications/Google Chrome.app/...`` → ``Google Chrome``), else the command name."""
    try:
        exe = subprocess.run(["ps", "-o", "comm=", "-p", str(pid)], capture_output=True, timeout=1.0, check=False).stdout.decode().strip()
    except (OSError, subprocess.SubprocessError):
        return None
    if ".app/" in exe:
        return exe.split(".app/")[0].rsplit("/", 1)[-1]
    return exe.rsplit("/", 1)[-1] or None


_MISS = object()
_FRESH_FOR = 30.0   # seconds: the Mac can hand a closed connection's port to another app


class ProcessResolver:
    def __init__(self, runner: Callable[[int], bytes] = _run_lsof, own_pid: int | None = None,
                 display_name: Callable[[int], str | None] = _display_name, door_port: int = config.SYSTEM_PORT,
                 clock: Callable[[], float] = time.monotonic):
        self._run = runner
        self._own = own_pid or os.getpid()
        self._name = display_name
        self._door = door_port
        self._clock = clock
        self._cache: OrderedDict[int, tuple[float, tuple[int, str] | None]] = OrderedDict()   # port -> (when, answer)
        self._names: OrderedDict[tuple[int, str], str] = OrderedDict()   # (pid, command) -> app name
        self._state = threading.Lock()     # the two dicts above; never held while a tool runs
        # One door listing at a time: a connection that waited here usually
        # finds its answer in the listing the one before it just ran. The
        # one-port backup runs outside it, so a slow `lsof` for one deep-door
        # app never queues the others (review 2026-11-24).
        self._listing = threading.Lock()

    def resolve(self, peername: tuple[str, int] | None) -> tuple[int, str] | None:
        if not peername:
            return None
        port = peername[1]
        got = self._get(port)
        if got is not _MISS:
            return got
        if peername[0] in _LOOPBACK:   # the system door's clients; the deep door's never are
            with self._listing:
                got = self._get(port)
                if got is _MISS:
                    for p, found in parse_door_listing(self._run(self._door), self._own, self._door).items():
                        self._put(p, self._named(*found))   # always the listing's answer: it is the newest
                    got = self._get(port)
            if got is not _MISS:
                return got
        got = parse_lsof(self._run(port), self._own)   # not via the door port (deep door)
        got = self._named(*got) if got else None
        self._put(port, got)
        return got

    def _get(self, port: int):
        with self._state:
            hit = self._cache.get(port)
            if hit is None or self._clock() - hit[0] > _FRESH_FOR:
                return _MISS
            return hit[1]

    def _put(self, port: int, got: tuple[int, str] | None) -> None:
        with self._state:
            self._cache[port] = (self._clock(), got)
            self._cache.move_to_end(port)
            if len(self._cache) > _CACHE:
                self._cache.popitem(last=False)

    def _named(self, pid: int, comm: str) -> tuple[int, str]:
        # Keyed by command too, so a pid the Mac hands to a new program gets a fresh name.
        key = (pid, comm)
        with self._state:
            name = self._names.get(key)
        if name is None:
            name = self._name(pid) or comm
            with self._state:
                self._names[key] = name
                if len(self._names) > _CACHE:
                    self._names.popitem(last=False)
        return pid, name
