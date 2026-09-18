import asyncio
import socket

import httpx
import pytest

from omna_plugin import daemon


async def test_daemon_opens_both_doors_and_stops(tmp_path, monkeypatch, unused_tcp_port_factory):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    api, system = unused_tcp_port_factory(), unused_tcp_port_factory()
    stop = asyncio.Event()
    task = asyncio.create_task(daemon.serve(api_port=api, system_port=system, stop=stop))
    h = None
    for _ in range(50):
        try:
            h = httpx.get(f"http://127.0.0.1:{api}/omna/health", timeout=0.5).json()
            break
        except httpx.HTTPError:
            await asyncio.sleep(0.1)
    assert h and h["ok"] and h["doors"] == {"api": True, "system": True, "deep": False}
    r = httpx.get(f"http://127.0.0.1:{api}/omna/proxy.pac")
    assert f"127.0.0.1:{system}" in r.text
    stop.set()
    await asyncio.wait_for(task, 10)


async def test_daemon_surfaces_an_api_bind_failure_instead_of_hanging(tmp_path, monkeypatch, unused_tcp_port_factory):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    api, system = unused_tcp_port_factory(), unused_tcp_port_factory()
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", api))
    blocker.listen(1)
    try:
        # uvicorn itself turns a bind OSError into sys.exit(3) (SystemExit) after logging it,
        # rather than letting the OSError propagate — daemon.py must catch BaseException, not
        # just Exception, to observe this on the API door's dedicated thread.
        with pytest.raises(SystemExit):
            await asyncio.wait_for(daemon.serve(api_port=api, system_port=system, stop=asyncio.Event()), 10)
    finally:
        blocker.close()
