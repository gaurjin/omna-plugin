"""Run every door in one process: the API door (uvicorn) and the mitmproxy
master (system door + deep door), sharing one Policy and one Pipeline/
MaskingSession, with one clean shutdown path (an ``asyncio.Event``).

The API door's own request-handling runs on a dedicated OS thread with its
own event loop. That is what lets a caller in THIS SAME PROCESS reach it with
a plain, synchronous HTTP client (e.g. a health check, or a test) without
deadlocking: a synchronous call blocks whatever thread calls it, and if that
happened to be the same thread serving the request, the request could never
be answered. The system/deep door (mitmproxy) and the coordinating ``stop``
wait live on the outer event loop, the one returned by ``asyncio.run``.
"""

from __future__ import annotations

import asyncio
import signal
import threading

import uvicorn

from . import config, crashlog
from .engine import MaskingSession, engine_version
from .pipeline import Pipeline
from .policy import Policy
from .procs import ProcessResolver
from .proxy import create_app
from .system_door import OmnaAddon, build_master


async def serve(api_port: int = config.DEFAULT_PORT, system_port: int = config.SYSTEM_PORT, *,
                smart: bool = False, restore_secrets: bool = True, stop: asyncio.Event | None = None) -> None:
    policy = Policy.load()
    session = MaskingSession(smart=smart, restore_secrets=restore_secrets)
    if smart:
        import omna_pii_mask

        print("omna: preparing the on-device Contextual model (first run downloads ~809 MB)...", flush=True)
        omna_pii_mask.download_model()
    pipeline = Pipeline(session)
    stop = stop or asyncio.Event()

    app = create_app(session, pipeline=pipeline, policy=policy, doors_state=policy.doors, system_port=system_port)
    api = uvicorn.Server(uvicorn.Config(app, host=config.DEFAULT_HOST, port=api_port, log_level="warning", access_log=False))
    api.install_signal_handlers = lambda: None   # one handler for the whole process, below

    api_ready = threading.Event()
    api_error: list[BaseException] = []
    main_loop = asyncio.get_running_loop()

    def _run_api() -> None:
        api_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(api_loop)

        async def _serve() -> None:
            api_ready.set()
            await api.serve()

        try:
            api_loop.run_until_complete(_serve())
        except BaseException as exc:   # e.g. the port is already in use
            api_error.append(exc)
            api_ready.set()            # don't leave the waiter blocked on an early failure
            main_loop.call_soon_threadsafe(stop.set)   # don't run headless of the API door
        finally:
            api_loop.close()

    api_thread = threading.Thread(target=_run_api, name="omna-api-door", daemon=True)
    api_thread.start()
    await asyncio.to_thread(api_ready.wait)

    master = None
    tasks: list[asyncio.Task] = []
    if policy.doors.get("system", True):
        addon = OmnaAddon(pipeline, policy, door="system", resolver=ProcessResolver().resolve)
        master = build_master(policy, addon, port=system_port, ca_dir=config.ca_dir(),
                              deep_apps=policy.deep_apps if policy.doors.get("deep") else None)
        tasks.append(asyncio.create_task(master.run()))

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass

    print(f"omna: masking proxy on {config.base_url(api_port)}  (engine {engine_version()}, smart={'on' if smart else 'off'}, secrets={'restored locally' if restore_secrets else 'redacted for good'})", flush=True)
    if master:
        print(f"omna: system door on 127.0.0.1:{system_port}", flush=True)

    await stop.wait()
    api.should_exit = True
    if master:
        master.shutdown()
    await asyncio.gather(*tasks, return_exceptions=True)
    await asyncio.to_thread(api_thread.join, 10)
    if api_error:
        raise api_error[0]


def run(**kw) -> None:
    # The daemon dies into a log file nobody reads. Record the cause locally,
    # masked and unsent, so `omna crash` can explain it later (#132).
    crashlog.install_excepthook("daemon")
    try:
        asyncio.run(serve(**kw))
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:
        crashlog.record(e, where="daemon")
        raise
