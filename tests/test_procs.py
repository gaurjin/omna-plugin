from omna_plugin.procs import ProcessResolver, parse_lsof

LSOF = b"p812\ncGoogle Chrome He\np4242\ncomna\n"


def test_parse_lsof_excludes_our_own_pid():
    assert parse_lsof(LSOF, own_pid=4242) == (812, "Google Chrome He")


def test_parse_lsof_empty():
    assert parse_lsof(b"", own_pid=1) is None


def test_parse_lsof_skips_a_stray_non_numeric_line():
    out = b"plsof: WARNING: something\np812\ncGoogle Chrome He\n"
    assert parse_lsof(out, own_pid=4242) == (812, "Google Chrome He")


def test_resolver_caches_and_uses_runner():
    calls = []

    def fake_run(port):
        calls.append(port)
        return LSOF

    r = ProcessResolver(runner=fake_run, own_pid=4242, display_name=lambda pid: "Google Chrome")
    assert r.resolve(("127.0.0.1", 50123)) == (812, "Google Chrome")
    assert r.resolve(("127.0.0.1", 50123)) == (812, "Google Chrome")
    assert calls == [7789, 50123]   # the door listing (empty here), then the one-port backup; then remembered


def test_a_connection_not_from_this_mac_loopback_skips_the_door_listing():
    """The deep door's connections never come in over 127.0.0.1: listing the
    door for them would only add a second `lsof` run."""
    calls = []

    def fake_run(port):
        calls.append(port)
        return LSOF

    r = ProcessResolver(runner=fake_run, own_pid=4242, display_name=lambda pid: "Google Chrome")
    assert r.resolve(("192.168.1.20", 50123)) == (812, "Google Chrome")
    assert calls == [50123]


def _door_listing(ports, door=7789):
    """What `lsof -iTCP:<door>` prints while one app holds these connections to the door."""
    out = b"p812\ncGoogle Chrome He\n"
    for i, p in enumerate(ports):
        out += b"f%d\nn127.0.0.1:%d->127.0.0.1:%d\n" % (30 + i, p, door)
    out += b"p4242\ncomna\n"
    for i, p in enumerate(ports):
        out += b"f%d\nn127.0.0.1:%d->127.0.0.1:%d\n" % (60 + i, door, p)
    return out


def test_a_burst_of_connections_runs_the_app_lookup_once_not_once_each():
    """Bug list row 3 (client test 2026-11-21): the cache was keyed by the
    connection's own port, and every new connection has a new port, so
    `lsof` + `ps` ran for almost every connection. A burst of 20 connections
    from one app must cost at most 2 `lsof` runs and 1 `ps` run."""
    ports = list(range(50001, 50021))
    lsof_runs, ps_runs = [], []

    def fake_run(port):
        lsof_runs.append(port)
        return _door_listing(ports) if port == 7789 else LSOF

    def fake_name(pid):
        ps_runs.append(pid)
        return "Google Chrome"

    r = ProcessResolver(runner=fake_run, own_pid=4242, display_name=fake_name)
    for p in ports:
        assert r.resolve(("127.0.0.1", p)) == (812, "Google Chrome")
    assert len(lsof_runs) <= 2, f"lsof ran {len(lsof_runs)} times for 20 connections"
    assert len(ps_runs) == 1, f"ps ran {len(ps_runs)} times for one app"


def test_a_connection_the_door_listing_misses_still_gets_its_own_lookup():
    """The deep door's connections never touch the door port: the old
    one-port lookup stays as the backup, so they are still named."""
    calls = []

    def fake_run(port):
        calls.append(port)
        return _door_listing([]) if port == 7789 else LSOF

    r = ProcessResolver(runner=fake_run, own_pid=4242, display_name=lambda pid: "Google Chrome")
    assert r.resolve(("127.0.0.1", 50123)) == (812, "Google Chrome")
    assert 50123 in calls


def test_a_port_the_mac_reuses_for_another_app_is_looked_up_again():
    """Review 2026-11-24 (a risk older than this fix): a remembered answer was
    kept forever, so a port the Mac gave to a different app later still
    showed the first app's name, and per-app rules used the wrong app."""
    now = [0.0]
    app = [b"p812\ncGoogle Chrome He\n"]
    r = ProcessResolver(runner=lambda port: app[0], own_pid=4242, display_name=lambda pid: None,
                        clock=lambda: now[0])
    assert r.resolve(("192.168.1.20", 50123)) == (812, "Google Chrome He")
    app[0] = b"p900\ncClaude\n"
    now[0] = 31.0
    assert r.resolve(("192.168.1.20", 50123)) == (900, "Claude")


def test_slow_one_port_lookups_do_not_wait_for_each_other():
    """Review 2026-11-24: one lock around every lookup made 20 deep-door
    connections run `lsof` one after another, filling the thread pool that
    masking also uses."""
    import concurrent.futures as cf
    import time

    def slow_run(port):
        time.sleep(0.3)
        return LSOF

    r = ProcessResolver(runner=slow_run, own_pid=4242, display_name=lambda pid: "Google Chrome")
    t0 = time.monotonic()
    with cf.ThreadPoolExecutor(5) as pool:
        got = list(pool.map(lambda p: r.resolve(("192.168.1.20", p)), range(50001, 50006)))
    assert all(g == (812, "Google Chrome") for g in got)
    assert time.monotonic() - t0 < 0.9, "five 0.3 s lookups ran one after another"
