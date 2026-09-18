from omna_plugin.procs import ProcessResolver, parse_lsof

LSOF = b"p812\ncGoogle Chrome He\np4242\ncomna\n"


def test_parse_lsof_excludes_our_own_pid():
    assert parse_lsof(LSOF, own_pid=4242) == (812, "Google Chrome He")


def test_parse_lsof_empty():
    assert parse_lsof(b"", own_pid=1) is None


def test_resolver_caches_and_uses_runner():
    calls = []

    def fake_run(port):
        calls.append(port)
        return LSOF

    r = ProcessResolver(runner=fake_run, own_pid=4242, display_name=lambda pid: "Google Chrome")
    assert r.resolve(("127.0.0.1", 50123)) == (812, "Google Chrome")
    assert r.resolve(("127.0.0.1", 50123)) == (812, "Google Chrome")
    assert calls == [50123]
