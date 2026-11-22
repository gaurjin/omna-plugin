"""The local dashboard (`omna dashboard`)."""
from omna_plugin import dashboard



def test_what_was_caught_counts_each_private_detail_once():
    # #19 (client test 2026-11-21: "it's literally 99.99% wrong"): a chat
    # resends its history every turn, and the dashboard added every mention
    # (PERSON ×87,098 on the owner's Mac). Same rule as the status screen and
    # the daily count (#14-15): each detail once, by its private fingerprint.
    from omna_plugin import receipts
    f = lambda fps: [{"entity": "EMAIL", "layer": "L1", "n": len(fps), "fp": fps}]   # noqa: E731
    for _ in range(3):
        receipts.append({"masked": {"EMAIL": 2}, "finds": f(["a1", "b2"]), "app": "claude"})
    d = dashboard.snapshot(days=7)
    assert d["by_kind_once"] == {"EMAIL": 2}
    html = dashboard.render(d)
    assert "each detail counted once" in html
