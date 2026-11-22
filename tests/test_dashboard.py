"""The local dashboard (`omna dashboard`)."""
import pytest

from omna_plugin import dashboard


@pytest.fixture(autouse=True)
def _fresh_snapshot():
    # The dashboard keeps a snapshot for 2 s on purpose; each test starts clean.
    dashboard._cache.update(at=0.0, days=None, data=None)



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


def test_mixed_receipt_counts_the_same_on_dashboard_and_status():
    # Checker 2026-11-22 (#19): EMAIL with a fingerprint + PHONE ×3 without one
    # in the same receipt: the dashboard dropped the PHONE, status counted it.
    from omna_plugin import cli, receipts
    receipts.append({"masked": {"EMAIL": 1, "PHONE": 3}, "app": "claude",
                     "finds": [{"entity": "EMAIL", "layer": "L1", "n": 1, "fp": ["e1"]},
                               {"entity": "PHONE", "layer": "L1", "n": 3, "fp": []}]})
    receipts.append({"masked": {"EMAIL": 1}, "app": "claude",
                     "finds": [{"entity": "EMAIL", "layer": "L1", "n": 1, "fp": "e1"}]})   # a fingerprint stored as text
    d = dashboard.snapshot(days=7)
    assert d["by_kind_once"] == {"EMAIL": 1, "PHONE": 3}, d["by_kind_once"]
    assert cli._private_details_today(receipts.tail(0)) == 4


def test_how_certain_panel_counts_details_not_mentions():
    from omna_plugin import receipts
    for _ in range(5):
        receipts.append({"masked": {"PERSON": 1}, "by_layer": {"L3": 1}, "app": "claude",
                         "finds": [{"entity": "PERSON", "layer": "L3", "n": 1, "fp": ["p1"]}]})
    d = dashboard.snapshot(days=7)
    assert d["by_layer_once"] == {"L3": 1}, d.get("by_layer_once")
