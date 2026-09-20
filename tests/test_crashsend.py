"""The one module that can send anything to Omna. Tested accordingly."""

import httpx
import pytest

from omna_plugin import crashlog, crashsend
from omna_plugin.policy import Policy

FAKE_STRIPE = "sk_live_" + "51H8xk2KJ3mN4oP5qR6sT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0u"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def captured(monkeypatch):
    """Record what would have gone over the wire; never touch the network."""
    seen = {"calls": []}

    def fake(url, json=None, timeout=None, headers=None):
        seen["calls"].append({"url": url, "json": json, "headers": headers})
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(crashsend.httpx, "post", fake)
    return seen


def _crash(msg="boom"):
    try:
        raise RuntimeError(msg)
    except RuntimeError as e:
        crashlog.record(e, where="cli")


def test_nothing_is_sent_while_the_answer_is_unset(home, captured):
    _crash()
    assert crashsend.send_pending() == 0
    assert captured["calls"] == [], "an unanswered question must never send"


def test_nothing_is_sent_after_a_no(home, captured):
    _crash()
    crashlog.remember_choice(False)
    assert crashsend.send_pending() == 0
    assert captured["calls"] == []


def test_a_yes_sends_and_marks_but_does_not_delete(home, captured):
    _crash("one")
    _crash("two")
    crashlog.remember_choice(True)
    assert crashsend.send_pending() == 2
    assert len(captured["calls"]) == 1
    assert crashlog.unsent() == []
    assert len(crashlog.tail(10)) == 2, "the local copy must survive sending"


def test_the_same_crash_is_never_sent_twice(home, captured):
    _crash()
    crashlog.remember_choice(True)
    assert crashsend.send_pending() == 1
    assert crashsend.send_pending() == 0
    assert len(captured["calls"]) == 1


def test_a_failed_send_is_retried_not_dropped(home, monkeypatch):
    _crash()
    crashlog.remember_choice(True)
    monkeypatch.setattr(crashsend.httpx, "post",
                        lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("offline")))
    assert crashsend.send_pending() == 0
    assert len(crashlog.unsent()) == 1, "an undelivered crash stays pending"

    monkeypatch.setattr(crashsend.httpx, "post",
                        lambda url, **k: httpx.Response(200, request=httpx.Request("POST", url)))
    assert crashsend.send_pending() == 1


def test_a_server_error_does_not_mark_it_sent(home, monkeypatch):
    _crash()
    crashlog.remember_choice(True)
    monkeypatch.setattr(crashsend.httpx, "post",
                        lambda url, **k: httpx.Response(500, request=httpx.Request("POST", url)))
    assert crashsend.send_pending() == 0
    assert len(crashlog.unsent()) == 1


def test_what_goes_over_the_wire_carries_no_secret_and_no_identity(home, captured):
    try:
        raise RuntimeError(f"auth failed for {FAKE_STRIPE} and jane.doe@example.com")
    except RuntimeError as e:
        crashlog.record(e, where="proxy")
    crashlog.remember_choice(True)
    crashsend.send_pending()

    import json as _json
    body = _json.dumps(captured["calls"][0]["json"])
    assert "sk_live" not in body
    assert "jane.doe@example.com" not in body
    assert str(home) not in body
    # local bookkeeping stays local
    assert '"id"' not in body and '"sent"' not in body


def test_it_goes_to_omna_dev_over_https_and_nowhere_else(home, captured):
    _crash()
    crashlog.remember_choice(True)
    crashsend.send_pending()
    url = captured["calls"][0]["url"]
    assert url == "https://omna.dev/api/public/crash"
    assert url.startswith("https://")


def test_the_question_is_asked_once_and_a_no_is_final(home):
    _crash()
    assert crashlog.should_ask() is True
    assert crashsend.ask_and_remember(crashlog.unsent(), input_fn=lambda _: "n") is False
    assert Policy.load().crash_reports == "off"
    assert crashlog.should_ask() is False

    _crash()  # a second crash must NOT re-ask
    assert crashlog.should_ask() is False


def test_a_yes_is_remembered(home):
    _crash()
    assert crashsend.ask_and_remember(crashlog.unsent(), input_fn=lambda _: "y") is True
    assert Policy.load().crash_reports == "on"
    assert crashlog.may_send() is True


def test_just_pressing_enter_means_no(home):
    _crash()
    assert crashsend.ask_and_remember(crashlog.unsent(), input_fn=lambda _: "") is False
    assert Policy.load().crash_reports == "off"


def test_ctrl_c_at_the_prompt_means_no_and_does_not_crash(home):
    _crash()
    def boom(_):
        raise KeyboardInterrupt
    assert crashsend.ask_and_remember(crashlog.unsent(), input_fn=boom) is False
