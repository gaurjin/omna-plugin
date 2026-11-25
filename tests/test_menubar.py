from PIL import Image

from omna_plugin import menubar
_real_stop_other_menu_bars = menubar.stop_other_menu_bars  # captured before conftest's guard patches it
from omna_plugin.mac import app_bundle, launchd

SELF = __import__('omna_plugin.config', fromlist=['x']).self_command()   # how the menu bar runs omna (#34)


def test_status_lines_not_running(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    assert menubar.status_lines(None) == ["Omna: OFF — NOT masking · click to resume",
                                          "Browsers and desktop apps go to the AI UNMASKED",
                                          "omna start -d (or click above)"]


# #44 (client test 2026-11-22): the menu bar said 0 / 0 / 0 while hundreds of
# messages went through the Mac-wide door, and "every app" while Wi-Fi was not
# routed through Omna. It now shows the same Today line as `omna status`.

def test_status_lines_show_todays_messages_and_details_like_omna_status():
    h = {"doors": {"api": True, "system": True}, "requests_this_run": 0}
    lines = menubar.status_lines(h, today=(312, 41), route=("Wi-Fi", True))
    assert lines[0] == "Omna: ON · click to pause"
    assert lines[1] == "Today: 312 messages to AI · 41 private details hidden"
    assert lines[2] == "Mac apps: protected (Claude, ChatGPT and other AI apps)"
    assert not any("tokenized" in l or "off the wire" in l or "this session" in l or "overhead" in l for l in lines)


def test_status_lines_one_message_reads_as_one():
    lines = menubar.status_lines({"doors": {"system": True}}, today=(1, 1), route=("Wi-Fi", True))
    assert lines[1] == "Today: 1 message to AI · 1 private detail hidden"


def test_status_lines_never_say_protected_when_wifi_is_not_routed():
    lines = menubar.status_lines({"doors": {"system": True}}, today=(0, 0), route=("Wi-Fi", False))
    assert lines[2] == "Mac apps: NOT protected on Wi-Fi — run omna init"
    assert not any("every app" in l for l in lines)


def test_status_lines_mac_wide_door_off():
    lines = menubar.status_lines({"doors": {"api": True, "system": False}}, today=(0, 0), route=("Wi-Fi", True))
    assert lines[2] == "Mac apps: turned off — desktop AI apps go unmasked"


def test_status_lines_missing_doors_key_does_not_crash():
    assert menubar.status_lines({"requests_this_run": 1}) == [
        "Omna: ON · click to pause",
        "Today: 0 messages to AI · 0 private details hidden",
        "Mac apps: turned off — desktop AI apps go unmasked",
    ]


def test_today_counts_come_from_the_receipts_of_both_doors(tmp_path, monkeypatch):
    import json
    from datetime import date

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    from omna_plugin import config
    today = date.today().isoformat()
    recs = [
        {"ts": f"{today}T10:00:00+0000", "door": "system", "finds": []},
        {"ts": f"{today}T10:01:00+0000", "door": "api", "finds": []},
        {"ts": f"{today}T10:02:00+0000", "door": "control", "finds": []},
        {"ts": "2000-01-01T10:00:00+0000", "door": "system", "finds": []},
    ]
    path = config.receipts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))
    msgs, _details = menubar.today_counts()
    assert msgs == 2


def test_menu_words_are_plain():
    assert menubar.REPORTS_LABEL == "Keep receipts on this Mac"
    assert menubar.STYLE_LABEL == "Realistic stand-ins in browsers"
    assert menubar.QUIT_LABEL == "Hide this icon (Omna keeps masking)"
    assert menubar.RESTORE_LABEL == "Restore on reply (shield mode)"


def test_icon_image_size_and_mode():
    img = menubar._icon_image(True)
    assert img.size == Image.open(menubar.LOGO_PATH).size
    assert img.mode == "RGBA"


def test_icon_image_on_state_is_the_unmodified_logo():
    base = Image.open(menubar.LOGO_PATH).convert("RGBA")
    on = menubar._icon_image(True)
    assert on.tobytes() == base.tobytes()


def _pixels(img):
    return [img.getpixel((x, y)) for x in range(img.width) for y in range(img.height)]


def _dot_centre(w):
    cx, cy, _ = (part * w for part in menubar.OFF_DOT_AT)
    return int(cx), int(cy)


def test_icon_image_off_state_adds_a_red_dot_and_greys_the_logo():
    w = Image.open(menubar.LOGO_PATH).width
    on = menubar._icon_image(True)
    off = menubar._icon_image(False)
    assert off.getpixel(_dot_centre(w)) == menubar.OFF_DOT_COLOR
    assert on.getpixel(_dot_centre(w)) != menubar.OFF_DOT_COLOR
    # The same O, in grey: readable on a light AND a dark menu bar (#45).
    logo = [p for p in _pixels(off) if p[3] == 255 and p != menubar.OFF_DOT_COLOR]
    assert logo and all(p[:3] == menubar.OFF_LOGO_COLOR[:3] for p in logo)


def test_off_state_keeps_the_ring_of_the_o_whole():
    # #45 (owner 2026-11-22): the red dot sits beside the O; no piece of the
    # ring is cut away or painted over.
    on = menubar._icon_image(True)
    off = menubar._icon_image(False)
    ring = [(x, y) for x in range(on.width) for y in range(on.height) if on.getpixel((x, y))[3] > 0]
    assert all(off.getpixel(p)[3] >= on.getpixel(p)[3] for p in ring), "part of the ring was cut away"
    covered = [p for p in ring if off.getpixel(p) == menubar.OFF_DOT_COLOR]
    assert len(covered) <= len(ring) * 0.02, f"the dot covers {len(covered)} of {len(ring)} ring pixels"


def test_logo_has_no_white_box_behind_it():
    # #45 (owner 2026-11-22): the logo sat on a white box in the menu bar.
    # Only the O itself may be drawn: the middle of the O and every edge are clear.
    img = Image.open(menubar.LOGO_PATH).convert("RGBA")
    w, h = img.size
    edges = [img.getpixel((x, y)) for x in range(w) for y in (0, h - 1)]
    edges += [img.getpixel((x, y)) for y in range(h) for x in (0, w - 1)]
    assert all(p[3] == 0 for p in edges), "the picture has a background"
    assert img.getpixel((w // 2, h // 2))[3] == 0, "the middle of the O is filled in"
    drawn = sum(1 for p in _pixels(img) if p[3] > 0)
    assert drawn < w * h * 0.4, f"{drawn} of {w * h} pixels drawn: a box, not a logo"


def _near_gradient(rgb, stops=((0x2F, 0x5B, 0xFF), (0x4A, 0x45, 0xFF), (0x86, 0x36, 0xEF))):
    """How far a colour is from the website's blue-to-purple gradient line."""
    best = 999.0
    for a, b in zip(stops, stops[1:]):
        ab = [b[i] - a[i] for i in range(3)]
        t = sum((rgb[i] - a[i]) * ab[i] for i in range(3)) / sum(v * v for v in ab)
        t = min(1.0, max(0.0, t))
        best = min(best, sum((rgb[i] - a[i] - t * ab[i]) ** 2 for i in range(3)) ** 0.5)
    return best


def test_logo_is_the_website_o_in_its_own_colours():
    # #45 (owner 2026-11-22): "the same O" as omna.dev — its gradient
    # #2F5BFF -> #4A45FF -> #8636EF, blue at the top, purple lower down.
    img = Image.open(menubar.LOGO_PATH).convert("RGBA")
    solid = [(x, y) for x in range(img.width) for y in range(img.height) if img.getpixel((x, y))[3] == 255]
    assert solid
    assert all(_near_gradient(img.getpixel(p)) < 6 for p in solid)
    top = min(solid, key=lambda p: p[1])
    bottom = max(solid, key=lambda p: p[1])
    assert img.getpixel(top)[0] < img.getpixel(bottom)[0], "blue should be at the top, purple at the bottom"


class _FakeIcon:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True


def test_confirm_and_uninstall_non_darwin_never_shells_out(monkeypatch, capsys):
    monkeypatch.setattr(menubar.sys, "platform", "linux")
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda *a, **k: calls.append(a))
    icon, state = _FakeIcon(), {"paused": False}
    menubar._confirm_and_uninstall(icon, state)
    assert calls == []
    assert "omna uninstall" in capsys.readouterr().out
    assert not icon.stopped


def test_confirm_and_uninstall_darwin_cancel_runs_only_the_dialog(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "darwin")
    calls = []

    class R:
        stdout = b"button returned:Cancel"

    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd) or R())
    icon, state = _FakeIcon(), {"paused": False}
    menubar._confirm_and_uninstall(icon, state)
    assert len(calls) == 1
    assert not icon.stopped
    assert state["paused"] is False


def test_confirm_and_uninstall_darwin_confirm_opens_terminal_then_stops_itself(monkeypatch):
    # Regression: this process's own crash-recovery poll loop must not be left
    # running to respawn the daemon `omna uninstall` (in the Terminal window it
    # just opened) is in the middle of wiping — belt (paused) and suspenders
    # (icon.stop(), which ends this whole process).
    monkeypatch.setattr(menubar.sys, "platform", "darwin")
    calls = []

    class R:
        stdout = b"button returned:Uninstall"

    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd) or R())
    icon, state = _FakeIcon(), {"paused": False}
    menubar._confirm_and_uninstall(icon, state)
    assert len(calls) == 2
    assert "omna uninstall" in calls[1][2]
    assert state["paused"] is True
    assert icon.stopped


def test_toggle_masking_running_pauses_via_cli_stop_and_sets_paused_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    state = {"paused": False}
    menubar._toggle_masking({"doors": {}}, state)
    assert calls == [SELF + ["stop"]]
    assert state["paused"] is True


def test_toggle_masking_not_running_resumes_via_cli_start_and_clears_paused_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    state = {"paused": True}
    menubar._toggle_masking(None, state)
    assert calls == [SELF + ["start", "-d"]]
    assert state["paused"] is False


def test_ensure_daemon_calls_omna_ensure_when_not_paused(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    menubar._ensure_daemon({"paused": False})
    assert calls == [SELF + ["ensure"]]


def test_ensure_daemon_does_nothing_when_paused(monkeypatch):
    from omna_plugin import pause
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    pause.begin("menubar")                  # #43: the note on disk is what "paused" means
    menubar._ensure_daemon({"paused": True})
    assert calls == []


def test_toggle_login_item_enables_when_currently_disabled(monkeypatch):
    calls = []
    monkeypatch.setattr(app_bundle, "login_item_enabled", lambda: False)
    monkeypatch.setattr(app_bundle, "enable_login_item", lambda: calls.append("enable"))
    monkeypatch.setattr(app_bundle, "disable_login_item", lambda: calls.append("disable"))
    menubar._toggle_login_item()
    assert calls == ["enable"]


def test_toggle_login_item_disables_when_currently_enabled(monkeypatch):
    calls = []
    monkeypatch.setattr(app_bundle, "login_item_enabled", lambda: True)
    monkeypatch.setattr(app_bundle, "enable_login_item", lambda: calls.append("enable"))
    monkeypatch.setattr(app_bundle, "disable_login_item", lambda: calls.append("disable"))
    menubar._toggle_login_item()
    assert calls == ["disable"]


def test_toggle_reports_flips_the_policy_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    assert menubar._reports_enabled() is True  # default
    menubar._toggle_reports()
    assert menubar._reports_enabled() is False
    menubar._toggle_reports()
    assert menubar._reports_enabled() is True


def test_quit_darwin_unloads_its_own_launchd_job_before_stopping(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "darwin")
    calls = []
    monkeypatch.setattr(launchd, "bootout", lambda label: calls.append(("bootout", label)))

    class Icon:
        def stop(self_inner):
            calls.append("stop")

    menubar._quit(Icon())
    assert calls == [("bootout", launchd.MENUBAR_LABEL), "stop"]


def test_quit_non_darwin_just_stops_the_icon(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "linux")
    calls = []

    class Icon:
        def stop(self_inner):
            calls.append("stop")

    menubar._quit(Icon())
    assert calls == ["stop"]


def test_toggle_realistic_style_flips_the_policy_style(tmp_path, monkeypatch):
    """#143(a): switching the style used to need a terminal."""
    from omna_plugin.policy import Policy
    from omna_plugin.style import REALISTIC, TOKENS

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    assert Policy.load().style == TOKENS
    assert menubar._realistic_style() is False
    menubar._toggle_realistic_style()
    assert Policy.load().style == REALISTIC
    assert menubar._realistic_style() is True
    menubar._toggle_realistic_style()
    assert Policy.load().style == TOKENS
    assert menubar._realistic_style() is False


def test_the_icon_survives_its_file_vanishing_during_an_upgrade(monkeypatch, tmp_path):
    """#18 (client test 2026-11-21): reinstalling the curl command replaced its
    files while the menu-bar icon ran; the next redraw could not open the logo,
    the drawing thread died, and the icon vanished with no message."""
    from omna_plugin import menubar
    monkeypatch.setattr(menubar, "LOGO_PATH", tmp_path / "gone.png")
    img = menubar._icon_image(True)
    assert img.size[0] > 0


def test_menu_bar_runs_omna_by_full_path_not_by_name(monkeypatch):
    # #34 (2026-11-21): the menu bar is started by macOS at login, where PATH
    # does not include ~/.local/bin. ["omna", "ensure"] failed every 4 s with
    # "No such file or directory: 'omna'": the curl command was never brought
    # back after it went down, and the whole Mac lost its AI traffic.
    import os
    calls = []
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    monkeypatch.setattr(menubar.pause, "end", lambda *a, **k: None)
    monkeypatch.setattr(menubar.pause, "begin", lambda *a, **k: None, raising=False)
    menubar._ensure_daemon({"paused": False})
    menubar._resume({"paused": True}, "click")
    menubar._toggle_masking(None, {"paused": False})
    assert len(calls) == 3
    for cmd in calls:
        assert os.path.isabs(cmd[0]) and os.path.exists(cmd[0]), f"menu bar runs {cmd!r}: not a full path"


# ---------------------------------------------------------------- #35: no menu-bar icon after an upgrade
# Owner, 2026-11-21: no Omna icon in the menu bar, and clicking
# /Applications/Omna Plugin.app did nothing. The running menu bar came from a
# tool folder an upgrade had deleted; its poll thread died on its first error
# (FileNotFoundError 'omna'), so crash recovery stopped for good; and because
# it was still running, macOS only "activated" it on a click.

class _PollIcon:
    def __init__(self):
        self.icon = None
        self.title = ""

    def update_menu(self):
        pass


def test_one_error_never_ends_the_menu_bar_crash_recovery(monkeypatch):
    calls = []

    def flaky_ensure(state):
        calls.append(1)
        if len(calls) == 1:
            raise FileNotFoundError("omna")

    monkeypatch.setattr(menubar, "_health", lambda port: None)
    monkeypatch.setattr(menubar, "_ensure_daemon", flaky_ensure)
    naps = []

    def sleep(s):
        naps.append(s)
        if len(naps) == 3:
            raise SystemExit                 # end the test after three rounds

    try:
        menubar._poll_forever(_PollIcon(), {"paused": False}, 7788, sleep=sleep)
    except SystemExit:
        pass
    assert len(calls) == 3, f"crash recovery stopped after the first error ({len(calls)} round(s) ran)"


def test_a_new_menu_bar_replaces_an_old_one_still_running(monkeypatch):
    import os
    import signal
    me = os.getpid()
    listing = f"{me} /x/python -m omna_plugin.cli menubar\n1012 /old/python3.12 /old/bin/omna menubar\n77 /x/python -m omna_plugin.cli start --port 7788\n"
    comm = f"{me} /x/python\n1012 /old/python3.12\n77 /x/python\n"
    monkeypatch.setattr(menubar.subprocess, "run",
                        lambda cmd, **k: type("R", (), {"stdout": comm if "comm=" in cmd[-1] else listing, "returncode": 0})())
    sent = []
    monkeypatch.setattr(menubar.os, "kill", lambda pid, sig: sent.append((pid, sig)))
    _real_stop_other_menu_bars()
    assert (1012, signal.SIGTERM) in sent, "the old menu bar was left running"
    assert all(pid != me for pid, _ in sent), "it stopped itself"
    assert all(pid != 77 for pid, _ in sent), "it stopped the curl command (plugin/proxy) service — must never happen"



def test_closing_old_menu_bars_never_touches_unrelated_programs(monkeypatch):
    # Checker 2026-11-21: the pattern also matched editors and searches.
    import signal
    listing = "\n".join([
        "11 /Users/x/.local/share/uv/tools/omna-plugin/bin/python /Users/x/.local/share/uv/tools/omna-plugin/bin/omna menubar",
        "12 /Users/x/Omna Labs/omna-plugin/.venv/bin/python -m omna_plugin.cli menubar --port 7788",
        "21 vim /tmp/omna menubar notes",
        "22 grep /omna menubar",
        "23 rg omna_plugin.cli menubar src/",
        "24 python3 -c import omna_plugin.cli menubar",
        "25 /x/python -m omna_plugin.cli start --port 7788",
        "26 tail -f /Users/x/.omna/menubar.log",
        "27 less /bin/omna menubar",
        "28 sh -c echo python -m omna_plugin.cli menubar",
        "29 /usr/bin/vim /tmp/bin/omna menubar",
    ]) + "\n"
    # What program each process really is (ps comm): checker 2, 2026-11-21.
    programs = {"11": "/Users/x/.local/share/uv/tools/omna-plugin/bin/python", "12": "/Users/x/Omna Labs/omna-plugin/.venv/bin/python",
                "21": "vim", "22": "grep", "23": "rg", "24": "/usr/bin/python3", "25": "/x/python", "26": "tail",
                "27": "/usr/bin/less", "28": "/bin/sh", "29": "/usr/bin/vim"}
    comm = "".join(f"{k} {v}\n" for k, v in programs.items())
    monkeypatch.setattr(menubar.subprocess, "run",
                        lambda cmd, **k: type("R", (), {"stdout": comm if "comm=" in cmd[-1] else listing, "returncode": 0})())
    sent = []
    monkeypatch.setattr(menubar.os, "kill", lambda pid, sig: sent.append(pid))
    _real_stop_other_menu_bars()
    assert sorted(sent) == [11, 12], sent


def test_the_check_round_changes_the_icon_only_on_the_main_thread(monkeypatch):
    # #35 (2026-11-21, macOS 27): the background check set the icon's picture,
    # tooltip and menu from its own thread; macOS traps that (crash report:
    # -[NSStatusItem setMenu:] -> assertBarrierOnQueue) or leaves no icon.
    class Icon:
        def __init__(self):
            self.changes = []

        def __setattr__(self, k, v):
            if k != "changes":
                self.changes.append(k)
            object.__setattr__(self, k, v)

        def update_menu(self):
            self.changes.append("menu")

    handed = []
    monkeypatch.setattr(menubar, "_on_main", handed.append, raising=False)
    monkeypatch.setattr(menubar, "_health", lambda port: {"ok": True})
    icon = Icon()
    menubar._poll_once(icon, {"paused": False}, 7788)
    assert icon.changes == [], f"changed off the main thread: {icon.changes}"
    assert len(handed) == 1
    handed[0]()
    assert "menu" in icon.changes and "icon" in icon.changes


def test_start_up_shows_the_icon_only_on_the_main_thread(monkeypatch):
    # #35: pystray runs ``setup`` on its own thread; showing the icon from there
    # raced macOS 27 (icon there in some starts, missing in others; always
    # missing when the app was opened from Finder).
    class Icon:
        visible = False

    handed = []
    started = []
    monkeypatch.setattr(menubar, "_on_main", handed.append, raising=False)
    monkeypatch.setattr(menubar.threading, "Thread", lambda **kw: type("T", (), {"start": lambda self: started.append(kw)})())
    icon = Icon()
    menubar._setup(icon, {"paused": False}, 7788)
    assert icon.visible is False, "shown off the main thread"
    assert len(handed) == 1 and len(started) == 1
    handed[0]()
    assert icon.visible is True


def test_the_app_menu_bar_counts_as_a_menu_bar(monkeypatch):
    # #35: the app's main program is now its own Python, "omna-menubar".
    import os
    import signal
    me = os.getpid()
    app = "/Applications/Omna Plugin.app/Contents/MacOS/omna-menubar"
    listing = f"{me} /x/python -m omna_plugin.cli menubar\n2001 {app}\n2002 {app} -m omna_plugin.cli ensure\n77 /x/python -m omna_plugin.cli start --port 7788\n"
    comm = f"{me} /x/python\n2001 {app}\n2002 {app}\n77 /x/python\n"
    monkeypatch.setattr(menubar.subprocess, "run",
                        lambda cmd, **k: type("R", (), {"stdout": comm if "comm=" in cmd[-1] else listing, "returncode": 0})())
    sent = []
    monkeypatch.setattr(menubar.os, "kill", lambda pid, sig: sent.append((pid, sig)))
    _real_stop_other_menu_bars()
    assert (2001, signal.SIGTERM) in sent, "the app's menu bar was left running"
    assert all(pid not in (2002, 77, me) for pid, _ in sent), sent


def _ran(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd[-1] if cmd[-1] != "-d" else "start -d"))
    monkeypatch.setattr(menubar, "_health", lambda port: None)
    monkeypatch.setattr(menubar, "_on_main", lambda fn: None)
    return calls


def test_a_terminal_stop_is_not_undone_by_the_menu_bar(monkeypatch):
    # #43 (2026-11-22): `omna stop` writes "off on purpose" to disk, but the menu
    # bar's crash recovery only looked at its own memory and ran `omna ensure`
    # every 4 seconds — starting Omna again behind the person's back.
    from omna_plugin import pause
    calls = _ran(monkeypatch)
    pause.begin("stop")
    menubar._poll_once(object(), {"paused": False}, 7788)
    assert "ensure" not in calls, calls


def test_a_pause_ended_elsewhere_brings_crash_recovery_back(monkeypatch):
    # #43: `omna start -d` ended a menu-bar Pause; the menu bar still thought
    # it was paused and never restarted a crashed service again.
    calls = _ran(monkeypatch)
    state = {"paused": True}
    menubar._poll_once(object(), state, 7788)       # no pause on disk any more
    assert state["paused"] is False and "ensure" in calls, (state, calls)


def test_an_expired_pause_ends_even_if_the_menu_bar_restarted(monkeypatch):
    import time
    from omna_plugin import pause
    calls = _ran(monkeypatch)
    pause.begin("menubar", now=time.time() - 3600)
    menubar._poll_once(object(), {"paused": False}, 7788)   # a new menu bar, empty memory
    assert "start -d" in calls and pause.state() is None, calls


def test_a_leftover_off_note_while_omna_runs_does_not_switch_recovery_off_for_good(monkeypatch):
    # #43 checker 2026-11-22: a stop note left behind while the service runs
    # kept crash recovery off forever. Older than 30 s while Omna answers: gone.
    import time
    from omna_plugin import pause
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd[-1]))
    monkeypatch.setattr(menubar, "_on_main", lambda fn: None)
    monkeypatch.setattr(menubar, "_health", lambda port: {"ok": True})
    pause.begin("stop", now=time.time() - 120)
    menubar._poll_once(object(), {"paused": True}, 7788)
    assert pause.state() is None
    pause.begin("stop")                                   # a fresh one (the menu bar's own Pause sequence)
    menubar._poll_once(object(), {"paused": True}, 7788)
    assert pause.state() is not None


def test_today_counts_only_real_messages(tmp_path, monkeypatch):
    """#53 (owner 2026-11-23: "increasing every second when I have not given
    any input"): Remote Control pings, claude.ai branch checks, token counts
    and empty requests are not messages to AI."""
    import json
    from datetime import date

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    from omna_plugin import config, cli
    t = f"{date.today().isoformat()}T10:00:00+0000"
    rec = lambda host, route, note=None, n=200: {"ts": t, "door": "system", "host": host, "route": route,  # noqa: E731
                                                 "note": note, "bytes_in": n, "finds": []}
    recs = [
        rec("api.anthropic.com", "/v1/messages"),                                    # counted
        rec("chatgpt.com", "/backend-api/f/conversation"),                           # counted
        rec("api.anthropic.com", "/v1/messages", "file-not-masked:image"),           # counted
        rec("api.anthropic.com", "/v1/code/sessions/cse_1/worker/heartbeat", "passthrough-remote-control"),
        rec("api.anthropic.com", "/v1/code/sessions/cse_1/worker/events"),           # old receipt, before #52
        rec("claude.ai", "/v1/code/sessions/cse_1/client/presence"),
        rec("claude.ai", "/v1/code/github/get-batch-branch-status"),
        rec("api.anthropic.com", "/v1/messages/count_tokens"),
        rec("muse.ai", "/api/hatch/vm/wake"),
        rec("claude.ai", "/v1/code/sessions/cse_1", "passthrough-nonprompt", 0),
        rec("muse.ai", "/api/falco", "passthrough-site-report"),
        rec("api.anthropic.com", "CONNECT", "bypassed-tool-off:claude-code", 0),
        rec("claude.ai", "TLS", "tls-refused", 0),
        dict(rec("chat.example-ai.com", "websocket", None, 0), status=101),        # counted: both doors write 0 bytes
        dict(rec("localhost", "/v1/realtime", "websocket", 0), status=101),        # counted (API door)
    ]
    path = config.receipts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))
    msgs, refused, _details = cli.today_counts()
    assert (msgs, refused) == (5, 1)


def test_today_counts_one_message_per_send_with_omna_for_chrome_and_the_mac_wide_door(tmp_path, monkeypatch):
    """Bug list row 5 (2026-11-25, check row5.py: 1 message counted as 2).
    Omna for Chrome writes a record per Hide click (door "chrome") and labels
    every send; the send's system-door receipt is the message. Chrome's records
    add private details only (each once), never messages."""
    import json
    from datetime import date

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    from omna_plugin import config, cli
    t = f"{date.today().isoformat()}T10:00:00+0000"
    find = lambda fp: {"entity": "AWS_KEY", "layer": "L1", "risk": "secret", "action": "redacted", "n": 1, "fp": [fp]}  # noqa: E731
    chrome = lambda fp: {"ts": t, "product": "chrome", "door": "chrome", "kind": "typed", "route": "typed",  # noqa: E731
                         "host": "chatgpt.com", "finds": [find(fp)]}
    send = lambda finds=(): {"ts": t, "door": "system", "host": "chatgpt.com", "route": "/backend-api/f/conversation",  # noqa: E731
                             "bytes_in": 120, "finds": list(finds)}
    path = config.receipts_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    def counts(recs):
        path.write_text("".join(json.dumps(r) + "\n" for r in recs))
        msgs, _refused, details = cli.today_counts()
        return msgs, details

    assert counts([chrome("f6eb6eef67ee8435"), send()]) == (1, 1)                        # 1 hide, 1 send
    assert counts([send()]) == (1, 0)                                                   # nothing hidden
    assert counts([chrome("f6eb6eef67ee8435"), chrome("1fa40ec3ebc4a7c4"), send()]) == (1, 2)   # 2 hides, 1 send
    assert counts([send([find("0123456789abcdef")])]) == (1, 1)                         # no extension
