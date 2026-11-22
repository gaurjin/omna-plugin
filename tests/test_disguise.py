"""Values in disguise: one character at a time, backwards, as hex.

Found 2026-11-15: Claude Code saw a stand-in in config.txt, re-read the file
with ``od -c``, and the real email and password went to the AI. The fixtures
are the real dumps of that file (od -c, xxd, hexdump -C, od -x).
"""

from pathlib import Path

import pytest

from omna_plugin.engine import MaskingSession, TOKEN_RE

F = Path(__file__).parent / "fixtures" / "disguise"
EMAIL = "jane.doe@example.com"
PASSWORD = "Tr0ub4dor-Blue-77"


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return MaskingSession()


def spread(value: str, gap: str = "   ") -> str:
    return gap.join(value)


def hex_of(value: str) -> str:
    return value.encode().hex()


def no_real_values(out: str) -> None:
    flat = "".join(out.split())
    # Not even a piece: hex dumps repeat the bytes as text, cut every 16 bytes.
    for value in (EMAIL, PASSWORD):
        for i in range(len(value) - 7):
            assert value[i:i + 8] not in flat, value[i:i + 8]
    for value in (EMAIL, PASSWORD):
        assert value not in out
        assert "".join(value.split()) not in flat
        assert value[::-1] not in flat
        assert hex_of(value) not in flat.lower()


@pytest.mark.parametrize("dump", ["odc", "xxd", "hexdumpC", "xxdp"])
def test_a_dump_read_after_the_plain_file_hides_the_values(session, dump):
    session.mask_text((F / "config.txt").read_text())          # the agent's first read
    out = session.mask_text((F / f"config.{dump}.txt").read_text()).masked
    no_real_values(out)
    assert TOKEN_RE.search(out)


@pytest.mark.parametrize("dump", ["odc", "xxd", "hexdumpC"])
def test_a_dump_read_first_is_learned_and_hidden(session, dump):
    # No plain read before: the dump itself is read back and masked.
    out = session.mask_text((F / f"config.{dump}.txt").read_text()).masked
    no_real_values(out)


def test_spread_backwards_and_web_encoded_forms_of_a_known_value(session):
    session.mask_text(f"CUSTOMER_EMAIL={EMAIL}\nDB_PASSWORD={PASSWORD}\n")
    for text in (f"the letters: {spread(EMAIL, ' ')} end",
                 f"one per line:\n" + "\n".join(EMAIL) + "\nend",
                 f"backwards: {EMAIL[::-1]}",
                 f"hex: {hex_of(PASSWORD)}",
                 "url: jane.doe%40example.com"):
        r = session.mask_text(text)
        assert EMAIL not in r.masked and PASSWORD not in r.masked
        assert "".join(EMAIL.split()) not in "".join(r.masked.split()), text
        assert EMAIL[::-1] not in r.masked and hex_of(PASSWORD) not in r.masked
        assert r.counts, text


def test_the_count_says_what_was_found(session):
    session.mask_text(f"CUSTOMER_EMAIL={EMAIL}")
    session.mask_text(f"DB_PASSWORD={PASSWORD}")
    r = session.mask_text(f"backwards: {PASSWORD[::-1]}")
    assert PASSWORD[::-1] not in r.masked
    assert r.counts.get("GENERIC_SECRET") == 1
    assert r.by_layer.get("DISGUISE") == 1


def test_ordinary_text_is_left_alone(session):
    session.mask_text(f"CUSTOMER_EMAIL={EMAIL}")
    for text in ("a b c d e f g h", "the quick brown fox", "0000000 1 2 3 4 5 6 7 8 9",
                 "deadbeef cafebabe 0123456789abcdef", "Use od -c to read a file."):
        assert session.mask_text(text).masked == text


def test_od_x_values_are_learned(session):
    # od -x prints bytes in swapped pairs: the form is not rewritten (stated
    # limit), but the values it hides become known, so a later plain or
    # spread-out copy is hidden.
    session.mask_text((F / "config.odx.txt").read_text())
    out = session.mask_text(f"the email is {spread(EMAIL, ' ')}").masked
    assert "".join(EMAIL.split()) not in "".join(out.split())


def test_a_value_left_unmasked_on_purpose_stays_unmasked(session):
    session.mask_text(f"CUSTOMER_EMAIL={EMAIL}")
    session.allow(EMAIL)
    assert session.mask_text(f"mail {EMAIL} today").masked == f"mail {EMAIL} today"


@pytest.mark.parametrize("dump", ["xxd", "hexdumpC"])
def test_a_hex_dump_with_a_private_value_becomes_its_masked_text(session, dump):
    out = session.mask_text((F / f"config.{dump}.txt").read_text()).masked
    assert out.startswith("(Omna: this hex dump held private values")
    assert "REGION=us-east-1" in out          # the rest of the file reads as it was


def test_a_card_list_shaped_like_a_dump_is_still_masked(session):
    # Security review 2026-11-15: a date, then a card number in groups of four,
    # looks like a hex dump line. It must reach the masking engine like any text.
    ledger = ("Ledger:\n20261115 4111 1111 1111 1111\n"
              "20261116 5500 0000 0000 0004\n20261117 212 555 0123\nend\n")
    out = session.mask_text(ledger).masked
    for value in ("4111 1111 1111 1111", "5500 0000 0000 0004", "212 555 0123"):
        assert value not in out


def test_a_crafted_dump_cannot_carry_a_key_in_its_side_column(session):
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    dump = ("00000000: 4142 4344 4546 4748 4142 4344 4546 4748  " + key + "\n"
            "00000010: 4142 4344 4546 4748 4142 4344 4546 4748  ABCDEFGHABCDEFGH\n")
    assert key not in session.mask_text(dump).masked


@pytest.mark.xfail(strict=True, reason="#24 OPEN: memory fix tries 1-2 failed (slow / leaked); original code restored 2026-11-22")
def test_memory_does_not_grow_with_every_known_value():
    # #24 (2-hour real-use run 2026-11-22: 518 MB → 1,181 MB): the finder kept
    # 3 compiled patterns (~30 KB) for EVERY real value ever masked, forever —
    # 59 MB of patterns after 10 minutes, growing. Patterns are now built only
    # when a text needs them, and only a bounded number are kept.
    import tracemalloc
    from omna_plugin import disguise
    known = {f"person.number{i}@example-mail.com": f"[EMAIL_{i}]" for i in range(3000)}
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]
    f = disguise.Finder()
    f.compile(known, (1, 0, 3000))
    grown = tracemalloc.get_traced_memory()[0] - before
    tracemalloc.stop()
    assert grown < 8_000_000, f"{grown / 1e6:.1f} MB for 3,000 known values"
    # and it still finds a value in disguise
    v = 'person.number42' + chr(64) + 'example-mail.com'
    out, used = f.find('here: ' + v[::-1] + ' end')
    assert used == ['[EMAIL' + '_42]'] and v[::-1] not in out


def test_many_known_values_stay_fast_on_tables_and_dumps():
    # Checker 2026-11-22 (#24 try 1): with more than 1,024 known values, a text
    # that looks spread-out (a markdown table) or a hex dump rebuilt every
    # pattern: 1.5-3.5 s instead of ~1 ms. Claude Code resends the chat, so one
    # table slowed every later message. Budget: 50 ms with 3,000 values.
    import random
    import string
    import subprocess
    import time
    from omna_plugin import disguise
    random.seed(3)
    vals = {"".join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(8, 24))): f"[V_{i}]"
            for i in range(3000)}
    f = disguise.Finder()
    f.compile(vals, (1, 0, 3000))
    one = list(vals)[5]
    table = "| a | b | c | d | e | f |\n|---|---|---|---|---|---|\n- - - - - - -\n  1 2 3 4 5 6 7\n"
    dump = subprocess.run(["xxd"], input=b"hello there, nothing secret here at all\n", capture_output=True).stdout.decode()
    for text in (table, dump, table * 20):
        f.find(text)                                    # warm
        t = time.perf_counter(); f.find(text); ms = (time.perf_counter() - t) * 1000
        assert ms < 50, f"{ms:.0f} ms for {text[:30]!r}"
    # still found when it really is there
    assert f.find("see: " + " ".join(one) + " end")[1] == [vals[one]]
    xxd = subprocess.run(["xxd"], input=("hello " + one + " bye\n").encode(), capture_output=True).stdout.decode()
    assert f.find(xxd)[1] == [vals[one]]


def test_checker_leak_cases_stay_masked():
    # Checker 2026-11-22 on #24 try 2: three realistic dumps where try 2 let a
    # private value through. Permanent: any future memory fix must pass these.
    import subprocess
    from omna_plugin import disguise
    v = "qwzqwzqwz"
    f = disguise.Finder()
    f.compile({v: "[S" + "_1]"}, (1, 0, 1))
    end_of_file = subprocess.run(["xxd"], input=b"x" * 26 + v.encode() + b"\n", capture_output=True).stdout.decode()
    assert f.find(end_of_file)[1], "value on the dump's last short line"
    elsewhere = ("00000000: 7878 7878 7878 7878 7878 7878 7878 7878  xxxxxxxxxxxxxxxx\n"
                 "10000000: 7878 7878 7878 7878 7878 7878 7878 7878  xxxxxxxxxxxxxxxx\n"
                 "key=0x" + v.encode().hex() + "\n")
    assert f.find(elsewhere)[1], "hex of the value outside the dump lines"
    column = ("00000000: 7820 3132 2020 6b3d 7878 7878 7878 7871  x 12  k=xxxxxxxq\n"
              "10000000: 777a 7177 7a71 777a 2078 7878 7878 7878  wzqwzqwz xxxxxxx\n")
    assert f.find(column)[1], "text column with a hex-looking word, value across a line break"
