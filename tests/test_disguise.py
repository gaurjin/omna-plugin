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


def test_a_hex_dump_with_nothing_private_is_left_exactly_as_it_is(session):
    import binascii
    data = b"hello world, this is a plain file with nothing private in it at all.\n"
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hx = " ".join(binascii.hexlify(chunk[i:i + 2]).decode() for i in range(0, len(chunk), 2))
        lines.append(f"{off:08x}: {hx:<39}  " + "".join(chr(b) if 32 <= b < 127 else "." for b in chunk))
    dump = "\n".join(lines) + "\n"
    assert session.mask_text(dump).masked == dump


def test_a_crafted_dump_cannot_carry_a_key_in_its_side_column(session):
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    dump = ("00000000: 4142 4344 4546 4748 4142 4344 4546 4748  " + key + "\n"
            "00000010: 4142 4344 4546 4748 4142 4344 4546 4748  ABCDEFGHABCDEFGH\n")
    assert key not in session.mask_text(dump).masked
