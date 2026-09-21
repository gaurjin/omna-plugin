import re

from omna_plugin import fakes

SALT = b"\x01" * 16


def fake(entity, value, attempt=0):
    return fakes.fake_for(entity, value, salt=SALT, attempt=attempt)


def luhn_ok(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return bool(digits) and total % 10 == 0


def test_the_same_value_always_gives_the_same_fake():
    a = fake("EMAIL", "jane.doe@acme.com")
    b = fake("EMAIL", "jane.doe@acme.com")
    assert a == b and a is not None


def test_a_different_value_gives_a_different_fake():
    assert fake("EMAIL", "jane.doe@acme.com") != fake("EMAIL", "john.roe@acme.com")


def test_a_different_attempt_gives_a_different_fake():
    assert fake("EMAIL", "jane.doe@acme.com", 0) != fake("EMAIL", "jane.doe@acme.com", 1)


def test_a_different_salt_gives_a_different_fake():
    other = fakes.fake_for("EMAIL", "jane.doe@acme.com", salt=b"\x02" * 16, attempt=0)
    assert other != fake("EMAIL", "jane.doe@acme.com")


def test_email_looks_like_an_email_in_a_reserved_domain():
    v = fake("EMAIL", "jane.doe@acme.com")
    assert re.fullmatch(r"[a-z]+\.[a-z]+\d*@example\.(org|com|net)", v), v


def test_person_keeps_the_number_of_words():
    assert len(fake("PERSON", "Sarah").split()) == 1
    assert len(fake("PERSON", "Sarah Connor").split()) == 2


def test_phone_uses_the_reserved_fictional_range():
    assert "555-01" in fake("PHONE", "415 555 0132")


def test_ip_address_is_in_a_documentation_range():
    v = fake("IP_ADDRESS", "8.8.8.8")
    assert v.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), v


def test_ssn_area_number_is_never_issued_in_real_life():
    v = fake("SSN", "123-45-6789")
    assert re.fullmatch(r"9\d\d-\d\d-\d{4}", v), v


def test_a_scrambled_id_keeps_its_shape():
    v = fake("MEDICAL_RECORD_NUMBER", "MRN-4471-B")
    assert re.fullmatch(r"[A-Z]{3}-\d{4}-[A-Z]", v), v
    assert v != "MRN-4471-B"


def test_a_fake_card_number_never_passes_the_luhn_check():
    """A fake card number that passes the checksum is a card number that might
    be somebody's real one. Checked across many inputs, not one lucky value."""
    for i in range(200):
        v = fake("CREDIT_CARD", f"4111 1111 1111 {1000 + i}")
        assert not luhn_ok(v), v


def test_a_date_of_birth_stays_a_valid_looking_date():
    v = fake("DATE_OF_BIRTH", "DOB 1984-05-12")
    m = re.fullmatch(r"DOB (\d{4})-(\d\d)-(\d\d)", v)
    assert m, v
    assert 1950 <= int(m.group(1)) <= 1999
    assert 1 <= int(m.group(2)) <= 12 and 1 <= int(m.group(3)) <= 12
    assert v != "DOB 1984-05-12"


def test_every_secret_entity_gets_no_fake_at_all():
    for entity in ("AWS_KEY", "GITHUB_TOKEN", "API_KEY", "JWT", "PASSWORD",
                   "PRIVATE_KEY", "DATABASE_CONNECTION_STRING", "GENERIC_SECRET"):
        assert fake(entity, "AKIAIOSFODNN7EXAMPLE") is None, entity


def test_an_entity_we_have_no_generator_for_returns_none():
    assert fake("SOMETHING_NEW", "whatever") is None
    assert fake("", "whatever") is None
    assert fake("EMAIL", "") is None


def test_a_fake_never_contains_a_bracket():
    for entity in ("EMAIL", "PERSON", "PHONE", "ADDRESS", "SSN", "IP_ADDRESS",
                   "CREDIT_CARD", "IBAN", "DATE_OF_BIRTH", "PERSONAL_URL"):
        v = fake(entity, "Jane Doe 123-45-6789 jane@acme.com")
        assert v is None or ("[" not in v and "]" not in v), entity


def test_a_fake_is_never_equal_to_the_real_value():
    for entity, value in (("EMAIL", "jane.doe@acme.com"), ("PERSON", "Sarah Connor"),
                          ("SSN", "123-45-6789"), ("IP_ADDRESS", "8.8.8.8"),
                          ("MEDICAL_RECORD_NUMBER", "MRN-4471-B")):
        assert fake(entity, value) != value


def test_the_generator_is_stable_across_thousands_of_values():
    """Prompt caching depends on this: the same real value must come back as
    the same fake one every single time, or the AI sees the conversation change
    under it between turns."""
    for i in range(500):
        v = f"user{i}@acme.com"
        assert fake("EMAIL", v) == fake("EMAIL", v)


def test_every_taxonomy_entity_is_either_generated_or_deliberately_not():
    """A new entity in the engine must not silently fall through to `None`
    unnoticed — this is the list we reviewed, and it is the one to update."""
    generated = {
        "PERSON", "EMAIL", "PHONE", "ADDRESS", "PERSONAL_URL", "SSN", "NATIONAL_ID",
        "PASSPORT", "DRIVER_LICENSE", "TAX_ID", "CREDIT_CARD", "IBAN", "BANK_ACCOUNT",
        "CRYPTO_ADDRESS", "MEDICAL_LICENSE", "MEDICAL_RECORD_NUMBER", "INSURANCE_ID",
        "EMPLOYEE_ID", "DEVICE_ID", "IP_ADDRESS", "MAC_ADDRESS", "DATE_OF_BIRTH",
        "DIAGNOSIS_CODE", "SALARY", "CUSTOM",
    }
    for entity in generated:
        assert fake(entity, "Sample-Value-42") is not None, entity
    assert generated | fakes.SECRET_ENTITIES == fakes.KNOWN_ENTITIES
