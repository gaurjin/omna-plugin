"""Verifying the provider on the way OUT.

Omna opens your request, so this leg is our responsibility: something that
could impersonate api.anthropic.com to Omna would receive a masked prompt AND
your real API key.
"""

import ssl

import pytest

from omna_plugin import upstream_tls
from omna_plugin.policy import Policy


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def _self_signed(cn: str = "example.test"):
    """A throwaway certificate, made here so no network or fixture file is needed."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER), key


# --------------------------------------------------------------- the pin itself
def test_a_pin_is_stable_and_specific_to_the_key():
    der_a, _ = _self_signed("a.test")
    der_b, _ = _self_signed("b.test")
    pin_a = upstream_tls.spki_sha256(der_a)
    assert pin_a == upstream_tls.spki_sha256(der_a), "the same cert must give the same pin"
    assert pin_a != upstream_tls.spki_sha256(der_b)
    # base64 of a SHA-256 digest
    import base64
    assert len(base64.b64decode(pin_a)) == 32


def test_the_pin_follows_the_KEY_not_the_certificate():
    """THE reason pinning gets a bad name is pinning the certificate, which
    breaks on every routine renewal. We pin the public key, so a renewal that
    reuses the key keeps working."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    der1, key = _self_signed("renew.test")
    # same key, brand new certificate — i.e. a routine renewal
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "renew.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert2 = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    der2 = cert2.public_bytes(serialization.Encoding.DER)
    assert der1 != der2, "the certificates differ"
    assert upstream_tls.spki_sha256(der1) == upstream_tls.spki_sha256(der2), \
        "a renewal reusing the key must NOT break the pin"


# ------------------------------------------------------------------- enforcement
def test_no_pins_configured_means_no_opinion():
    der, _ = _self_signed()
    upstream_tls.verify_chain_against_pins([der], [])  # must not raise


def test_a_matching_pin_passes():
    der, _ = _self_signed()
    upstream_tls.verify_chain_against_pins([der], [upstream_tls.spki_sha256(der)])


def test_a_wrong_certificate_is_refused_and_says_why():
    real, _ = _self_signed("real.test")
    impostor, _ = _self_signed("impostor.test")
    with pytest.raises(upstream_tls.PinnedVerificationError) as e:
        upstream_tls.verify_chain_against_pins([impostor], [upstream_tls.spki_sha256(real)])
    msg = str(e.value)
    assert "was NOT sent" in msg
    assert "omna tls pin" in msg, "the error must say how to fix it"


def test_matching_any_certificate_in_the_chain_is_enough():
    """Pinning an intermediate is the sane choice, so a match anywhere in the
    chain counts — not just the leaf."""
    leaf, _ = _self_signed("leaf.test")
    intermediate, _ = _self_signed("intermediate.test")
    upstream_tls.verify_chain_against_pins(
        [leaf, intermediate], [upstream_tls.spki_sha256(intermediate)]
    )


def test_an_unparseable_certificate_does_not_silently_pass():
    real, _ = _self_signed()
    with pytest.raises(upstream_tls.PinnedVerificationError):
        upstream_tls.verify_chain_against_pins([b"not a certificate"],
                                               [upstream_tls.spki_sha256(real)])


# ---------------------------------------------------------------- the ssl context
def test_default_changes_nothing_for_anyone_who_did_not_opt_in(home):
    assert upstream_tls.ssl_context(Policy()) is True


def test_strict_mode_uses_a_fixed_bundle_not_the_machine_trust_store(home):
    pol = Policy(); pol.tls_strict = True
    ctx = upstream_tls.ssl_context(pol)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_configuring_pins_alone_also_turns_on_a_real_context(home):
    pol = Policy(); pol.tls_pins = {"api.anthropic.com": ["abc"]}
    assert isinstance(upstream_tls.ssl_context(pol), ssl.SSLContext)


def test_pins_are_looked_up_case_insensitively(home):
    pol = Policy(); pol.tls_pins = {"api.anthropic.com": ["abc"]}
    assert upstream_tls.pins_for("API.Anthropic.COM", pol) == ["abc"]
    assert upstream_tls.pins_for("api.openai.com", pol) == []


def test_policy_round_trips_the_tls_settings(home):
    pol = Policy()
    pol.tls_strict = True
    pol.tls_pins = {"api.anthropic.com": ["pin1", "pin2"]}
    pol.save()
    back = Policy.load()
    assert back.tls_strict is True
    assert back.tls_pins == {"api.anthropic.com": ["pin1", "pin2"]}


# ------------------------------------------------------------ actually enforced
def test_no_pins_costs_nothing_and_never_looks(home, monkeypatch):
    """The default path must not open a TLS connection per request."""
    monkeypatch.setattr(upstream_tls, "fetch_pins",
                        lambda *a, **k: pytest.fail("must not probe when nothing is pinned"))
    upstream_tls.forget_cached_verdicts()
    upstream_tls.ensure_pinned("api.anthropic.com", Policy())


def test_a_matching_host_passes_and_is_cached(home, monkeypatch):
    calls = []
    monkeypatch.setattr(upstream_tls, "fetch_pins", lambda h, **k: calls.append(h) or ["GOOD"])
    upstream_tls.forget_cached_verdicts()
    pol = Policy(); pol.tls_pins = {"api.anthropic.com": ["GOOD"]}

    upstream_tls.ensure_pinned("api.anthropic.com", pol)
    upstream_tls.ensure_pinned("api.anthropic.com", pol)
    assert len(calls) == 1, "the verdict must be cached, not re-probed every request"


def test_an_impostor_is_refused_before_anything_is_sent(home, monkeypatch):
    monkeypatch.setattr(upstream_tls, "fetch_pins", lambda h, **k: ["IMPOSTOR"])
    upstream_tls.forget_cached_verdicts()
    pol = Policy(); pol.tls_pins = {"api.anthropic.com": ["EXPECTED"]}

    with pytest.raises(upstream_tls.PinnedVerificationError) as e:
        upstream_tls.ensure_pinned("api.anthropic.com", pol)
    assert "was NOT sent" in str(e.value)
    assert "omna tls pin api.anthropic.com" in str(e.value)


def test_the_cache_expires_so_a_rotation_is_picked_up(home, monkeypatch):
    seen = ["OLD"]
    monkeypatch.setattr(upstream_tls, "fetch_pins", lambda h, **k: list(seen))
    upstream_tls.forget_cached_verdicts()
    pol = Policy(); pol.tls_pins = {"h.test": ["OLD"]}

    upstream_tls.ensure_pinned("h.test", pol, now=0.0)
    seen[0] = "ROTATED"
    upstream_tls.ensure_pinned("h.test", pol, now=1.0)          # still cached: ok
    with pytest.raises(upstream_tls.PinnedVerificationError):     # past the TTL
        upstream_tls.ensure_pinned("h.test", pol, now=upstream_tls._TTL_SECONDS + 1)


def test_a_network_failure_is_not_treated_as_an_attack(home, monkeypatch):
    """A flaky network must not masquerade as an impostor, and must not be
    cached as a verdict either."""
    monkeypatch.setattr(upstream_tls, "fetch_pins",
                        lambda h, **k: (_ for _ in ()).throw(OSError("no route to host")))
    upstream_tls.forget_cached_verdicts()
    pol = Policy(); pol.tls_pins = {"h.test": ["EXPECTED"]}
    upstream_tls.ensure_pinned("h.test", pol)     # must not raise
    assert "h.test" not in upstream_tls._CACHE
