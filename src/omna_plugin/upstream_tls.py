"""How Omna verifies the AI provider on the way out.

Omna sits in the middle by design: it opens your request, masks it, and sends
it on. That makes the *outbound* leg our responsibility. If someone could
impersonate ``api.anthropic.com`` to us, they would receive a masked prompt
plus your real API key — the masking would have worked and you would still be
robbed.

Two settings, both under your control, neither of them on by default:

**Strict CA (recommended, cheap).** Verify the provider against a fixed,
audited CA bundle (``certifi``) instead of whatever your machine happens to
trust. This matters because ``omna init`` adds a certificate authority to your
Mac's trust store for the *inbound* side — and a corporate MDM profile may have
added others. Neither should be able to vouch for Anthropic. Turn on with
``omna tls strict``.

**Pinning (strongest, sharpest edges).** Additionally require the provider's
certificate chain to contain a specific public key. This defeats even a
genuinely-issued certificate from a compromised or coerced CA.

Honest cost, stated because pinning is the classic way to ship an outage:
providers rotate certificates, and when they do, a pinned client stops working
until it is updated. That is why this is **off by default and empty by
default** — an unattended pin is a time bomb. We do not ship pins we would
have to chase; you add the ones you are willing to maintain, and Omna refuses
the connection rather than silently falling back if one stops matching.

Pins are SHA-256 of the certificate's SubjectPublicKeyInfo, base64 — the same
form as HTTP Public Key Pinning and what every other tool prints. Get one with:

    omna tls pin api.anthropic.com
"""

from __future__ import annotations

import base64
import hashlib
import socket
import ssl

from .policy import Policy


def spki_sha256(der_cert: bytes) -> str:
    """The pin for one certificate, from its DER bytes.

    We hash the public key, not the whole certificate, deliberately: a provider
    that renews with the SAME key keeps working. Pinning the certificate itself
    would break on every routine renewal, which is how pinning gets a bad name.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_der_x509_certificate(der_cert)
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


def fetch_pins(host: str, port: int = 443, timeout: float = 10.0) -> list[str]:
    """Every pin in the live chain for ``host``, leaf first.

    Returns more than one so you can pin an intermediate rather than the leaf.
    Pinning an intermediate survives leaf rotation, which is usually what you
    actually want.
    """
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            pins = [spki_sha256(der)] if der else []
            # Python only exposes the full chain from 3.10 on some builds; the
            # leaf is always available and is enough to get someone started.
            try:
                for cert in tls.get_verified_chain()[1:]:      # type: ignore[attr-defined]
                    pins.append(spki_sha256(cert.public_bytes(1)))
            except (AttributeError, OSError, ValueError):
                pass
    return pins


class PinnedVerificationError(ssl.SSLError):
    """The provider's chain did not contain any pin we were told to expect."""


def verify_chain_against_pins(der_certs: list[bytes], pins: list[str]) -> None:
    """Raise unless at least one certificate in the chain matches a pin.

    Fail closed: no match means we do not send. There is no "warn and continue"
    mode, because a warning on a background proxy is a warning nobody reads.
    """
    if not pins:
        return
    seen = []
    for der in der_certs:
        try:
            seen.append(spki_sha256(der))
        except Exception:
            continue
    if not any(p in pins for p in seen):
        raise PinnedVerificationError(
            "omna: the provider's certificate does not match any pin you configured, "
            "so the request was NOT sent. Either the certificate rotated (run "
            "`omna tls pin <host>` and update it) or something is impersonating it. "
            f"expected one of {pins}, saw {seen}"
        )


def ssl_context(policy: Policy | None = None) -> "ssl.SSLContext | bool | str":
    """What to hand httpx as ``verify=``.

    Default returns True — today's behaviour, your machine's trust store,
    nothing changes for anyone who has not opted in.
    """
    pol = policy or Policy.load()
    if not pol.tls_strict and not pol.tls_pins:
        return True
    import certifi

    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # TLS 1.2 floor: every provider we talk to does 1.3, and anything offering
    # less than 1.2 is not a provider we should be reaching.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def pins_for(host: str, policy: Policy | None = None) -> list[str]:
    pol = policy or Policy.load()
    return list((pol.tls_pins or {}).get(host.lower(), []))


# --------------------------------------------------------------- enforcement
# Storing a pin and never checking it is worse than no pin, so this is the part
# that actually runs on the request path.
#
# It checks the host BEFORE the first request is forwarded to it, and re-checks
# on a timer, caching the verdict in between so we are not opening a second TLS
# connection per request.
#
# **Honest limit.** We verify on our own connection and then forward on httpx's
# connection, so in principle an attacker who could impersonate the provider on
# exactly one of the two could slip through. Defeating that properly needs a
# post-handshake hook httpx does not expose. What this DOES stop is the real
# threat: a persistent impostor — a hijacked DNS entry, a corporate MITM box, a
# rogue CA — because those answer every connection, including ours.
_CACHE: dict[str, tuple[float, str | None]] = {}
_TTL_SECONDS = 600.0


def ensure_pinned(host: str, policy: Policy | None = None, *, now: float | None = None) -> None:
    """Raise PinnedVerificationError if ``host`` is pinned and does not match.

    A host with no pins returns immediately, so this costs nothing for the
    people who have not opted in — which is everyone by default.
    """
    import time

    pins = pins_for(host, policy)
    if not pins:
        return
    host = host.lower()
    now = now if now is not None else time.monotonic()
    hit = _CACHE.get(host)
    if hit and now - hit[0] < _TTL_SECONDS:
        if hit[1]:
            raise PinnedVerificationError(hit[1])
        return
    try:
        seen = fetch_pins(host)
    except OSError as e:
        # Could not look: do NOT cache, and do not block. A flaky network must
        # not masquerade as an attack, and the request will fail on its own if
        # the host is genuinely unreachable.
        del e
        return
    if any(p in pins for p in seen):
        _CACHE[host] = (now, None)
        return
    msg = (
        f"omna: {host} presented a certificate that matches none of the pins you "
        f"configured, so the request was NOT sent. Either the certificate rotated "
        f"(run `omna tls pin {host} --save` to update it) or something is "
        f"impersonating it.\n  expected one of: {pins}\n  saw: {seen}"
    )
    _CACHE[host] = (now, msg)
    raise PinnedVerificationError(msg)


def forget_cached_verdicts() -> None:
    """Drop the cache (a pin changed, or a test needs a clean slate)."""
    _CACHE.clear()
