"""The server certificate of the syslog TLS receiver (RFC 5425) and the CA
that signs device client certificates (mutual TLS).

Stored in ``auth_settings("syslog_tls")`` as ``cert_pem`` (the server
certificate, then any intermediates), ``key_pem`` (its private key,
encrypted at rest: ``routes.db.users.AUTH_SETTING_SECRET_PATHS``) and
``client_ca_pem`` (one or more CA certificates; empty: no client CA). The
live copy is :data:`MATERIAL`, loaded at startup and replaced by the admin
API (``/api/admin/metrics/receivers/tls`` in
``netcontrol/routes/metrics_engine.py``). The private key never leaves
this module through :func:`public_view`.

:func:`server_context` builds the listener's ``ssl.SSLContext``: TLS 1.2 or
later, and, with ``require_client_cert``, ``CERT_REQUIRED`` against the
client CA, so only a device holding a certificate that CA signed can send.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import re
import ssl
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from netcontrol.tls_pem import load_cert_chain_pem

SETTING_KEY = "syslog_tls"
FIELDS: tuple[str, ...] = ("cert_pem", "key_pem", "client_ca_pem")

# Size limits of the PEM text an admin may store.
MAX_CERT_PEM_CHARS = 65536
MAX_KEY_PEM_CHARS = 16384
MAX_CA_PEM_CHARS = 262144
MAX_CA_CERTS = 100

# Bounds of a generated self-signed certificate.
MIN_DAYS = 1
MAX_DAYS = 3650
MAX_SANS = 32
MAX_COMMON_NAME_CHARS = 64

_DNS_NAME = re.compile(
    r"^(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


class TlsMaterialError(ValueError):
    """A certificate, key or CA that cannot be used (the message says why)."""


MATERIAL: dict[str, str] = dict.fromkeys(FIELDS, "")


def sanitize(data: Any) -> dict[str, str]:
    """The stored material from ``data`` (the ``auth_settings`` row): each
    field a string, "" when missing."""
    out = dict.fromkeys(FIELDS, "")
    if isinstance(data, dict):
        for key in FIELDS:
            value = data.get(key)
            out[key] = value if isinstance(value, str) else ""
    return out


def apply(data: Any) -> dict[str, str]:
    """Make ``data`` (sanitized here) the live material. Returns it."""
    MATERIAL.clear()
    MATERIAL.update(sanitize(data))
    return dict(MATERIAL)


def has_certificate(material: dict[str, str] | None = None) -> bool:
    material = MATERIAL if material is None else material
    return bool(material.get("cert_pem") and material.get("key_pem"))


def has_client_ca(material: dict[str, str] | None = None) -> bool:
    material = MATERIAL if material is None else material
    return bool(material.get("client_ca_pem"))


def material_key(require_client_cert: bool) -> str:
    """A digest of what a TLS listener is built from: a different one means
    the listener must be rebuilt."""
    digest = hashlib.sha256()
    for key in FIELDS:
        digest.update(MATERIAL.get(key, "").encode("utf-8"))
        digest.update(b"\x00")
    digest.update(b"1" if require_client_cert else b"0")
    return digest.hexdigest()


# ── Parsing and validation ───────────────────────────────────────────────────


def _load_certificates(pem: str, what: str) -> list[x509.Certificate]:
    try:
        certs = x509.load_pem_x509_certificates(str(pem or "").encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise TlsMaterialError(f"The {what} is not a PEM certificate.") from exc
    if not certs:
        raise TlsMaterialError(f"The {what} is not a PEM certificate.")
    return certs


def _pem(certs: list[x509.Certificate]) -> str:
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in certs)


def _public_der(key: Any) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def validate_server_pair(cert_pem: str, key_pem: str) -> tuple[str, str]:
    """The server certificate (chain) and private key, checked and
    normalized: ``(cert_pem, key_pem)``. Raises :class:`TlsMaterialError`
    when either is not PEM, the key is encrypted or does not belong to the
    certificate, or the certificate has expired."""
    if len(cert_pem or "") > MAX_CERT_PEM_CHARS:
        raise TlsMaterialError(f"The certificate is longer than {MAX_CERT_PEM_CHARS} characters.")
    if len(key_pem or "") > MAX_KEY_PEM_CHARS:
        raise TlsMaterialError(f"The private key is longer than {MAX_KEY_PEM_CHARS} characters.")
    certs = _load_certificates(cert_pem, "certificate")
    try:
        key = serialization.load_pem_private_key(str(key_pem or "").encode("ascii"), password=None)
    except TypeError as exc:
        raise TlsMaterialError("The private key is encrypted: give it without a passphrase.") from exc
    except (ValueError, UnicodeEncodeError) as exc:
        raise TlsMaterialError("The private key is not a PEM private key.") from exc
    if _public_der(key.public_key()) != _public_der(certs[0].public_key()):
        raise TlsMaterialError("The private key does not belong to the certificate.")
    if certs[0].not_valid_after_utc <= dt.datetime.now(dt.UTC):
        raise TlsMaterialError(f"The certificate expired on {certs[0].not_valid_after_utc.date().isoformat()}.")
    normalized_key = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    normalized_cert = _pem(certs)
    try:
        load_cert_chain_pem(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), normalized_cert, normalized_key)
    except ssl.SSLError as exc:
        raise TlsMaterialError(f"The certificate and key cannot be used for TLS: {exc.reason or exc}") from exc
    return normalized_cert, normalized_key


def validate_client_ca(pem: str) -> str:
    """The client CA bundle, checked and normalized. Raises
    :class:`TlsMaterialError` when it is not PEM certificates."""
    if len(pem or "") > MAX_CA_PEM_CHARS:
        raise TlsMaterialError(f"The client CA is longer than {MAX_CA_PEM_CHARS} characters.")
    certs = _load_certificates(pem, "client CA")
    if len(certs) > MAX_CA_CERTS:
        raise TlsMaterialError(f"The client CA holds more than {MAX_CA_CERTS} certificates.")
    return _pem(certs)


# ── Self-signed certificate ──────────────────────────────────────────────────


def _general_name(value: str) -> x509.GeneralName:
    text = str(value or "").strip()
    try:
        return x509.IPAddress(ipaddress.ip_address(text))
    except ValueError:
        pass
    if len(text) > 253 or not _DNS_NAME.match(text):
        raise TlsMaterialError(f"{text!r} is not a DNS name or IP address.")
    return x509.DNSName(text.lower())


def generate_self_signed(common_name: str, sans: list[str], days: int) -> tuple[str, str]:
    """A new EC P-256 key and a self-signed server certificate for it,
    valid ``days`` from now: ``(cert_pem, key_pem)``. The subject
    alternative names are ``sans`` (DNS names or IP addresses) plus the
    common name when it is one of those."""
    name = str(common_name or "").strip()
    if not name or len(name) > MAX_COMMON_NAME_CHARS:
        raise TlsMaterialError(f"The common name must be 1 to {MAX_COMMON_NAME_CHARS} characters.")
    if not MIN_DAYS <= int(days) <= MAX_DAYS:
        raise TlsMaterialError(f"The validity must be {MIN_DAYS} to {MAX_DAYS} days.")
    if len(sans) > MAX_SANS:
        raise TlsMaterialError(f"At most {MAX_SANS} subject alternative names.")
    names: list[x509.GeneralName] = []
    for value in sans:
        general = _general_name(value)
        if general not in names:
            names.append(general)
    try:
        general = _general_name(name)
    except TlsMaterialError:
        pass  # a common name that is no host name stays out of the SANs
    else:
        if general not in names:
            names.append(general)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=int(days)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    return cert_pem, key_pem


# ── Listener context and API view ────────────────────────────────────────────


def server_context(require_client_cert: bool) -> ssl.SSLContext:
    """The TLS listener's context from :data:`MATERIAL`. Raises
    :class:`TlsMaterialError` without a server certificate, or when client
    certificates are required and no client CA is stored."""
    if not has_certificate():
        raise TlsMaterialError("No server certificate is stored for the syslog TLS receiver.")
    if require_client_cert and not has_client_ca():
        raise TlsMaterialError("Client certificates are required but no client CA is stored.")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        load_cert_chain_pem(ctx, MATERIAL["cert_pem"], MATERIAL["key_pem"])
        if require_client_cert:
            ctx.load_verify_locations(cadata=MATERIAL["client_ca_pem"])
            ctx.verify_mode = ssl.CERT_REQUIRED
    except ssl.SSLError as exc:
        raise TlsMaterialError(f"The stored certificate cannot be used for TLS: {exc.reason or exc}") from exc
    return ctx


def _iso(value: dt.datetime) -> str:
    return value.isoformat()


def _name(name: x509.Name) -> str:
    return name.rfc4514_string()


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [str(v) for v in ext.get_values_for_type(x509.DNSName)] + [
        str(v) for v in ext.get_values_for_type(x509.IPAddress)
    ]


def _self_signed(cert: x509.Certificate) -> bool:
    if cert.subject != cert.issuer:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except ValueError, TypeError, InvalidSignature:
        return False
    return True


def describe(cert: x509.Certificate) -> dict[str, Any]:
    """What the admin sees of a server certificate."""
    digest = cert.fingerprint(hashes.SHA256())
    return {
        "subject": _name(cert.subject),
        "issuer": _name(cert.issuer),
        "not_before": _iso(cert.not_valid_before_utc),
        "not_after": _iso(cert.not_valid_after_utc),
        "sha256_fingerprint": ":".join(f"{b:02X}" for b in digest),
        "sans": _sans(cert),
        "self_signed": _self_signed(cert),
    }


def public_view(material: dict[str, str] | None = None) -> dict[str, Any]:
    """The API view of the material: the certificates, never the key."""
    material = MATERIAL if material is None else material
    cert_pem = material.get("cert_pem", "")
    ca_pem = material.get("client_ca_pem", "")
    certificate = None
    if cert_pem:
        try:
            certificate = describe(_load_certificates(cert_pem, "certificate")[0])
        except TlsMaterialError:
            certificate = None
    client_ca: list[dict[str, str]] = []
    if ca_pem:
        try:
            client_ca = [
                {"subject": _name(c.subject), "not_after": _iso(c.not_valid_after_utc)}
                for c in _load_certificates(ca_pem, "client CA")
            ]
        except TlsMaterialError:
            client_ca = []
    return {
        "has_certificate": has_certificate(material),
        "certificate": certificate,
        "cert_pem": cert_pem,
        "has_client_ca": bool(ca_pem),
        "client_ca": client_ca,
        "client_ca_pem": ca_pem,
    }
