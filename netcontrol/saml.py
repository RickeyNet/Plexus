"""SAML 2.0 service provider: the protocol, with no FastAPI in it.

Plexus signs a browser in through a SAML 2.0 identity provider (Entra ID,
Okta, ADFS, Keycloak, PingFederate, Shibboleth) with SP-initiated Web
Browser SSO: an ``AuthnRequest`` sent over the HTTP-Redirect binding, the
``Response`` received over HTTP-POST at the assertion consumer service
(ACS). This module holds everything that builds what Plexus sends or checks
what the IdP returns, so it can be tested with locally generated keys:

- the SP metadata document and the ``AuthnRequest`` redirect URL;
- IdP metadata parsing (entity ID, SSO URL, signing certificates), from
  pasted XML or a URL, and manual certificates;
- response validation. The assertion must carry its own XML signature
  (``signxml``; RSA/ECDSA with SHA-256 or stronger) made by one of the
  configured IdP certificates, and only the bytes that signature covers are
  read afterwards, so a wrapped or injected element is never trusted. Then:
  status ``Success``, exactly one assertion and no encrypted one, issuer,
  audience, bearer subject confirmation with recipient = the ACS URL,
  ``InResponseTo`` = the request Plexus sent (on the response and the
  confirmation), ``NotBefore`` / ``NotOnOrAfter`` with 2 minutes of skew,
  and the response ``Destination`` when present;
- attribute mapping: username (an attribute, the email attribute, or the
  ``NameID``), display name and groups.

The caller refuses a replayed assertion ID (``routes.db.saml``).

XML is parsed twice-safe: every document first goes through
:func:`netcontrol.integrations.safe_xml.parse_xml` (``defusedxml``, any DTD
or entity refused), and the response is then parsed by ``lxml`` with entity
resolution, DTD loading and network access off, as ``signxml`` needs.

Every failure raises :class:`SamlError` (a :class:`netcontrol.sso.SsoError`)
with a code from :data:`netcontrol.sso.SSO_ERROR_CODES` and a short step
description that never holds the assertion.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import time
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode
from xml.sax.saxutils import escape, quoteattr  # nosec B406 - output escaping only, no parsing

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from lxml import etree  # nosec B410 - parsed only after defusedxml refused DTDs/entities, with a hardened parser
from signxml import InvalidCertificate, SignatureConfiguration, XMLVerifier
from signxml.exceptions import SignXMLException

from netcontrol.integrations.safe_xml import DoctypeRefused, parse_xml
from netcontrol.sso import (
    MAX_RESPONSE_BYTES,
    SsoError,
    SsoIdentity,
    clean_display_name,
    clean_username,
    group_values,
    is_allowed_url,
    log_safe,
    provider_request,
)

LOGIN_PATH = "/api/auth/saml/login"
ACS_PATH = "/api/auth/saml/acs"
METADATA_PATH = "/api/auth/saml/metadata"

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
CONFIRMATION_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

CLOCK_SKEW_SECONDS = 120
# The longest an accepted assertion is remembered for replay checks, even
# when its NotOnOrAfter lies further out.
MAX_ASSERTION_LIFETIME_SECONDS = 24 * 3600
MAX_CERTS = 5

# lxml parser for the (already defusedxml-checked) response: nothing is
# resolved, loaded or fetched.
_PARSER = etree.XMLParser(
    resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False, huge_tree=False
)


class SamlError(SsoError):
    """A SAML sign-in step failed (see :class:`SsoError`)."""


# ── Certificates ─────────────────────────────────────────────────────────────


def _load_cert(text: str) -> x509.Certificate:
    raw = str(text or "").strip()
    if "-----BEGIN CERTIFICATE-----" not in raw:
        body = "".join(raw.split())
        raw = "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"
    try:
        return x509.load_pem_x509_certificate(raw.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise SamlError("provider", "an IdP signing certificate is not a valid X.509 certificate") from exc


def normalize_cert(text: str) -> str:
    """A certificate given as PEM or as the bare base64 of metadata,
    returned as PEM. Raises ``provider`` when it is not a certificate."""
    cert = _load_cert(text)
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def cert_fingerprint(pem: str) -> str:
    """SHA-256 fingerprint, colon separated (shown to the admin)."""
    digest = _load_cert(pem).fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def cert_not_after(pem: str) -> str:
    return _load_cert(pem).not_valid_after_utc.strftime("%Y-%m-%d")


# ── Metadata ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IdpMetadata:
    entity_id: str
    sso_url: str
    certs: tuple[str, ...]


def _tag(ns: str, local: str) -> str:
    return "{" + NS[ns] + "}" + local


def parse_idp_metadata(xml_text: str | bytes, entity_id: str = "") -> IdpMetadata:
    """The IdP's entity ID, HTTP-Redirect SSO URL and signing certificates
    from its metadata. An ``EntitiesDescriptor`` with several IdPs needs
    ``entity_id`` to pick one."""
    if isinstance(xml_text, str):
        xml_text = xml_text.encode("utf-8")
    if not xml_text.strip():
        raise SamlError("provider", "the IdP metadata is empty")
    if len(xml_text) > MAX_RESPONSE_BYTES:
        raise SamlError("provider", "the IdP metadata is too large")
    try:
        root = parse_xml(xml_text)
    except DoctypeRefused as exc:
        raise SamlError("provider", "the IdP metadata declares a document type, which is refused") from exc
    except Exception as exc:  # ParseError and friends
        raise SamlError("provider", "the IdP metadata is not well-formed XML") from exc

    if root.tag == _tag("md", "EntityDescriptor"):
        descriptors = [root]
    elif root.tag == _tag("md", "EntitiesDescriptor"):
        descriptors = list(root.iter(_tag("md", "EntityDescriptor")))
    else:
        raise SamlError("provider", "the IdP metadata has no EntityDescriptor")
    idps = [d for d in descriptors if d.find(_tag("md", "IDPSSODescriptor")) is not None]
    if entity_id:
        idps = [d for d in idps if d.get("entityID") == entity_id]
    if not idps:
        raise SamlError(
            "provider",
            "the IdP metadata describes no identity provider" + (" with that entity ID" if entity_id else ""),
        )
    if len(idps) > 1:
        raise SamlError("provider", "the IdP metadata describes several identity providers; give the entity ID")
    desc = idps[0]
    idp = desc.find(_tag("md", "IDPSSODescriptor"))
    assert idp is not None  # filtered above
    sso_url = ""
    for svc in idp.findall(_tag("md", "SingleSignOnService")):
        if svc.get("Binding") == BINDING_REDIRECT and svc.get("Location"):
            sso_url = str(svc.get("Location")).strip()
            break
    if not sso_url:
        raise SamlError("provider", "the IdP metadata has no HTTP-Redirect SingleSignOnService")
    certs: list[str] = []
    for kd in idp.findall(_tag("md", "KeyDescriptor")):
        if kd.get("use") not in (None, "", "signing"):
            continue
        for node in kd.iter(_tag("ds", "X509Certificate")):
            pem = normalize_cert(node.text or "")
            if pem not in certs:
                certs.append(pem)
    if not certs:
        raise SamlError("provider", "the IdP metadata has no signing certificate")
    return IdpMetadata(entity_id=str(desc.get("entityID") or ""), sso_url=sso_url, certs=tuple(certs[:MAX_CERTS]))


async def fetch_metadata(url: str, ca_cert_file: str = "", transport: httpx.AsyncBaseTransport | None = None) -> str:
    """The IdP metadata document at ``url`` (``https``; redirects are not
    followed). The address passes the outbound SSRF guard and the request
    goes to the address the guard approved (``sso.provider_request``), like
    every other URL an admin has Plexus fetch."""
    if not is_allowed_url(url):
        raise SamlError("provider", "the IdP metadata URL must be an https URL")
    try:
        resp = await provider_request(
            "GET",
            url,
            ca_cert_file=ca_cert_file,
            transport=transport,
            error=SamlError,
            headers={"Accept": "application/samlmetadata+xml, application/xml, text/xml"},
        )
    except httpx.HTTPError as exc:
        raise SamlError("provider", f"IdP metadata request failed ({type(exc).__name__})") from exc
    if resp.status_code != 200:
        raise SamlError("provider", f"IdP metadata URL answered HTTP {resp.status_code}")
    if len(resp.content) > MAX_RESPONSE_BYTES:
        raise SamlError("provider", "the IdP metadata is too large")
    return resp.text


def sp_metadata_xml(entity_id: str, acs_url: str) -> str:
    """The service provider metadata to register at the IdP: entity ID and
    an HTTP-POST ACS; signed assertions wanted, requests unsigned."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<md:EntityDescriptor xmlns:md="{NS["md"]}" entityID={quoteattr(entity_id)}>\n'
        '  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        f"    <md:NameIDFormat>{escape(NAMEID_UNSPECIFIED)}</md:NameIDFormat>\n"
        f"    <md:AssertionConsumerService Binding={quoteattr(BINDING_POST)} "
        f'Location={quoteattr(acs_url)} index="0" isDefault="true"/>\n'
        "  </md:SPSSODescriptor>\n"
        "</md:EntityDescriptor>\n"
    )


# ── AuthnRequest ─────────────────────────────────────────────────────────────


def new_request_id() -> str:
    """An XML ID (must not start with a digit): ``_`` and 40 hex digits."""
    return "_" + secrets.token_hex(20)


def _instant(ts: float) -> str:
    return datetime.fromtimestamp(int(ts), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def authn_request_xml(
    *, request_id: str, sp_entity_id: str, acs_url: str, sso_url: str, now: float, authn_context: Iterable[str] = ()
) -> str:
    """``authn_context``: AuthnContextClassRef values the IdP is asked to
    use one of (``RequestedAuthnContext``, exact comparison)."""
    classes = "".join(f"<saml:AuthnContextClassRef>{escape(c)}</saml:AuthnContextClassRef>" for c in authn_context)
    requested = f'<samlp:RequestedAuthnContext Comparison="exact">{classes}</samlp:RequestedAuthnContext>'
    return (
        f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" '
        f'ID={quoteattr(request_id)} Version="2.0" IssueInstant="{_instant(now)}" '
        f"Destination={quoteattr(sso_url)} AssertionConsumerServiceURL={quoteattr(acs_url)} "
        f"ProtocolBinding={quoteattr(BINDING_POST)}>"
        f"<saml:Issuer>{escape(sp_entity_id)}</saml:Issuer>"
        f'<samlp:NameIDPolicy Format="{NAMEID_UNSPECIFIED}" AllowCreate="true"/>'
        f"{requested if classes else ''}"
        "</samlp:AuthnRequest>"
    )


def authn_request_url(
    sso_url: str,
    *,
    request_id: str,
    sp_entity_id: str,
    acs_url: str,
    relay_state: str,
    now: float | None = None,
    authn_context: Iterable[str] = (),
) -> str:
    """The IdP SSO URL carrying a deflated, base64 ``SAMLRequest`` and the
    ``RelayState`` (HTTP-Redirect binding, unsigned)."""
    xml = authn_request_xml(
        request_id=request_id,
        sp_entity_id=sp_entity_id,
        acs_url=acs_url,
        sso_url=sso_url,
        now=time.time() if now is None else now,
        authn_context=authn_context,
    )
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = compressor.compress(xml.encode("utf-8")) + compressor.flush()
    params = {"SAMLRequest": base64.b64encode(deflated).decode("ascii")}
    if relay_state:
        params["RelayState"] = relay_state
    sep = "&" if "?" in sso_url else "?"
    return sso_url + sep + urlencode(params)


# ── Response ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SamlSettings:
    """What :func:`parse_response` checks against (from the saved config)."""

    idp_entity_id: str
    certs: tuple[str, ...]
    sp_entity_id: str
    acs_url: str
    username_attribute: str = ""
    email_attribute: str = ""
    display_name_attribute: str = ""
    groups_attribute: str = ""
    # The attribute that identifies the person for good (the account is
    # bound to it); empty = the NameID.
    subject_attribute: str = ""
    # AuthnContextClassRef values, one of which the IdP must assert; empty =
    # whatever the IdP used.
    required_authn_context: tuple[str, ...] = ()


@dataclass(frozen=True)
class SamlResult:
    identity: SsoIdentity
    assertion_id: str
    # Epoch seconds until which the assertion ID must be remembered.
    expires_at: int


def parse_time(value: str | None) -> float | None:
    """An ``xs:dateTime`` as epoch seconds (no zone = UTC), ``None`` when
    absent; raises ``token`` when malformed."""
    if value is None:
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SamlError("token", "a SAML timestamp is malformed") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def _decode_response(saml_response: str) -> bytes:
    raw = str(saml_response or "").strip()
    if not raw:
        raise SamlError("token", "no SAMLResponse in the POST")
    if len(raw) > MAX_RESPONSE_BYTES * 4 // 3 + 4:
        raise SamlError("token", "the SAML response is too large")
    try:
        return base64.b64decode("".join(raw.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SamlError("token", "the SAML response is not base64") from exc


def _parse_xml(data: bytes) -> Any:
    # defusedxml first: refuses any DTD or entity before lxml sees the bytes.
    try:
        parse_xml(data)
    except DoctypeRefused as exc:
        raise SamlError("token", "the SAML response declares a document type, which is refused") from exc
    except Exception as exc:
        raise SamlError("token", "the SAML response is not well-formed XML") from exc
    try:
        return etree.fromstring(data, parser=_PARSER)  # nosec B320 - hardened parser, input already defused
    except etree.XMLSyntaxError as exc:
        raise SamlError("token", "the SAML response is not well-formed XML") from exc


def _verify_assertion(assertion: Any, certs: tuple[str, ...]) -> Any:
    """The assertion as covered by a valid signature from one of ``certs``.

    The assertion is verified on its own (a copy of the element), and the
    signature's single reference must point at the assertion itself."""
    if assertion.find("ds:Signature", NS) is None:
        raise SamlError("token", "the assertion is not signed")
    assertion_id = assertion.get("ID") or ""
    if not assertion_id:
        raise SamlError("token", "the assertion has no ID")
    data = etree.tostring(assertion)
    config = SignatureConfiguration(require_x509=True, expect_references=1, location="./")
    last: Exception | None = None
    for pem in certs:
        try:
            result = XMLVerifier().verify(data, x509_cert=pem, expect_config=config, parser=_PARSER, id_attribute="ID")
        except (SignXMLException, etree.LxmlError, ValueError) as exc:
            last = exc
            continue
        signed = result.signed_xml  # type: ignore[union-attr]
        if signed is None or signed.tag != _tag("saml", "Assertion") or signed.get("ID") != assertion_id:
            raise SamlError("token", "the signature does not cover the assertion")
        return signed
    reason = type(last).__name__ if last else "no certificate"
    if isinstance(last, InvalidCertificate):
        detail = "expired or not yet valid" if "valid" in str(last) else "not usable"
        raise SamlError("token", f"the configured IdP certificate is {detail}")
    raise SamlError("token", f"the assertion signature is not valid for the configured IdP certificate ({reason})")


def _text(node: Any) -> str:
    return (node.text or "").strip() if node is not None else ""


def _attributes(assertion: Any) -> dict[str, list[str]]:
    """Attribute values by ``Name``, and by ``FriendlyName`` for keys no
    ``Name`` has. ``Name`` is the identifier; ``FriendlyName`` is a label
    with no meaning of its own, so an attribute merely labelled like the
    configured one never adds to it or stands in for it."""
    by_name: dict[str, list[str]] = {}
    by_friendly_name: dict[str, list[str]] = {}
    for attr in assertion.iterfind("saml:AttributeStatement/saml:Attribute", NS):
        values = [_text(v) for v in attr.iterfind("saml:AttributeValue", NS)]
        values = [v for v in values if v]
        for key, out in ((attr.get("Name"), by_name), (attr.get("FriendlyName"), by_friendly_name)):
            if key:
                out.setdefault(key, []).extend(values)
    return {**by_friendly_name, **by_name}


def _check_window(not_before: float | None, not_on_or_after: float | None, now: float, what: str) -> None:
    if not_before is not None and now + CLOCK_SKEW_SECONDS < not_before:
        raise SamlError("token", f"the {what} is not yet valid")
    if not_on_or_after is not None and now - CLOCK_SKEW_SECONDS >= not_on_or_after:
        raise SamlError("token", f"the {what} has expired")


def parse_response(
    saml_response: str, settings: SamlSettings, *, request_id: str, now: float | None = None
) -> SamlResult:
    """The identity in a base64 ``SAMLResponse`` once every check passed.

    ``request_id`` is the ID of the ``AuthnRequest`` this browser was sent
    with; IdP-initiated responses (no ``InResponseTo``) are refused."""
    now = time.time() if now is None else now
    if not settings.certs:
        raise SamlError("provider", "no IdP signing certificate is configured")
    root = _parse_xml(_decode_response(saml_response))
    if root.tag != _tag("samlp", "Response"):
        raise SamlError("token", "the document is not a SAML Response")

    # The response envelope is not trusted for identity, only to refuse.
    status = root.find("samlp:Status/samlp:StatusCode", NS)
    status_value = status.get("Value") if status is not None else ""
    if status_value != STATUS_SUCCESS:
        second = status.find("samlp:StatusCode", NS) if status is not None else None
        sub_value = second.get("Value", "") if second is not None else ""
        denied = sub_value.endswith((":RequestDenied", ":AuthnFailed", ":NoPassive"))
        raise SamlError("denied" if denied else "provider", f"the IdP answered status {log_safe(status_value, 80)}")
    in_response_to = root.get("InResponseTo")
    if not request_id or not in_response_to or not secrets.compare_digest(in_response_to, request_id):
        raise SamlError("state", "the response does not answer the request this browser started")
    destination = root.get("Destination")
    if destination and destination != settings.acs_url:
        raise SamlError("token", "the response Destination is not this ACS URL")
    if root.find(".//saml:EncryptedAssertion", NS) is not None:
        raise SamlError("token", "encrypted assertions are not supported")
    assertions = root.findall(".//saml:Assertion", NS)
    if len(assertions) != 1 or assertions[0].getparent() is not root:
        raise SamlError("token", "the response must hold exactly one assertion")

    assertion = _verify_assertion(assertions[0], settings.certs)
    assertion_id = str(assertion.get("ID"))

    issuer = _text(assertion.find("saml:Issuer", NS))
    if not settings.idp_entity_id or issuer != settings.idp_entity_id:
        raise SamlError("token", "the assertion issuer is not the configured IdP")

    conditions = assertion.find("saml:Conditions", NS)
    if conditions is None:
        raise SamlError("token", "the assertion has no Conditions")
    cond_not_after = parse_time(conditions.get("NotOnOrAfter"))
    _check_window(parse_time(conditions.get("NotBefore")), cond_not_after, now, "assertion")
    audiences = [_text(a) for a in conditions.iterfind("saml:AudienceRestriction/saml:Audience", NS)]
    if settings.sp_entity_id not in audiences:
        raise SamlError("token", "the assertion audience is not this service provider")

    subject = assertion.find("saml:Subject", NS)
    if subject is None:
        raise SamlError("token", "the assertion has no Subject")
    confirmed_until: float | None = None
    for confirmation in subject.iterfind("saml:SubjectConfirmation", NS):
        if confirmation.get("Method") != CONFIRMATION_BEARER:
            continue
        data = confirmation.find("saml:SubjectConfirmationData", NS)
        if data is None:
            continue
        until = parse_time(data.get("NotOnOrAfter"))
        if until is None or now - CLOCK_SKEW_SECONDS >= until:
            continue
        if data.get("NotBefore") is not None:
            continue  # SAML profiles: a bearer confirmation carries no NotBefore
        if data.get("Recipient") != settings.acs_url:
            continue
        irt = data.get("InResponseTo")
        if not irt or not secrets.compare_digest(irt, request_id):
            continue
        confirmed_until = until
        break
    if confirmed_until is None:
        raise SamlError(
            "token",
            "no bearer subject confirmation matches this ACS URL, request and time (Recipient, InResponseTo, NotOnOrAfter)",
        )

    name_id_node = subject.find("saml:NameID", NS)
    name_id = _text(name_id_node)
    if not name_id:
        raise SamlError("claims", "the assertion has no NameID")
    nameid_format = name_id_node.get("Format") if name_id_node is not None else ""

    attrs = _attributes(assertion)

    def first(name: str) -> str:
        values = attrs.get(name) if name else None
        return values[0] if values else ""

    if settings.username_attribute:
        raw_username: Any = first(settings.username_attribute) or (
            first(settings.email_attribute) if settings.email_attribute else ""
        )
        what = f"attribute '{settings.username_attribute}'"
    elif settings.email_attribute:
        raw_username = first(settings.email_attribute)
        what = f"attribute '{settings.email_attribute}'"
    else:
        if nameid_format == NAMEID_TRANSIENT:
            raise SamlError("claims", "the NameID is transient; map a username attribute")
        raw_username = name_id
        what = "NameID"
    username = clean_username(raw_username or None, what, SamlError)
    display_name = clean_display_name(first(settings.display_name_attribute)) if settings.display_name_attribute else ""
    groups = group_values(attrs.get(settings.groups_attribute, [])) if settings.groups_attribute else []

    if settings.required_authn_context:
        asserted = {
            _text(ref)
            for ref in assertion.iterfind("saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef", NS)
        }
        if not asserted & set(settings.required_authn_context):
            raise SamlError("claims", "the IdP did not sign the user in with a required authentication context")

    if settings.subject_attribute:
        subject_id = first(settings.subject_attribute)
        if not subject_id:
            raise SamlError("claims", f"attribute '{settings.subject_attribute}' (the subject) is missing")
    else:
        # A transient NameID changes every sign-in, so bind the account to
        # the username instead.
        subject_id = username if nameid_format == NAMEID_TRANSIENT else name_id
    expires = min(t for t in (cond_not_after, confirmed_until) if t is not None)
    expires_at = int(min(expires, now + MAX_ASSERTION_LIFETIME_SECONDS)) + CLOCK_SKEW_SECONDS
    return SamlResult(
        identity=SsoIdentity(sub=subject_id[:512], username=username, display_name=display_name, groups=groups),
        assertion_id=hashlib.sha256(f"{issuer}\n{assertion_id}".encode()).hexdigest(),
        expires_at=expires_at,
    )
