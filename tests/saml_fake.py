"""A fake SAML 2.0 identity provider for tests: a key and self-signed
certificate generated in-test, IdP metadata, and signed responses built to
order (``build_response``) so each validation rule can be broken on its own.

Every name, host and value is invented (``example.com``).
"""

from __future__ import annotations

import base64
import datetime as dt
import time
import zlib
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod

IDP_ENTITY_ID = "https://idp.example.com/saml"
IDP_SSO_URL = "https://idp.example.com/saml/sso"
SP_ENTITY_ID = "http://testserver/api/auth/saml/metadata"
ACS_URL = "http://testserver/api/auth/saml/acs"

NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"


def make_key_and_cert(cn: str = "idp.example.com", *, days: int = 365) -> tuple[str, str]:
    """A fresh RSA key and self-signed certificate, both PEM."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=max(1, 1 - days)))
        .not_valid_after(now + dt.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return key_pem, cert.public_bytes(serialization.Encoding.PEM).decode()


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(int(ts), dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def cert_body(cert_pem: str) -> str:
    return "".join(line for line in cert_pem.splitlines() if "CERTIFICATE" not in line)


def idp_metadata(cert_pem: str, *, entity_id: str = IDP_ENTITY_ID, sso_url: str = IDP_SSO_URL) -> str:
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{entity_id}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_body(cert_pem)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_body(cert_pem)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{sso_url}/post"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


def request_from_redirect(location: str) -> tuple[str, str]:
    """``(AuthnRequest ID, RelayState)`` from the redirect Plexus sent."""
    params = parse_qs(urlsplit(location).query)
    xml = zlib.decompress(base64.b64decode(params["SAMLRequest"][0]), -15)
    root = etree.fromstring(xml)
    return root.get("ID"), params.get("RelayState", [""])[0]


def build_assertion(
    *,
    request_id: str,
    now: float | None = None,
    assertion_id: str = "_assertion-0001",
    issuer: str = IDP_ENTITY_ID,
    audience: str = SP_ENTITY_ID,
    recipient: str = ACS_URL,
    name_id: str = "alice@example.com",
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    not_before_offset: int = -60,
    not_on_or_after_offset: int = 300,
    confirmation_offset: int = 300,
    confirmation_in_response_to: str | None = None,
    attributes: dict[str, list[str]] | None = None,
) -> etree._Element:
    now = time.time() if now is None else now
    attributes = (
        attributes
        if attributes is not None
        else {
            "uid": ["alice"],
            "mail": ["alice@example.com"],
            "displayName": ["Alice Example"],
            "groups": ["plexus-users", "netops"],
        }
    )
    attrs = "".join(
        f'<saml:Attribute Name="{name}">'
        + "".join(f"<saml:AttributeValue>{v}</saml:AttributeValue>" for v in values)
        + "</saml:Attribute>"
        for name, values in attributes.items()
    )
    irt = request_id if confirmation_in_response_to is None else confirmation_in_response_to
    xml = f"""<saml:Assertion xmlns:saml="{NS_SAML}" ID="{assertion_id}" Version="2.0" IssueInstant="{_iso(now)}">
<saml:Issuer>{issuer}</saml:Issuer>
<saml:Subject>
<saml:NameID Format="{name_id_format}">{name_id}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData InResponseTo="{irt}" Recipient="{recipient}" NotOnOrAfter="{_iso(now + confirmation_offset)}"/>
</saml:SubjectConfirmation>
</saml:Subject>
<saml:Conditions NotBefore="{_iso(now + not_before_offset)}" NotOnOrAfter="{_iso(now + not_on_or_after_offset)}">
<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="{_iso(now)}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
<saml:AttributeStatement>{attrs}</saml:AttributeStatement>
</saml:Assertion>"""
    return etree.fromstring(xml.encode())


def sign(element: etree._Element, key_pem: str, cert_pem: str) -> etree._Element:
    """``element`` enveloped-signed as IdPs sign assertions (exclusive C14N)."""
    signer = XMLSigner(
        signature_algorithm=SignatureMethod.RSA_SHA256,
        digest_algorithm=DigestAlgorithm.SHA256,
        c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    )
    return signer.sign(element, key=key_pem, cert=cert_pem, reference_uri="#" + element.get("ID"))


def build_response(
    assertion: etree._Element | None,
    *,
    request_id: str,
    destination: str = ACS_URL,
    status: str = "urn:oasis:names:tc:SAML:2.0:status:Success",
    extra: str = "",
) -> bytes:
    resp = etree.fromstring(
        f'<samlp:Response xmlns:samlp="{NS_SAMLP}" xmlns:saml="{NS_SAML}" ID="_response-0001" Version="2.0" '
        f'IssueInstant="{_iso(time.time())}" Destination="{destination}" InResponseTo="{request_id}">'
        f"<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>"
        f'<samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>{extra}</samlp:Response>'.encode()
    )
    if assertion is not None:
        resp.append(assertion)
    return etree.tostring(resp)


def encode(xml: bytes) -> str:
    return base64.b64encode(xml).decode("ascii")


class FakeSamlIdP:
    """A key, a certificate and helpers for a complete signed response."""

    def __init__(self) -> None:
        self.key_pem, self.cert_pem = make_key_and_cert()

    def metadata(self) -> str:
        return idp_metadata(self.cert_pem)

    def response(self, request_id: str, **assertion_kwargs) -> str:
        assertion = sign(build_assertion(request_id=request_id, **assertion_kwargs), self.key_pem, self.cert_pem)
        return encode(build_response(assertion, request_id=request_id))
