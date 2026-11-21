"""OPNsense certificates and certificate authorities, for expiry tracking.

What is read (``collector.collect_certificates``; both GET, every row of the
trust store, OPNsense 24.7+; checked against ``opnsense/core`` master,
``controllers/OPNsense/Trust/Api/CertController.php`` and
``CaController.php``, ``models/OPNsense/Trust/Cert.xml`` and ``Ca.xml``,
``FieldTypes/CertificatesField.php``, ``FieldTypes/CAsField.php``):

  - ``trust/cert/search`` (privilege "System: Trust: Certificates"): one row
    per certificate with ``refid`` (13 hex digits, what services reference),
    ``descr``, ``caref`` (the issuing CA's refid, ``%caref`` its name),
    ``commonname``, ``valid_from`` / ``valid_to`` (Unix seconds, from
    ``openssl_x509_parse``), ``in_use`` (``1`` when anything but a user or
    the certificate itself references the refid: the web GUI, OpenVPN,
    IPsec, a plugin), ``is_user`` (the common name is a local user) and
    ``cert_type`` (``server_cert``, ``usr_cert``, ``combined_server_client``,
    from the extended key usage).
  - ``trust/ca/search`` (privilege "System: Trust: Authorities"): one row per
    CA with the same date and name fields, ``caref`` (the parent CA of an
    intermediate) and ``refcount`` (how many places reference the CA:
    certificates it issued, CAs below it, services that trust it).

The search answers carry every field of the model, the private key
(``prv``, ``prv_payload``) and the PEM bodies included: only
``_CERT_KEPT`` / ``_CA_KEPT`` are kept, straight after the call, and nothing
else is stored, logged or put in a snapshot. Never ``add``, ``set``,
``del``, ``generate_file`` or ``raw_dump``.

A release without the trust API (24.1 and older answer 404) falls back to
the ``<cert>`` and ``<ca>`` sections of the ``config.xml`` the collection
downloads (``certificates_from_config``): only the public certificate is
parsed (``crt``, base64 PEM), never ``prv``; ``in_use`` and ``refcount`` are
worked out from the references the way ``CertificatesField`` /
``CAsField`` do.

``certificate_records`` turns either into the records the snapshot carries:
expiry, days left, the tier (``availability.certificate_tier``) and whether
the certificate is *tracked* (alerted on):

  - a certificate is tracked when it is in use;
  - a CA is tracked when a tracked certificate or a tracked CA below it
    names it as issuer, or when something other than the certificates and
    CAs it issued references it (a service that trusts it, e.g. an OpenVPN
    server's CA);
  - everything else (unused certificates, user certificates no service
    uses, CAs nothing tracked depends on) is listed only.
"""

from __future__ import annotations

import base64
import xml.etree.ElementTree as ElementTree  # nosec B405 - types only; parsing goes through safe_xml
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from netcontrol.integrations.availability import CERTIFICATE_TIER_RANK, certificate_expiry_text, certificate_tier
from netcontrol.integrations.pathtrace.opnsense_config import parse_xml

PATH_CERTIFICATES = ("trust/cert/search",)
PATH_AUTHORITIES = ("trust/ca/search",)
# (key, paths, the privilege that grants them).
CERTIFICATE_PARTS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("certificates", PATH_CERTIFICATES, "System: Trust: Certificates"),
    ("authorities", PATH_AUTHORITIES, "System: Trust: Authorities"),
)

# The fields kept of a search row: no key, no PEM, no CSR.
_COMMON_KEPT = ("uuid", "refid", "descr", "caref", "%caref", "commonname", "valid_from", "valid_to")
_CERT_KEPT = (*_COMMON_KEPT, "in_use", "is_user", "cert_type", "%cert_type")
_CA_KEPT = (*_COMMON_KEPT, "refcount")
# Where a reference to a certificate does not make it "in use"
# (``CertificatesField``: a user's certificate list, the certificate itself).
_NOT_IN_USE_PATHS = frozenset({"system.user", "cert"})
_TYPE_LABELS = {
    "server_cert": "Server",
    "usr_cert": "Client",
    "combined_server_client": "Server and client",
}


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _flag(value: Any) -> bool:
    return _text(value).lower() in ("1", "true", "yes")


def keep_rows(body: Any, kind: str) -> list[dict[str, Any]]:
    """The rows of a ``trust/cert/search`` (``kind`` ``certificates``) or
    ``trust/ca/search`` (``authorities``) answer with only the kept fields."""
    kept = _CERT_KEPT if kind == "certificates" else _CA_KEPT
    found = body.get("rows") if isinstance(body, dict) else None
    rows = [r for r in found if isinstance(r, dict)] if isinstance(found, list) else []
    return [{k: row[k] for k in kept if k in row} for row in rows]


# ── config.xml fallback ─────────────────────────────────────────────────────


def _load(crt: str) -> x509.Certificate | None:
    """The certificate of a ``<crt>`` (base64 of the PEM), ``None`` when it is
    not one."""
    try:
        pem = base64.b64decode("".join(crt.split()), validate=True)
        return x509.load_pem_x509_certificate(pem)
    except ValueError:  # binascii.Error too
        return None


def _common_name(cert: x509.Certificate) -> str:
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    value = names[0].value if names else ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _cert_type(cert: x509.Certificate) -> str:
    """``Store::extractPurpose``'s type, from the extended key usage."""
    try:
        usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return ""
    server = ExtendedKeyUsageOID.SERVER_AUTH in usage
    client = ExtendedKeyUsageOID.CLIENT_AUTH in usage
    if server:
        return "combined_server_client" if client else "server_cert"
    return "usr_cert" if client else ""


def _references(root: ElementTree.Element) -> dict[str, list[str]]:
    """Every text value of the document -> where it occurs, as
    ``CertificatesField`` names it: ``<grandparent>.<parent>`` of the
    element holding it, or only ``<parent>`` below the root."""
    parents = {child: parent for parent in root.iter() for child in parent}
    found: dict[str, list[str]] = {}
    for element in root.iter():
        value = (element.text or "").strip()
        parent = parents.get(element)
        if not value or parent is None:
            continue
        grandparent = parents.get(parent)
        path = f"{grandparent.tag}.{parent.tag}" if grandparent is not None and grandparent is not root else parent.tag
        found.setdefault(value, []).append(path)
    return found


def _config_row(element: ElementTree.Element, cert: x509.Certificate) -> dict[str, Any]:
    return {
        "uuid": _text(element.get("uuid")),
        "refid": _text(element.findtext("refid")),
        "descr": _text(element.findtext("descr")),
        "caref": _text(element.findtext("caref")),
        "commonname": _common_name(cert),
        "valid_from": str(int(cert.not_valid_before_utc.timestamp())),
        "valid_to": str(int(cert.not_valid_after_utc.timestamp())),
    }


def certificates_from_config(config_xml: str | None) -> dict[str, Any] | None:
    """The certificates and CAs of a ``config.xml`` in the shape of the
    search answers' kept rows (``source`` ``config.xml``); ``None`` when the
    text is no OPNsense configuration. Only the public certificate is
    parsed; an entry whose certificate cannot be parsed (a pending signing
    request) is left out."""
    root = parse_xml(config_xml or "")
    if root is None:
        return None
    references = _references(root)
    users = {_text(u.findtext("name")) for u in root.findall("system/user")}
    certificates: list[dict[str, Any]] = []
    for element in root.findall("cert"):
        cert = _load(_text(element.findtext("crt")))
        if cert is None:
            continue
        row = _config_row(element, cert)
        paths = references.get(row["refid"], []) if row["refid"] else []
        row["in_use"] = "1" if any(p not in _NOT_IN_USE_PATHS for p in paths) else "0"
        row["is_user"] = "1" if row["commonname"] in users else "0"
        row["cert_type"] = _cert_type(cert)
        certificates.append(row)
    authorities: list[dict[str, Any]] = []
    for element in root.findall("ca"):
        cert = _load(_text(element.findtext("crt")))
        if cert is None:
            continue
        row = _config_row(element, cert)
        # ``CAsField``: every occurrence of the refid but its own.
        row["refcount"] = str(max(0, len(references.get(row["refid"], [])) - 1)) if row["refid"] else "0"
        authorities.append(row)
    return {"source": "config.xml", "certificates": certificates, "authorities": authorities}


# ── Records ──────────────────────────────────────────────────────────────────


def _epoch(value: Any) -> float | None:
    text = _text(value)
    try:
        return float(text) if text else None
    except ValueError:
        return None


def _iso(epoch: float | None) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds") if epoch is not None else ""


def _refcount(row: dict) -> int:
    try:
        return int(_text(row.get("refcount")) or 0)
    except ValueError:
        return 0


def _tracked_authorities(certificates: list[dict], authorities: list[dict], in_use: set[str]) -> set[str]:
    """The refids of the CAs that are tracked (see the module docstring)."""
    issued: dict[str, int] = {}
    for row in [*certificates, *authorities]:
        caref = _text(row.get("caref"))
        if caref:
            issued[caref] = issued.get(caref, 0) + 1
    tracked = set()
    for row in authorities:
        refid = _text(row.get("refid"))
        if refid and _refcount(row) > issued.get(refid, 0):
            tracked.add(refid)  # referenced by something it did not issue
    # A tracked certificate's issuer, and up the chain.
    parents = {_text(r.get("refid")): _text(r.get("caref")) for r in authorities if _text(r.get("refid"))}
    pending = [_text(r.get("caref")) for r in certificates if _text(r.get("refid")) in in_use]
    pending += [parents.get(refid, "") for refid in tracked]
    while pending:
        refid = pending.pop()
        if refid and refid in parents and refid not in tracked:
            tracked.add(refid)
            pending.append(parents[refid])
    return tracked


def certificate_records(found: Any, now: float | None) -> list[dict[str, Any]] | None:
    """The certificates and CAs of a collection's ``certificates`` part
    (``collector.collect_certificates``) as records: ``id`` (``cert:<refid>``
    or ``ca:<refid>``: the refid stays when a certificate is reissued or
    renewed in place), ``kind`` (``certificate`` / ``authority``), name,
    common name, issuer, type, the dates (UTC ISO), ``days_left`` (whole
    days, negative once expired), ``tier`` (``availability.certificate_tier``
    at ``now``), ``in_use``, ``user`` and ``tracked``. ``None`` when not
    read. Ordered: tracked first, soonest expiry first."""
    if not isinstance(found, dict):
        return None
    certificates = [r for r in found.get("certificates") or [] if isinstance(r, dict)]
    authorities = [r for r in found.get("authorities") or [] if isinstance(r, dict)]
    ca_names = {_text(r.get("refid")): _text(r.get("descr")) for r in authorities if _text(r.get("refid"))}
    in_use = {_text(r.get("refid")) for r in certificates if _flag(r.get("in_use")) and _text(r.get("refid"))}
    tracked_cas = _tracked_authorities(certificates, authorities, in_use)
    records: list[dict[str, Any]] = []
    for kind, rows in (("certificate", certificates), ("authority", authorities)):
        for row in rows:
            refid = _text(row.get("refid")) or _text(row.get("uuid"))
            if not refid:
                continue
            valid_to = _epoch(row.get("valid_to"))
            caref = _text(row.get("caref"))
            tracked = refid in (in_use if kind == "certificate" else tracked_cas)
            days_left = None
            if valid_to is not None and now is not None:
                days_left = int((valid_to - now) / 86400)  # toward zero
            cert_type = _text(row.get("cert_type"))
            # No issuing CA on the firewall: a root CA signs itself; a
            # certificate may also come from a CA the firewall does not hold.
            unlinked = "self-signed" if kind == "authority" else "external or self-signed"
            records.append(
                {
                    "id": f"{'cert' if kind == 'certificate' else 'ca'}:{refid}",
                    "kind": kind,
                    "refid": refid,
                    "name": _text(row.get("descr")) or _text(row.get("commonname")) or refid,
                    "common_name": _text(row.get("commonname")),
                    "issuer": _text(row.get("%caref")) or ca_names.get(caref, "") or ("" if caref else unlinked),
                    "type": "CA" if kind == "authority" else _TYPE_LABELS.get(cert_type, cert_type),
                    "valid_from": _iso(_epoch(row.get("valid_from"))),
                    "valid_to": _iso(valid_to),
                    "days_left": days_left,
                    "tier": certificate_tier(valid_to, now),
                    "in_use": _refcount(row) > 0 if kind == "authority" else _flag(row.get("in_use")),
                    "user": _flag(row.get("is_user")),
                    "tracked": tracked,
                }
            )
    records.sort(key=lambda r: (not r["tracked"], -CERTIFICATE_TIER_RANK.get(r["tier"], 0), r["valid_to"] or "~"))
    return records


def days_text(record: dict[str, Any]) -> str:
    """``expires in 12 days`` / ``expired 3 days ago`` of a record."""
    return certificate_expiry_text(record.get("days_left"), str(record.get("tier") or ""))
