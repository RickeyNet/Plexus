"""Parse XML that Plexus did not write: firewall configs and API answers.

A document type declaration is refused outright, so no entity, internal or
external, is ever declared or expanded (no "billion laughs", no file or URL
reads). Every config and API answer Plexus reads is plain XML with no DTD.
The parsing is done by ``defusedxml`` so the refusal sits in the parser
itself, not in a text check made before it.
"""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree  # nosec B405 - types and ParseError only; parsing goes through defusedxml

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring as _defused_fromstring


class DoctypeRefused(ValueError):
    """The XML declares a document type (and so possibly entities)."""


def parse_xml(text: str | bytes) -> ElementTree.Element:
    """The root element of ``text``.

    Raises :class:`DoctypeRefused` when the document has a DTD or entity
    declaration, and ``xml.etree.ElementTree.ParseError`` when it is not
    well-formed XML."""
    try:
        return _defused_fromstring(text, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as exc:
        raise DoctypeRefused("the XML declares a document type, which is refused") from exc
