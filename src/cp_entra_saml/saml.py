"""Decoding of SAML messages and federation metadata. Read-only: nothing here
validates signatures; it extracts what an administrator needs to compare."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from typing import Dict, List, Optional

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

GROUP_CLAIM_NAMES = (
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
    "group_attr",
    "groups",
)


class SamlError(Exception):
    pass


def _parse_xml(data: bytes) -> ET.Element:
    # No DTDs: SAML never needs one, and refusing them rules out entity tricks.
    head = data[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in data.lower():
        raise SamlError("XML with a DOCTYPE or entity declaration is not accepted")
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise SamlError("not well-formed XML: %s" % e) from e


def _b64(value: str) -> bytes:
    v = re.sub(r"\s+", "", value)
    v += "=" * (-len(v) % 4)
    try:
        return base64.b64decode(v)
    except (binascii.Error, ValueError) as e:
        raise SamlError("not valid Base64: %s" % e) from e


def decode_redirect_request(url: str) -> Dict[str, Optional[str]]:
    """Decode the AuthnRequest carried in an HTTP-Redirect binding URL."""
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    if "SAMLRequest" not in q:
        raise SamlError("the URL has no SAMLRequest parameter")
    raw = _b64(q["SAMLRequest"][0])
    try:
        xml = zlib.decompress(raw, -15)
    except zlib.error:
        xml = raw  # some senders do not deflate
    root = _parse_xml(xml)
    policy = root.find("samlp:NameIDPolicy", NS)
    issuer = root.find("saml:Issuer", NS)
    return {
        "id": root.get("ID"),
        "issue_instant": root.get("IssueInstant"),
        "destination": root.get("Destination"),
        "acs_url": root.get("AssertionConsumerServiceURL"),
        "protocol_binding": root.get("ProtocolBinding"),
        "issuer": (issuer.text or "").strip() if issuer is not None else None,
        "nameid_format": policy.get("Format") if policy is not None else None,
        "relay_state": q.get("RelayState", [None])[0],
        "signed": "Signature" in q,
    }


def decode_response(b64_value: str) -> Dict[str, object]:
    """Decode a SAMLResponse form value (HTTP-POST binding)."""
    root = _parse_xml(_b64(b64_value))
    out: Dict[str, object] = {
        "id": root.get("ID"),
        "issue_instant": root.get("IssueInstant"),
        "destination": root.get("Destination"),
        "in_response_to": root.get("InResponseTo"),
        "response_signed": root.find("ds:Signature", NS) is not None,
    }
    codes = [c.get("Value") or "" for c in root.iterfind("samlp:Status//samlp:StatusCode", NS)]
    out["status"] = codes[0] if codes else None
    out["status_detail"] = codes[1:]
    msg = root.find("samlp:Status/samlp:StatusMessage", NS)
    out["status_message"] = (msg.text or "").strip() if msg is not None else None
    issuer = root.find("saml:Issuer", NS)
    out["issuer"] = (issuer.text or "").strip() if issuer is not None else None
    out["encrypted_assertion"] = root.find("saml:EncryptedAssertion", NS) is not None

    a = root.find("saml:Assertion", NS)
    out["has_assertion"] = a is not None
    if a is None:
        return out
    out["assertion_signed"] = a.find("ds:Signature", NS) is not None
    nameid = a.find("saml:Subject/saml:NameID", NS)
    if nameid is not None:
        out["nameid"] = (nameid.text or "").strip()
        out["nameid_format"] = nameid.get("Format")
    scd = a.find("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", NS)
    if scd is not None:
        out["recipient"] = scd.get("Recipient")
    cond = a.find("saml:Conditions", NS)
    if cond is not None:
        out["not_before"] = cond.get("NotBefore")
        out["not_on_or_after"] = cond.get("NotOnOrAfter")
    out["audiences"] = [(e.text or "").strip() for e in a.iterfind("saml:Conditions/saml:AudienceRestriction/saml:Audience", NS)]
    attrs: Dict[str, List[str]] = {}
    for at in a.iterfind("saml:AttributeStatement/saml:Attribute", NS):
        attrs[at.get("Name") or ""] = [(v.text or "").strip() for v in at.iterfind("saml:AttributeValue", NS)]
    out["attributes"] = attrs
    out["group_claims"] = sorted(n for n in attrs if n in GROUP_CLAIM_NAMES or n.lower().endswith("/groups"))
    return out


def parse_metadata(xml: bytes) -> Dict[str, object]:
    """Identity-provider federation metadata -> the values Check Point needs."""
    root = _parse_xml(xml)
    if not root.tag.endswith("}EntityDescriptor"):
        raise SamlError("the document is not SAML metadata (root element %s)" % root.tag)
    idp = root.find("md:IDPSSODescriptor", NS)
    if idp is None:
        raise SamlError("the metadata has no IDPSSODescriptor (not an identity provider?)")
    sso = {}
    for s in idp.iterfind("md:SingleSignOnService", NS):
        sso[(s.get("Binding") or "").rsplit(":", 1)[-1]] = s.get("Location")
    certs = []
    for kd in idp.iterfind("md:KeyDescriptor", NS):
        if kd.get("use") not in (None, "signing"):
            continue
        for c in kd.iterfind(".//ds:X509Certificate", NS):
            der = _b64(c.text or "")
            certs.append({
                "base64": base64.b64encode(der).decode("ascii"),
                "sha1": hashlib.sha1(der).hexdigest().upper(),
                "sha256": hashlib.sha256(der).hexdigest().upper(),
            })
    return {
        "entity_id": root.get("entityID"),
        "sso_redirect_url": sso.get("HTTP-Redirect"),
        "sso_post_url": sso.get("HTTP-POST"),
        "signing_certificates": certs,
    }
