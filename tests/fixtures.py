"""Synthetic SAML messages and browser captures. Nothing here comes from a real environment."""
import base64
import json
import urllib.parse
import zlib

IDP_TENANT = "00000000-1111-2222-3333-444444444444"
IDP_SSO = "https://login.microsoftonline.com/%s/saml2" % IDP_TENANT
IDP_ISSUER = "https://sts.windows.net/%s/" % IDP_TENANT
UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CERT_B64 = base64.b64encode(b"not a real certificate, only bytes to hash").decode()
USER_PASSWORD = "Sup3r-Secret-Pw!"
PORTAL_TOKEN = "0123456789abcdef" * 3


def sp_values(portal_base):
    return (portal_base + "/spPortal/ACS/ID/" + UUID, portal_base + "/spPortal/ACS/Login/" + UUID)


def authn_request_url(portal_base, request_id="_req1"):
    entity_id, acs = sp_values(portal_base)
    xml = (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" '
        'IssueInstant="2030-01-01T00:00:00Z" Destination="%s" AssertionConsumerServiceURL="%s" '
        'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        '<saml:Issuer>%s</saml:Issuer>'
        '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>'
        '</samlp:AuthnRequest>' % (request_id, IDP_SSO, acs, entity_id))
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = co.compress(xml.encode()) + co.flush()
    relay = portal_base + "/spPortal/ServiceProvider?idpId=%s&realm=identity_portal" % UUID
    return IDP_SSO + "?" + urllib.parse.urlencode({"SAMLRequest": base64.b64encode(deflated).decode(), "RelayState": relay})


def saml_response_b64(portal_base, request_id="_req1", status="Success", audience=None, recipient=None,
                      nameid="user@example.com", groups=None):
    entity_id, acs = sp_values(portal_base)
    audience = audience or entity_id
    recipient = recipient or acs
    attrs = '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><AttributeValue>%s</AttributeValue></Attribute>' % nameid
    if groups:
        attrs += '<Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups">%s</Attribute>' % "".join(
            "<AttributeValue>%s</AttributeValue>" % g for g in groups)
    assertion = "" if status != "Success" else (
        '<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="2030-01-01T00:00:10Z">'
        '<Issuer>%s</Issuer>'
        '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignatureValue>AAAA</SignatureValue></Signature>'
        '<Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</NameID>'
        '<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        '<SubjectConfirmationData InResponseTo="%s" NotOnOrAfter="2030-01-01T01:00:00Z" Recipient="%s"/>'
        '</SubjectConfirmation></Subject>'
        '<Conditions NotBefore="2029-12-31T23:55:00Z" NotOnOrAfter="2030-01-01T01:00:00Z">'
        '<AudienceRestriction><Audience>%s</Audience></AudienceRestriction></Conditions>'
        '<AttributeStatement>%s</AttributeStatement></Assertion>' % (IDP_ISSUER, nameid, request_id, recipient, audience, attrs))
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" '
        'IssueInstant="2030-01-01T00:00:10Z" Destination="%s" InResponseTo="%s">'
        '<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">%s</Issuer>'
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></samlp:Status>%s'
        '</samlp:Response>' % (acs, request_id, IDP_ISSUER, status, assertion))
    return base64.b64encode(xml.encode()).decode()


def metadata_xml():
    return (
        '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">'
        '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>'
        '<X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor>'
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>'
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>'
        '</IDPSSODescriptor></EntityDescriptor>' % (IDP_ISSUER, CERT_B64, IDP_SSO, IDP_SSO)).encode()


def handoff_page(nac_url):
    return (
        '<html><head><script type="text/javascript">\n'
        'var nacUrl =  %s;\n'
        'function closethisasap() { var xhr = new XMLHttpRequest();\n'
        '  xhr.onreadystatechange = function() { window.location = nacUrl+ "PortalMain"; };\n'
        '  xhr.open(\'POST\', nacUrl+"/Login");\n'
        "  var params = { realm: 'passwordRealm', username: 'user%%40example.com', password: '%s' };\n"
        '  xhr.send(params); };\n'
        '</script></head><body onload="closethisasap();"></body></html>' % (json.dumps(nac_url).replace("/", "\\/"), PORTAL_TOKEN))


def _entry(method, url, status, rtype="document", redirect="", body="", params=None, error=None, req_headers=None):
    e = {
        "startedDateTime": "2030-01-01T00:00:00.000Z",
        "_resourceType": rtype,
        "request": {"method": method, "url": url, "headers": req_headers or [], "cookies": [], "queryString": []},
        "response": {"status": status, "headers": [], "cookies": [], "redirectURL": redirect,
                     "content": {"mimeType": "text/html", "text": body}},
    }
    if params is not None:
        e["request"]["postData"] = {
            "mimeType": "application/x-www-form-urlencoded",
            "text": urllib.parse.urlencode(params),
            "params": [{"name": k, "value": urllib.parse.quote(v, safe="")} for k, v in params],
        }
    if error:
        e["response"]["_error"] = error
    return e


def capture(portal_base, published_at_root, **response_kwargs):
    """A complete sign-in as Chrome records it. published_at_root selects the failing hand-off."""
    sp = portal_base + "/spPortal/ServiceProvider?idpId=%s&realm=identity_portal" % UUID
    _, acs = sp_values(portal_base)
    idp_url = authn_request_url(portal_base)
    host = urllib.parse.urlsplit(portal_base).netloc
    entries = [
        _entry("GET", portal_base + "/PortalMain", 200, body="<html>PORTAL_IS</html>"),
        _entry("GET", sp, 303, redirect=idp_url),
        _entry("GET", idp_url, 200, body="<html>sign in sFT:'%s'</html>" % ("F" * 40)),
        _entry("POST", "https://login.microsoftonline.com/%s/login" % IDP_TENANT, 200,
               body="<html>ok</html>",
               params=[("login", "user@example.com"), ("passwd", USER_PASSWORD), ("flowToken", "F" * 40)],
               req_headers=[{"name": "Cookie", "value": "ESTSAUTH=abcdefghijkl"}]),
        _entry("POST", acs, 303, redirect=sp,
               params=[("SAMLResponse", saml_response_b64(portal_base, **response_kwargs)), ("RelayState", sp)]),
    ]
    if published_at_root:
        entries.append(_entry("GET", sp, 200, body=handoff_page("/")))
        entries.append(_entry("POST", "https://login/", 0, rtype="xhr", error="net::ERR_NAME_NOT_RESOLVED",
                              params=[("realm", "passwordRealm"), ("username", "user@example.com"), ("password", PORTAL_TOKEN)]))
    else:
        prefix = urllib.parse.urlsplit(portal_base).path
        entries.append(_entry("GET", sp, 200, body=handoff_page(prefix + "/")))
        entries.append(_entry("POST", "https://%s%s//Login" % (host, prefix), 200, rtype="xhr",
                              body='{"type":"SUCCESS","orgUrl":""}',
                              params=[("realm", "passwordRealm"), ("username", "user@example.com"), ("password", PORTAL_TOKEN)]))
    return {"log": {"version": "1.2", "entries": entries}}
