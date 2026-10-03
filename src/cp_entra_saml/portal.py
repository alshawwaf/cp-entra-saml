"""Checks against a live Captive Portal, as an anonymous browser would see it.

Nothing here signs in. It reads the pages the portal serves before login and
follows the first SAML redirect far enough to decode the request the gateway
would send to the identity provider.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Dict, List, Optional

from . import httpc, saml

REALM = "identity_portal"
_JS_VAR = re.compile(r"var\s+(urls|names|idps_types|idps_ids)\s*=\s*(\[.*?\]);", re.S)
_ASSET = re.compile(r'href="([^"]*)/css/Blob_static\.css"')
_KNOWN_PAGES = ("/PortalMain", "/Access", "/Login", "/Logoff")


class PortalError(Exception):
    pass


def normalize_base(url: str) -> str:
    """'https://host/connect/PortalMain' or 'https://host/' -> the portal base without a trailing slash."""
    u = urllib.parse.urlsplit(url.strip())
    if u.scheme != "https" or not u.hostname:
        raise PortalError("the portal address must be an https:// URL, for example https://portal.example.com/connect")
    path = u.path.rstrip("/")
    for page in _KNOWN_PAGES:
        if path.endswith(page):
            path = path[: -len(page)]
            break
    return urllib.parse.urlunsplit((u.scheme, u.netloc, path, "", ""))


def path_prefix(base: str) -> str:
    """'' for a portal at the root of its host, '/connect' for the default publication."""
    return urllib.parse.urlsplit(base).path


class _Session:
    """Carries the portal's session cookie between requests."""

    def __init__(self, client: httpc.Client):
        self.client = client
        self.cookies: Dict[str, str] = {}

    def request(self, method: str, url: str, body: Optional[bytes] = None,
                headers: Optional[Dict[str, str]] = None) -> httpc.Response:
        h = dict(headers or {})
        if self.cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        r = self.client.request(method, url, headers=h, body=body)
        for sc in r.header_all("Set-Cookie"):
            first = sc.split(";", 1)[0]
            if "=" in first:
                k, v = first.split("=", 1)
                self.cookies[k.strip()] = v.strip()
        return r


def _finding(fid: str, severity: str, title: str, detail: str, fix: str = "") -> dict:
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}


def check(portal_url: str, client: httpc.Client) -> dict:
    base = normalize_base(portal_url)
    prefix = path_prefix(base)
    host = urllib.parse.urlsplit(base).hostname or ""
    findings: List[dict] = []
    report: dict = {"portal": base, "path_prefix": prefix or "/", "findings": findings, "identity_providers": []}
    s = _Session(client)

    r = s.request("GET", base + "/PortalMain")
    hops = 0
    while r.status in (301, 302, 303, 307, 308) and hops < 3:
        loc = urllib.parse.urljoin(r.url, r.header("Location") or "")
        if urllib.parse.urlsplit(loc).hostname != host:
            break
        r = s.request("GET", loc)
        hops += 1
    report["portal_main_status"] = r.status
    page = r.text()
    if r.status != 200 or "PORTAL_IS" not in page:
        findings.append(_finding(
            "not-a-captive-portal", "error", "No Captive Portal answered at %s/PortalMain (HTTP %s)" % (base, r.status),
            "Check the address, including the path. The default publication is https://<gateway>/connect."))
        return report

    m = _ASSET.search(page)
    if m is not None and m.group(1) != prefix:
        findings.append(_finding(
            "prefix-differs", "warning",
            "The portal generates links under %r but was opened under %r" % (m.group(1) or "/", prefix or "/"),
            "A reverse proxy or an alias in front of the gateway is rewriting the path. SAML values are built from "
            "the Main URL configured on the gateway, not from the address used here."))

    r = s.request("POST", base + "/LoginSettings", body=b"",
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        settings = json.loads(r.text().strip())
    except ValueError:
        settings = {}
        findings.append(_finding("login-settings-unreadable", "warning",
                                 "The portal's LoginSettings answer could not be read (HTTP %s)" % r.status, ""))
    report["login_settings"] = settings
    saml_on = bool(settings.get("samlAuthEnabled"))
    if settings and not saml_on:
        findings.append(_finding(
            "saml-off", "info", "SAML sign-in is not enabled on this portal",
            "The portal offers %s." % ("user name and password" if settings.get("passwordLoginEnabled") else "no SAML login"),
            "Set the portal's authentication method to an identity provider and install policy."))
        return report

    if saml_on:
        r = s.request("GET", base + "/spPortal/IdentityProviders?Realm=" + REALM)
        js: Dict[str, list] = {}
        for name, value in _JS_VAR.findall(r.text()):
            try:
                js[name] = json.loads(value)
            except ValueError:
                js[name] = []
        ids = js.get("idps_ids") or []
        if r.status != 200 or not ids:
            findings.append(_finding(
                "no-identity-providers", "error", "SAML is enabled but the portal lists no identity provider",
                "GET %s/spPortal/IdentityProviders returned HTTP %s." % (base, r.status),
                "Attach an identity provider object to the portal's authentication settings and install policy."))
        for i, idp_id in enumerate(ids):
            idp = {"id": idp_id,
                   "name": (js.get("names") or [None] * len(ids))[i] if i < len(js.get("names") or []) else None,
                   "login_url": (js.get("urls") or [None] * len(ids))[i] if i < len(js.get("urls") or []) else None}
            q = urllib.parse.urlencode({"idpId": idp_id, "realm": REALM})
            rr = s.request("GET", base + "/spPortal/ServiceProvider?" + q)
            loc = rr.header("Location") or ""
            if rr.status in (302, 303) and "SAMLRequest=" in loc:
                try:
                    req = saml.decode_redirect_request(loc)
                    idp.update({"entity_id": req["issuer"], "reply_url": req["acs_url"],
                                "destination": req["destination"], "nameid_format": req["nameid_format"]})
                    acs = urllib.parse.urlsplit(req["acs_url"] or "")
                    if acs.hostname and acs.hostname.lower() != host.lower():
                        findings.append(_finding(
                            "acs-host-differs", "warning",
                            "The gateway's Reply URL uses host %s, not %s" % (acs.hostname, host),
                            "The identity provider will send the browser to %s after sign-in. Users must be able to "
                            "reach the portal under that name, and the portal session started under the other name "
                            "will not be found." % acs.hostname,
                            "Set the portal Main URL on the gateway to the address users actually open."))
                except saml.SamlError as e:
                    idp["error"] = str(e)
            else:
                idp["error"] = "expected a redirect to the identity provider, got HTTP %s" % rr.status
                findings.append(_finding(
                    "no-saml-redirect", "error",
                    "The portal did not redirect to identity provider %s" % (idp["name"] or idp_id), idp["error"]))
            report["identity_providers"].append(idp)

        if prefix == "":
            findings.append(_finding(
                "root-publication", "error",
                "SAML sign-in is likely to fail after the identity provider: this portal is published at the root of its host",
                "Seen on a gateway published this way: after the assertion is accepted, the gateway's hand-off page "
                "posts the login to nacUrl + \"/Login\". At the root nacUrl is \"/\" and the result is \"//Login\", "
                "which a browser sends to a host named \"login\"; the user ends on a blank page with no session. "
                "Check Point does not document this, and a hotfix may have changed it on your version, so confirm "
                "with one test sign-in and, if it fails, a capture: cp-entra-saml har <file>.",
                "Publish the portal under a path (Main URL https://%s/connect), install policy, and update the "
                "Identifier and Reply URL at the identity provider." % host))
    return report


def render(report: dict) -> str:
    lines: List[str] = []
    w = lines.append
    w("Portal: %s   (path prefix: %s)" % (report["portal"], report["path_prefix"]))
    ls = report.get("login_settings")
    if ls:
        w("Login methods: password %s, SAML %s" % ("on" if ls.get("passwordLoginEnabled") else "off",
                                                    "on" if ls.get("samlAuthEnabled") else "off"))
    for idp in report.get("identity_providers", []):
        w("")
        w("Identity provider: %s (%s)" % (idp.get("name") or "?", idp["id"]))
        if idp.get("error"):
            w("  error: %s" % idp["error"])
            continue
        w("  Sign-in URL:            %s" % idp.get("destination"))
        w("  Entity ID (Identifier): %s" % idp.get("entity_id"))
        w("  Reply URL (ACS):        %s" % idp.get("reply_url"))
        w("  NameID format asked:    %s" % (idp.get("nameid_format") or "none"))
    w("")
    w("Findings")
    if not report["findings"]:
        w("  none")
    order = {"error": 0, "warning": 1, "info": 2}
    for f in sorted(report["findings"], key=lambda x: order.get(x["severity"], 3)):
        w("  [%s] %s" % (f["severity"].upper(), f["title"]))
        if f.get("detail"):
            w("      " + f["detail"])
        if f.get("fix"):
            w("      Fix: " + f["fix"])
    return "\n".join(lines) + "\n"
