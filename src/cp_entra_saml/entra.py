"""Microsoft Entra ID through Microsoft Graph: an enterprise application with
SAML single sign-on, built without the portal.

Sign-in is interactive and happens at Microsoft: either the device code flow
(the operator opens a Microsoft page and enters a short code) or the browser
flow (authorization code with PKCE). This module never sees a password.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets
import subprocess
import sys
import time
import urllib.parse
import webbrowser
from typing import Callable, Dict, List, Optional

from . import httpc, saml

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
# "Microsoft Graph Command Line Tools", Microsoft's own public client for delegated Graph access.
DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
# Template behind "Create your own application > Integrate any other application (Non-gallery)".
NON_GALLERY_TEMPLATE = "8adf8e6e-67b2-4cf2-a259-e3dc5476c621"
# Every scope except User.Read needs admin consent in the tenant. Application.ReadWrite.All and
# AppRoleAssignment.ReadWrite.All are high-privilege; the second is requested only when assigning.
SCOPES_BASE = ("User.Read", "Application.ReadWrite.All")
SCOPES_READ = ("User.Read", "Application.Read.All")
SCOPES_ASSIGN = ("AppRoleAssignment.ReadWrite.All", "User.ReadBasic.All", "Group.Read.All")
NOTE = "Managed by cp-entra-saml"
BLOCKED_HINT = ("If the tenant blocks the device code flow (Conditional Access), sign in with --login browser, "
                "or with --use-az-cli after 'az login'.")


class GraphError(Exception):
    def __init__(self, method: str, url: str, status: int, payload):
        self.status = status
        err = payload.get("error") if isinstance(payload, dict) else None
        self.code = (err or {}).get("code", "") if isinstance(err, dict) else ""
        message = (err or {}).get("message", "") if isinstance(err, dict) else str(payload)[:300]
        hint = ""
        if status == 403:
            hint = (" (the signed-in account or the token lacks the permission for this step; an administrator "
                    "must consent to the requested Microsoft Graph permissions)")
        super().__init__("Microsoft Graph %s %s -> HTTP %d %s: %s%s"
                         % (method, urllib.parse.urlsplit(url).path, status, self.code, message, hint))


class AuthError(Exception):
    pass


# -- tokens ---------------------------------------------------------------------
def _scope(scopes) -> str:
    return " ".join("https://graph.microsoft.com/" + s for s in scopes)


def device_code_login(client: httpc.Client, tenant: str, client_id: str = DEFAULT_CLIENT_ID,
                      scopes=SCOPES_BASE, prompt: Optional[Callable[[str], None]] = None) -> str:
    """Returns an access token for Microsoft Graph."""
    base = "%s/%s/oauth2/v2.0" % (LOGIN, urllib.parse.quote(tenant, safe=""))
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    r = client.request("POST", base + "/devicecode", headers=form,
                       body=urllib.parse.urlencode({"client_id": client_id, "scope": _scope(scopes)}).encode())
    data = _json(r)
    if r.status != 200 or not data.get("device_code"):
        raise AuthError("Microsoft did not start the sign-in: %s" % _oauth_message(data))
    (prompt or _default_prompt)(
        "To sign in to Microsoft Entra, open %s and enter the code %s"
        % (data.get("verification_uri"), data.get("user_code")))
    interval = max(int(data.get("interval") or 5), 1)
    deadline = time.time() + int(data.get("expires_in") or 900)
    body = {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id, "device_code": data["device_code"]}
    while time.time() < deadline:
        time.sleep(interval)
        try:
            r = client.request("POST", base + "/token", headers=form, body=urllib.parse.urlencode(body).encode())
        except httpc.HttpError:
            interval = min(interval * 2, 30)  # network hiccup: keep waiting for the operator
            continue
        tok = _json(r)
        if r.status == 200 and tok.get("access_token"):
            return tok["access_token"]
        err = tok.get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        if err in ("authorization_declined", "access_denied"):
            raise AuthError("the sign-in was declined")
        if err == "expired_token":
            break
        if err == "temporarily_unavailable" or r.status in (429, 500, 502, 503, 504):
            interval = min(interval * 2, 30)
            continue
        raise AuthError("sign-in failed: %s. %s" % (_oauth_message(tok), BLOCKED_HINT))
    raise AuthError("the sign-in code expired before it was used; run the command again")


def browser_login(client: httpc.Client, tenant: str, client_id: str = DEFAULT_CLIENT_ID, scopes=SCOPES_BASE,
                  prompt: Optional[Callable[[str], None]] = None, timeout: float = 300.0) -> str:
    """Authorization code flow with PKCE and a one-shot listener on localhost.
    For tenants whose Conditional Access blocks the device code flow."""
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(24)
    got: Dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        timeout = 5  # a connection that sends nothing must not stall the wait

        def do_GET(self):  # noqa: N802 (name fixed by the base class)
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            # Anything on this machine can connect; only the redirect carrying our state counts.
            if not got and q.get("state", [""])[0] == state and ("code" in q or "error" in q):
                got.update({k: v[0] for k, v in q.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>You can close this window and return to the terminal.</body></html>")

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    try:
        redirect = "http://localhost:%d" % server.server_address[1]
        base = "%s/%s/oauth2/v2.0" % (LOGIN, urllib.parse.quote(tenant, safe=""))
        url = base + "/authorize?" + urllib.parse.urlencode({
            "client_id": client_id, "response_type": "code", "redirect_uri": redirect, "response_mode": "query",
            "scope": _scope(scopes), "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
            "prompt": "select_account"})
        (prompt or _default_prompt)("To sign in to Microsoft Entra, a browser window is opening. If it does not, open:\n" + url)
        try:
            webbrowser.open(url)
        except Exception:
            pass
        server.timeout = 1.0
        deadline = time.time() + timeout
        while not got and time.time() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    if not got:
        raise AuthError("no sign-in was completed in the browser within %d seconds" % int(timeout))
    if got.get("error"):
        raise AuthError("sign-in failed: %s. If the message is about the reply address, this client application "
                        "does not allow a localhost redirect; use --login device or your own --client-id."
                        % _oauth_message(got))
    r = client.request("POST", base + "/token", headers={"Content-Type": "application/x-www-form-urlencoded"},
                       body=urllib.parse.urlencode({"client_id": client_id, "grant_type": "authorization_code",
                                                    "code": got["code"], "redirect_uri": redirect,
                                                    "code_verifier": verifier}).encode())
    tok = _json(r)
    if r.status != 200 or not tok.get("access_token"):
        raise AuthError("sign-in failed: %s" % _oauth_message(tok))
    return tok["access_token"]


def azure_cli_token(tenant: Optional[str] = None) -> str:
    """Reuse an existing 'az login' session. Which Graph permissions that token carries is up to the
    Azure CLI; a 403 from Graph later means it is not enough for this tool."""
    exe = "az.cmd" if sys.platform == "win32" else "az"
    cmd = [exe, "account", "get-access-token", "--resource-type", "ms-graph", "--output", "json"]
    if tenant:
        cmd += ["--tenant", tenant]
    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise AuthError("could not run the Azure CLI: %s" % e) from e
    if out.returncode != 0:
        raise AuthError("the Azure CLI has no usable session: %s" % out.stderr.decode("utf-8", "replace").strip()[:300])
    try:
        return json.loads(out.stdout.decode("utf-8", "replace"))["accessToken"]
    except (ValueError, KeyError) as e:
        raise AuthError("unexpected output from the Azure CLI") from e


def _default_prompt(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _json(r: httpc.Response) -> dict:
    try:
        v = r.json()
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


def _oauth_message(data: dict) -> str:
    desc = str(data.get("error_description") or data.get("error") or "no detail").split("\r\n")[0]
    return desc.split("\n")[0][:400]


# -- Graph ----------------------------------------------------------------------
class Graph:
    def __init__(self, client: httpc.Client, token: str):
        self.client = client
        self.token = token

    def call(self, method: str, path: str, body=None, ok=(200, 201, 204)):
        url = path if path.startswith("https://") else GRAPH + path
        r = self.client.request_retry(method, url, idempotent=(method != "POST"),
                                      headers={"Authorization": "Bearer " + self.token}, json_body=body)
        data = None
        if r.body:
            try:
                data = r.json()
            except ValueError:
                data = {"error": {"message": r.text()[:300]}}
        if r.status not in ok:
            raise GraphError(method, url, r.status, data or {})
        return data

    def call_when_ready(self, method: str, path: str, body=None, wait: float = 120.0):
        """Objects created a moment ago can answer 404 for a while (directory replication)."""
        deadline = time.time() + wait
        delay = 2.0
        while True:
            try:
                return self.call(method, path, body)
            except GraphError as e:
                if e.status != 404 or time.time() > deadline:
                    raise
            time.sleep(delay)
            delay = min(delay * 1.5, 10.0)

    # -- tenant ---------------------------------------------------------------
    def tenant(self) -> dict:
        orgs = (self.call("GET", "/organization?$select=id,displayName,verifiedDomains") or {}).get("value") or []
        if not orgs:
            raise GraphError("GET", GRAPH + "/organization", 200, {"error": {"message": "no organization returned"}})
        o = orgs[0]
        default = [d.get("name") for d in o.get("verifiedDomains") or [] if d.get("isDefault")]
        return {"id": o["id"], "name": o.get("displayName"), "domain": default[0] if default else None}

    # -- application ----------------------------------------------------------
    def find_application(self, display_name: str) -> Optional[dict]:
        flt = urllib.parse.quote("displayName eq '%s'" % display_name.replace("'", "''"))
        apps = (self.call("GET", "/applications?$filter=%s&$select=id,appId,displayName,identifierUris,web,notes" % flt)
                or {}).get("value") or []
        if len(apps) > 1:
            raise GraphError("GET", GRAPH + "/applications", 200, {"error": {"message": (
                "%d applications are named %r; rename or remove the extras, or pick another --app-name"
                % (len(apps), display_name))}})
        return apps[0] if apps else None

    def service_principal_for(self, app_id: str) -> Optional[dict]:
        try:
            return self.call("GET", "/servicePrincipals(appId='%s')?$select=id,appId,displayName" % app_id)
        except GraphError as e:
            if e.status == 404:
                return None
            raise

    def create_saml_application(self, display_name: str) -> Dict[str, dict]:
        """Instantiate the non-gallery template: one application plus its service principal."""
        made = self.call("POST", "/applicationTemplates/%s/instantiate" % NON_GALLERY_TEMPLATE,
                         {"displayName": display_name})
        app, sp = made["application"], made["servicePrincipal"]
        self.call_when_ready("GET", "/servicePrincipals/%s?$select=id" % sp["id"])
        self.call_when_ready("GET", "/applications/%s?$select=id" % app["id"])
        return {"application": app, "servicePrincipal": sp}

    def enable_saml(self, sp_id: str, sign_on_url: Optional[str] = None) -> None:
        # This flag is also what lets the application carry an Identifier outside the tenant's own domains.
        self.call_when_ready("PATCH", "/servicePrincipals/%s" % sp_id, {"preferredSingleSignOnMode": "saml"})
        extras = {"notes": NOTE}
        if sign_on_url:
            extras["loginUrl"] = sign_on_url
        try:
            self.call("PATCH", "/servicePrincipals/%s" % sp_id, extras)
        except GraphError:
            pass  # only what the My Apps tile opens; sign-in from the portal does not depend on it

    def ensure_signing_certificate(self, sp_id: str, display_name: str) -> str:
        """Returns the thumbprint of the active SAML signing certificate, creating one if needed."""
        sp = self.call_when_ready("GET", "/servicePrincipals/%s?$select=id,preferredTokenSigningKeyThumbprint" % sp_id)
        thumb = sp.get("preferredTokenSigningKeyThumbprint")
        if thumb:
            return thumb
        cert = self.call_when_ready("POST", "/servicePrincipals/%s/addTokenSigningCertificate" % sp_id,
                                    {"displayName": "CN=" + _cn(display_name)})
        thumb = cert["thumbprint"]
        self.call_when_ready("PATCH", "/servicePrincipals/%s" % sp_id, {"preferredTokenSigningKeyThumbprint": thumb})
        return thumb

    def federation_metadata(self, tenant_id: str, app_id: str, thumbprint: Optional[str] = None,
                            wait: float = 180.0) -> bytes:
        """The application's own metadata. The endpoint answers 200 with the tenant's default
        certificates for an application it does not know yet, so wait for our certificate."""
        url = "%s/%s/federationmetadata/2007-06/federationmetadata.xml?appid=%s" % (LOGIN, tenant_id, app_id)
        want = (thumbprint or "").replace(":", "").upper()
        deadline = time.time() + wait
        while True:
            r = self.client.request_retry("GET", url)
            if r.status == 200 and b"IDPSSODescriptor" in r.body:
                if not want:
                    return r.body
                try:
                    certs = saml.parse_metadata(r.body)["signing_certificates"]
                except saml.SamlError:
                    certs = []
                if any(c["sha1"] == want for c in certs):
                    return r.body
            if time.time() > deadline:
                raise GraphError("GET", url, r.status, {"error": {"message": (
                    "the application's signing certificate has not appeared in its federation metadata yet; "
                    "run the command again in a minute")}})
            time.sleep(5)

    def set_service_provider(self, app_object_id: str, entity_id: str, reply_urls: List[str],
                             sp_id: Optional[str] = None) -> None:
        """Identifier (Entity ID) and Reply URL of the gateway, as generated by Check Point."""
        # Only the two properties: PATCH merges into "web", and echoing the rest back would carry stale entries.
        body = {"identifierUris": [entity_id], "web": {"redirectUris": list(reply_urls)}}
        deadline = time.time() + 120
        while True:
            try:
                self.call_when_ready("PATCH", "/applications/%s" % app_object_id, body)
                return
            except GraphError as e:
                # Until the SAML flag has replicated, Entra applies its verified-domain rule to the Identifier.
                text = str(e).lower()
                waiting = e.status == 400 and ("verified" in text or "identifier uri" in text or "api://" in text)
                if not waiting or time.time() > deadline:
                    raise
            if sp_id:
                self.call("PATCH", "/servicePrincipals/%s" % sp_id, {"preferredSingleSignOnMode": "saml"})
            time.sleep(10)

    # -- who may sign in --------------------------------------------------------
    def set_assignment_required(self, sp_id: str, required: bool) -> None:
        self.call("PATCH", "/servicePrincipals/%s" % sp_id, {"appRoleAssignmentRequired": required})

    def resolve_principal(self, ref: str) -> dict:
        """A user (UPN or object id) or a group (display name or object id)."""
        if _looks_like_guid(ref):
            for kind, path in (("user", "/users/%s?$select=id,userPrincipalName,displayName"),
                               ("group", "/groups/%s?$select=id,displayName")):
                try:
                    obj = self.call("GET", path % ref)
                except GraphError as e:
                    if e.status != 404:
                        raise
                    continue
                return {"id": obj["id"], "name": obj.get("userPrincipalName") or obj.get("displayName") or ref, "kind": kind}
            raise GraphError("GET", GRAPH + "/users/" + ref, 404,
                             {"error": {"message": "no user or group has the object id %s" % ref}})
        if "@" in ref:
            u = self.call("GET", "/users/%s?$select=id,userPrincipalName,displayName" % urllib.parse.quote(ref, safe="@"))
            return {"id": u["id"], "name": u.get("userPrincipalName") or ref, "kind": "user"}
        flt = urllib.parse.quote("displayName eq '%s'" % ref.replace("'", "''"))
        groups = (self.call("GET", "/groups?$filter=%s&$select=id,displayName" % flt) or {}).get("value") or []
        if len(groups) != 1:
            raise GraphError("GET", GRAPH + "/groups", 200, {"error": {"message": (
                "%d groups are named %r; pass the group's object id instead" % (len(groups), ref))}})
        return {"id": groups[0]["id"], "name": groups[0]["displayName"], "kind": "group"}

    def assign(self, sp_id: str, principal_id: str) -> bool:
        """Grant sign-in to the application. Returns False when the assignment already existed."""
        url = "/servicePrincipals/%s/appRoleAssignedTo?$select=id,principalId" % sp_id
        while url:
            page = self.call("GET", url) or {}
            if any(a.get("principalId") == principal_id for a in page.get("value") or []):
                return False
            url = page.get("@odata.nextLink")
        sp = self.call("GET", "/servicePrincipals/%s?$select=id,appRoles" % sp_id)
        roles = [r for r in sp.get("appRoles") or [] if r.get("isEnabled") and "User" in (r.get("allowedMemberTypes") or [])]
        user_role = [r for r in roles if (r.get("displayName") or "").lower() == "user"] or roles
        # The all-zero id is the "default access" role, valid only for applications that declare no roles.
        role_id = user_role[0]["id"] if user_role else "00000000-0000-0000-0000-000000000000"
        self.call("POST", "/servicePrincipals/%s/appRoleAssignedTo" % sp_id,
                  {"principalId": principal_id, "resourceId": sp_id, "appRoleId": role_id})
        return True

    # -- removal --------------------------------------------------------------
    def delete_application(self, app_object_id: str, sp_id: Optional[str]) -> None:
        """Deleting the application removes its enterprise application too; the second call is a safety net."""
        for path in ("/applications/%s" % app_object_id, "/servicePrincipals/%s" % sp_id if sp_id else None):
            if not path:
                continue
            try:
                self.call("DELETE", path)
            except GraphError as e:
                if e.status != 404:
                    raise


def _cn(display_name: str) -> str:
    """A certificate subject from an application name: no characters that need escaping in a DN."""
    safe = "".join(c if c.isalnum() or c in " -_." else " " for c in display_name)
    return " ".join(safe.split())[:60] or "cp-entra-saml"


def _looks_like_guid(value: str) -> bool:
    parts = value.split("-")
    return [len(p) for p in parts] == [8, 4, 4, 4, 12] and all(c in "0123456789abcdefABCDEF" for p in parts for c in p)
