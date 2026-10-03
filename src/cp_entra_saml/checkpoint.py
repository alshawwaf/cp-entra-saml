"""Check Point Management Web API: the calls needed to attach a SAML identity
provider to a gateway's Captive Portal (Browser-Based Authentication)."""
from __future__ import annotations

import base64
import time
from typing import Dict, List, Optional, Tuple

from . import httpc

IA_SERVICE = "identity awareness"
METHOD_IDP = "identity provider"
_AUTH_PATH = ("identity-awareness-settings", "browser-based-authentication-settings", "authentication-settings")
_WEB_PATH = ("identity-awareness-settings", "browser-based-authentication-settings",
             "browser-based-authentication-portal-settings", "portal-web-settings")


class ApiError(Exception):
    def __init__(self, command: str, status: int, payload: dict):
        self.command = command
        self.status = status
        self.code = str(payload.get("code") or "")
        self.payload = payload
        parts = [str(payload.get("message") or "HTTP %d" % status)]
        for key in ("blocking-errors", "errors", "warnings"):
            for item in payload.get(key) or []:
                msg = item.get("message") if isinstance(item, dict) else str(item)
                if msg:
                    parts.append("%s: %s" % (key[:-1], msg))
        super().__init__("%s failed: %s" % (command, "; ".join(parts)))


class TaskFailed(Exception):
    pass


class Unsupported(Exception):
    """The management server's API does not have what this tool needs."""


def _dig(obj: dict, path: Tuple[str, ...]):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _names(value) -> List[str]:
    """API replies give object references as names, or as objects with a name."""
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    out = []
    for v in value:
        if isinstance(v, dict):
            v = v.get("name") or v.get("uid")
        if v:
            out.append(str(v))
    return out


class Management:
    def __init__(self, server: str, client: httpc.Client, domain: Optional[str] = None):
        server = server.strip()
        if "://" in server:
            server = server.split("://", 1)[1]
        self.base = "https://%s/web_api/" % server.strip("/")
        self.client = client
        self.domain = domain
        self.sid: Optional[str] = None
        self.api_version: Optional[str] = None
        self.changed = False

    # -- session --------------------------------------------------------------
    def call(self, command: str, payload: Optional[dict] = None) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.sid:
            headers["X-chkp-sid"] = self.sid
        r = self.client.request("POST", self.base + command, headers=headers, json_body=payload or {})
        try:
            data = r.json() if r.body else {}
        except ValueError:
            data = {"message": "the server did not answer with JSON (HTTP %d). Is this a management server with "
                               "the API enabled for this client address?" % r.status}
        if r.status != 200:
            raise ApiError(command, r.status, data if isinstance(data, dict) else {"message": str(data)})
        return data

    def login(self, api_key: Optional[str] = None, user: Optional[str] = None,
              password: Optional[str] = None, read_only: bool = False) -> None:
        body: dict = {"session-name": "cp-entra-saml",
                      "session-description": "SAML identity provider for the Captive Portal"}
        if api_key:
            body["api-key"] = api_key
        elif user and password:
            body["user"], body["password"] = user, password
        else:
            raise ValueError("an API key, or a user name and password, is required")
        if self.domain:
            body["domain"] = self.domain
        if read_only:
            body["read-only"] = True
        reply = self.call("login", body)
        self.sid = reply["sid"]
        self.api_version = reply.get("api-server-version")

    def logout(self, discard: bool = False) -> None:
        if not self.sid:
            return
        try:
            if discard and self.changed:
                self.call("discard")
            self.call("logout")
        except (ApiError, httpc.HttpError):
            pass
        finally:
            self.sid = None

    def require_identity_provider_api(self) -> None:
        try:
            self.call("show-identity-providers", {"limit": 1})
        except ApiError as e:
            if e.status == 404 or "not_found" in e.code or "unknown" in e.code:
                raise Unsupported(
                    "this management server (API version %s) has no identity-provider commands. Create the "
                    "Identity Provider object in SmartConsole instead; the rest of this tool still applies."
                    % (self.api_version or "unknown")) from e
            raise

    # -- tasks ----------------------------------------------------------------
    def wait_task(self, task_id: str, what: str, timeout: float = 900.0) -> dict:
        deadline = time.time() + timeout
        delay = 2.0
        while True:
            reply = self.call("show-task", {"task-id": task_id, "details-level": "full"})
            tasks = reply.get("tasks") or []
            status = {str(t.get("status") or "").lower() for t in tasks}
            if tasks and "in progress" not in status and "pending" not in status:
                bad = [t for t in tasks if str(t.get("status") or "").lower() not in ("succeeded", "succeeded with warnings")]
                if bad:
                    raise TaskFailed("%s did not succeed: %s" % (what, "; ".join(_task_messages(bad)) or ", ".join(sorted(status))))
                return reply
            if time.time() > deadline:
                raise TaskFailed("%s is still running after %d seconds (task %s)" % (what, int(timeout), task_id))
            time.sleep(delay)
            delay = min(delay + 1.0, 8.0)

    def publish(self) -> None:
        reply = self.call("publish")
        if reply.get("task-id"):
            self.wait_task(reply["task-id"], "publish", timeout=300.0)
        self.changed = False

    def install_policy(self, package: str, targets: List[str]) -> None:
        reply = self.call("install-policy", {"policy-package": package, "targets": targets,
                                             "access": True, "threat-prevention": False})
        self.wait_task(reply["task-id"], "policy installation")

    # -- gateway --------------------------------------------------------------
    def show_gateway(self, name: str) -> Tuple[str, dict]:
        """Returns ('simple-gateway' | 'simple-cluster', object)."""
        last: Optional[ApiError] = None
        for kind in ("simple-gateway", "simple-cluster"):
            try:
                return kind, self.call("show-" + kind, {"name": name})
            except ApiError as e:
                last = e
                if "not_found" not in e.code and e.status != 404:
                    raise
        raise ApiError("show-simple-gateway", last.status if last else 404,
                       {"message": "no gateway or cluster object named %r" % name})

    @staticmethod
    def portal_state(gateway: dict) -> dict:
        auth = _dig(gateway, _AUTH_PATH) or {}
        web = _dig(gateway, _WEB_PATH) or {}
        ia = gateway.get("identity-awareness-settings") or {}
        return {
            "identity_awareness": bool(gateway.get("identity-awareness")),
            "browser_based_authentication": bool(ia.get("browser-based-authentication")),
            "method": auth.get("authentication-method"),
            "identity_providers": _names(auth.get("identity-provider")),
            "users_directories": auth.get("users-directories"),
            "main_url": web.get("main-url"),
        }

    def set_portal_identity_providers(self, kind: str, name: str, identity_providers: List[str]) -> None:
        self.call("set-" + kind, {"name": name, "identity-awareness-settings": {
            "browser-based-authentication-settings": {"authentication-settings": {
                "authentication-method": METHOD_IDP, "identity-provider": identity_providers}}}})
        self.changed = True

    def set_portal_method(self, kind: str, name: str, method: str) -> None:
        self.call("set-" + kind, {"name": name, "identity-awareness-settings": {
            "browser-based-authentication-settings": {"authentication-settings": {"authentication-method": method}}}})
        self.changed = True

    # -- identity provider object ----------------------------------------------
    def show_identity_provider(self, name: str) -> Optional[dict]:
        try:
            return self.call("show-identity-provider", {"name": name})
        except ApiError as e:
            if "not_found" in e.code or e.status == 404:
                return None
            raise

    def list_identity_providers(self) -> List[dict]:
        out: List[dict] = []
        offset = 0
        while True:
            reply = self.call("show-identity-providers", {"limit": 100, "offset": offset, "details-level": "full"})
            objs = reply.get("objects") or []
            out.extend(objs)
            offset += len(objs)
            if not objs or offset >= int(reply.get("total") or 0):
                return out

    def put_identity_provider(self, name: str, gateway: str, metadata_xml: bytes, comments: str = "") -> dict:
        """Create the object, or refresh the metadata of an existing one. Returns the object."""
        fields = {"data-receiving": "metadata_file",
                  "base64-metadata-file": base64.b64encode(metadata_xml).decode("ascii")}
        existing = self.show_identity_provider(name)
        if existing is None:
            body = {"name": name, "usage": "gateway_policy_and_logs", "gateway": gateway, "service": IA_SERVICE}
            body.update(fields)
            if comments:
                body["comments"] = comments
            reply = self.call("add-identity-provider", body)
        else:
            current_gw = _names(existing.get("gateway"))
            if existing.get("service") != IA_SERVICE or (current_gw and current_gw[0] != gateway):
                raise ApiError("set-identity-provider", 409, {"message": (
                    "an identity provider object named %r already exists for %s on %s; choose another name"
                    % (name, existing.get("service"), ", ".join(current_gw) or "no gateway"))})
            body = {"name": name}
            body.update(fields)
            reply = self.call("set-identity-provider", body)
        self.changed = True
        return reply

    def delete_identity_provider(self, name: str) -> None:
        self.call("delete-identity-provider", {"name": name})
        self.changed = True


def service_provider_values(idp_object: dict) -> Dict[str, object]:
    """The two values the identity provider must be given."""
    urls = idp_object.get("reply-urls") or []
    if isinstance(urls, str):
        urls = [urls]
    return {"entity_id": idp_object.get("required-identifier"), "reply_urls": [u for u in urls if u]}


def _task_messages(tasks: List[dict]) -> List[str]:
    out = []
    for t in tasks:
        label = "%s (%s)" % (t.get("task-name") or "task", t.get("status"))
        details = []
        for d in t.get("task-details") or []:
            if not isinstance(d, dict):
                continue
            for key in ("fault-message", "statusDescription", "status-description"):
                if d.get(key):
                    details.append(str(d[key]))
            for stage in d.get("stagesInfo") or []:
                for m in stage.get("messages") or []:
                    if m.get("message"):
                        details.append(str(m["message"]))
        if t.get("comments"):
            details.append(str(t["comments"]))
        out.append(label + (": " + " | ".join(dict.fromkeys(details)) if details else ""))
    return out
