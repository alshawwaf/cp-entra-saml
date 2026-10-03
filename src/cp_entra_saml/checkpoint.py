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


def _dig(obj, path: Tuple[str, ...]):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def names(value) -> List[str]:
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


def is_idp_method(value) -> bool:
    """Replies do not spell enum values the way requests do ('user_pass' for 'username and password',
    'defined_on_user' for 'defined on user record'), so recognise the identity provider method loosely."""
    v = str(value or "").lower().replace("_", " ").replace("-", " ").strip()
    return ("identity" in v and "provider" in v) or v in ("idp", "saml")


_REQUEST_METHODS = {"username and password": "username and password",
                    "user pass": "username and password",
                    "defined on user": "defined on user record",
                    "defined on user record": "defined on user record"}


def request_method(reply_value) -> Optional[str]:
    """The request spelling of a method read from a reply, or None when it cannot be restated
    safely (RADIUS needs its server named again; unknown values are never guessed)."""
    v = str(reply_value or "").lower().replace("_", " ").replace("-", " ").strip()
    return _REQUEST_METHODS.get(v)


def same_name(a: Optional[str], b: Optional[str]) -> bool:
    """Object names are case-insensitive on the management server."""
    return (a or "").casefold() == (b or "").casefold()


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
            data = None
        if not isinstance(data, dict):
            raise ApiError(command, r.status, {"message": (
                "the server did not answer with JSON (HTTP %d). Is this a management server, with the API "
                "enabled for this client address?" % r.status)})
        if r.status != 200:
            raise ApiError(command, r.status, data)
        return data

    def login(self, api_key: Optional[str] = None, user: Optional[str] = None,
              password: Optional[str] = None, read_only: bool = False) -> None:
        # The run can pause for a sign-in at the identity provider and a confirmation.
        body: dict = {"session-timeout": 3600}
        if not read_only:
            # A read-only login refuses a session name or description.
            body["session-name"] = "cp-entra-saml"
            body["session-description"] = "SAML identity provider for the Captive Portal"
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
        reply = None
        for wait in (10, 20, 0):
            try:
                reply = self.call("login", body)
                break
            except ApiError as e:
                text = str(e).lower()
                if "session-timeout" in text and "session-timeout" in body:
                    body.pop("session-timeout")
                    continue
                # The server limits how often one administrator may log in.
                if "too many requests" in text and wait:
                    time.sleep(wait)
                    continue
                raise
        if reply is None:
            reply = self.call("login", body)
        if not reply.get("sid"):
            raise ApiError("login", 200, {"message": "the server accepted the login but returned no session"})
        self.sid = reply["sid"]
        self.api_version = reply.get("api-server-version")

    def logout(self, discard: bool = False) -> None:
        if not self.sid:
            return
        try:
            if discard and self.changed:
                try:
                    self.call("discard")
                except (ApiError, httpc.HttpError):
                    pass
            try:
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
                    "Identity Provider object in SmartConsole instead; 'portal' and 'har' still apply."
                    % (self.api_version or "unknown")) from e
            raise

    def _mutate(self, command: str, payload: dict, what: str) -> dict:
        # Marked before sending: if the reply is lost the server may still have applied the change,
        # and the session must then be discarded rather than left holding locks.
        self.changed = True
        reply = self.call(command, payload)
        # Cluster edits are asynchronous: the reply is a task, a list of tasks, or the object itself.
        task_ids = [reply["task-id"]] if isinstance(reply.get("task-id"), str) else []
        task_ids += [t["task-id"] for t in reply.get("tasks") or [] if isinstance(t, dict) and t.get("task-id")]
        for task_id in task_ids:
            self.wait_task(task_id, what, timeout=300.0)
        return reply

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
        # Subtrees are absent, not empty, when the feature is off.
        auth = _dig(gateway, _AUTH_PATH) or {}
        web = _dig(gateway, _WEB_PATH) or {}
        ia = gateway.get("identity-awareness-settings") or {}
        method = auth.get("authentication-method")
        return {
            "name": gateway.get("name"),
            "identity_awareness": bool(gateway.get("identity-awareness")),
            "browser_based_authentication": bool(ia.get("browser-based-authentication")),
            "method": method,
            "uses_identity_provider": is_idp_method(method),
            "identity_providers": names(auth.get("identity-provider")),
            "users_directories": auth.get("users-directories"),
            "main_url": web.get("main-url"),
        }

    def _set_auth(self, kind: str, name: str, auth: dict) -> None:
        self._mutate("set-" + kind, {"name": name, "identity-awareness-settings": {
            "browser-based-authentication-settings": {"authentication-settings": auth}}}, "gateway update")

    def set_portal_identity_providers(self, kind: str, name: str, identity_providers: List[str]) -> None:
        # Method and list always travel together: the method has a default on the edit object.
        self._set_auth(kind, name, {"authentication-method": METHOD_IDP, "identity-provider": identity_providers})

    def set_portal_method(self, kind: str, name: str, method: str) -> None:
        """Leave identity-provider mode. The list is emptied too, so that no object stays referenced."""
        try:
            self._set_auth(kind, name, {"authentication-method": method, "identity-provider": []})
        except ApiError as e:
            if e.status not in (400, 409):
                raise
            self._set_auth(kind, name, {"authentication-method": method})

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
            return self._mutate("add-identity-provider", body, "identity provider object")
        problem = foreign_identity_provider(existing, gateway)
        if problem:
            raise ApiError("set-identity-provider", 409, {"message": problem})
        body = {"name": name}
        body.update(fields)
        return self._mutate("set-identity-provider", body, "identity provider object")

    def delete_identity_provider(self, name: str) -> None:
        self._mutate("delete-identity-provider", {"name": name}, "identity provider object")


def foreign_identity_provider(obj: dict, gateway: str) -> Optional[str]:
    """Why an existing object must not be reused for this gateway's portal, or None when it may."""
    owner = names(obj.get("gateway"))
    if obj.get("service") == IA_SERVICE and (not owner or same_name(owner[0], gateway)):
        return None
    return ("an identity provider object named %r already exists for %s on %s; choose another name with --idp-name"
            % (obj.get("name"), obj.get("service") or "another service", ", ".join(owner) or "no gateway"))


def belongs_to_portal(obj: dict, gateway: str) -> bool:
    return obj.get("service") == IA_SERVICE and any(same_name(n, gateway) for n in names(obj.get("gateway")))


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
