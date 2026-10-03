import base64
import hashlib
import json
import os
import sys
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

import fixtures  # noqa: E402
from cp_entra_saml import entra, httpc  # noqa: E402


class FakeHttp:
    """Scripted answers per (METHOD, path). A list is consumed one answer per call."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, headers=None, body=None, json_body=None):
        u = urllib.parse.urlsplit(url)
        self.calls.append((method, u.path, json_body if json_body is not None else body, dict(headers or {})))
        answer = self.routes[(method, u.path)]
        if isinstance(answer, list):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        status, payload = answer
        raw = payload if isinstance(payload, bytes) else (b"" if payload is None else json.dumps(payload).encode())
        return httpc.Response(status, [], raw, url)

    def request_retry(self, method, url, attempts=4, idempotent=True, **kw):
        self.idempotent = getattr(self, "idempotent", []) + [(method, idempotent)]
        return self.request(method, url, **kw)

    def paths(self, method=None):
        return [c[1] for c in self.calls if method in (None, c[0])]


class NoSleep(unittest.TestCase):
    def setUp(self):
        self._sleep = time.sleep
        time.sleep = lambda s: None

    def tearDown(self):
        time.sleep = self._sleep


TENANT = "example.com"
TOKEN_PATH = "/%s/oauth2/v2.0/token" % TENANT
DEVICE = (200, {"device_code": "DC", "user_code": "ABCD-1234", "verification_uri": "https://microsoft.com/devicelogin",
                "interval": 1, "expires_in": 900})


class DeviceCode(NoSleep):
    def login(self, token_answers, **kw):
        http = FakeHttp({("POST", "/%s/oauth2/v2.0/devicecode" % TENANT): DEVICE, ("POST", TOKEN_PATH): token_answers})
        shown = []
        token = entra.device_code_login(http, TENANT, prompt=shown.append, **kw)
        return token, http, shown

    def test_waits_for_the_operator_then_returns_the_token(self):
        token, http, shown = self.login([(400, {"error": "authorization_pending"}), (400, {"error": "slow_down"}),
                                         (200, {"access_token": "AT"})])
        self.assertEqual(token, "AT")
        self.assertIn("ABCD-1234", shown[0])
        self.assertIn("https://microsoft.com/devicelogin", shown[0])
        self.assertEqual(len(http.paths("POST")), 4)

    def test_requests_only_the_scopes_it_was_given(self):
        _, http, _ = self.login([(200, {"access_token": "AT"})], scopes=entra.SCOPES_BASE)
        sent = urllib.parse.parse_qs(http.calls[0][2].decode())["scope"][0]
        self.assertIn("Application.ReadWrite.All", sent)
        self.assertNotIn("AppRoleAssignment", sent)

    def test_declined(self):
        with self.assertRaises(entra.AuthError) as cm:
            self.login([(400, {"error": "authorization_declined"})])
        self.assertIn("declined", str(cm.exception))

    def test_policy_block_points_to_the_alternatives(self):
        with self.assertRaises(entra.AuthError) as cm:
            self.login([(400, {"error": "invalid_grant", "error_description": "AADSTS53003: Access has been blocked\r\nTrace ID: x"})])
        self.assertIn("AADSTS53003", str(cm.exception))
        self.assertIn("--login browser", str(cm.exception))
        self.assertNotIn("Trace ID", str(cm.exception))

    def test_device_code_is_never_shown(self):
        _, _, shown = self.login([(200, {"access_token": "AT"})])
        self.assertNotIn("DC", " ".join(shown).split())


def graph(routes):
    http = FakeHttp(routes)
    return entra.Graph(http, "TOKEN"), http


class Application(NoSleep):
    def test_every_call_is_authenticated(self):
        g, http = graph({("GET", "/v1.0/organization"): (200, {"value": [{"id": "T", "displayName": "X",
                                                                         "verifiedDomains": [{"name": "x.com", "isDefault": True}]}]})})
        self.assertEqual(g.tenant(), {"id": "T", "name": "X", "domain": "x.com"})
        self.assertEqual(http.calls[0][3]["Authorization"], "Bearer TOKEN")

    def test_two_applications_with_the_same_name_stop_the_run(self):
        g, _ = graph({("GET", "/v1.0/applications"): (200, {"value": [{"id": "1"}, {"id": "2"}]})})
        with self.assertRaises(entra.GraphError):
            g.find_application("App")

    def test_create_waits_until_the_new_objects_can_be_read(self):
        made = {"application": {"id": "obj", "appId": "app"}, "servicePrincipal": {"id": "sp"}}
        g, http = graph({
            ("POST", "/v1.0/applicationTemplates/%s/instantiate" % entra.NON_GALLERY_TEMPLATE): (201, made),
            ("GET", "/v1.0/servicePrincipals/sp"): [(404, {"error": {"code": "Request_ResourceNotFound"}}), (200, {"id": "sp"})],
            ("GET", "/v1.0/applications/obj"): (200, {"id": "obj"}),
        })
        out = g.create_saml_application("App")
        self.assertEqual(out["application"]["appId"], "app")
        self.assertEqual(http.paths("GET").count("/v1.0/servicePrincipals/sp"), 2)

    def test_existing_certificate_is_reused(self):
        g, http = graph({("GET", "/v1.0/servicePrincipals/sp"): (200, {"preferredTokenSigningKeyThumbprint": "AA"})})
        self.assertEqual(g.ensure_signing_certificate("sp", "App"), "AA")
        self.assertEqual(http.paths("POST"), [])

    def test_new_certificate_is_created_and_activated(self):
        g, http = graph({
            ("GET", "/v1.0/servicePrincipals/sp"): (200, {"preferredTokenSigningKeyThumbprint": None}),
            ("POST", "/v1.0/servicePrincipals/sp/addTokenSigningCertificate"): (200, {"thumbprint": "BB"}),
            ("PATCH", "/v1.0/servicePrincipals/sp"): (204, None),
        })
        self.assertEqual(g.ensure_signing_certificate("sp", "Check Point (GW), test"), "BB")
        post = [c for c in http.calls if c[0] == "POST"][0]
        self.assertTrue(post[2]["displayName"].startswith("CN="))
        self.assertNotIn(",", post[2]["displayName"])
        self.assertEqual([c[2] for c in http.calls if c[0] == "PATCH"], [{"preferredTokenSigningKeyThumbprint": "BB"}])

    def test_sign_on_url_failure_does_not_stop_saml_mode(self):
        g, http = graph({("PATCH", "/v1.0/servicePrincipals/sp"): [(204, None), (400, {"error": {"code": "x", "message": "no"}})]})
        g.enable_saml("sp", "https://gw/connect")
        self.assertEqual(http.calls[0][2], {"preferredSingleSignOnMode": "saml"})


class Metadata(NoSleep):
    def test_waits_for_the_applications_own_certificate(self):
        ours = hashlib.sha1(base64.b64decode(fixtures.CERT_B64)).hexdigest().upper()
        stale = fixtures.metadata_xml().replace(fixtures.CERT_B64.encode(), base64.b64encode(b"tenant default"))
        path = "/T/federationmetadata/2007-06/federationmetadata.xml"
        g, http = graph({("GET", path): [(200, stale), (200, stale), (200, fixtures.metadata_xml())]})
        xml = g.federation_metadata("T", "app", ours)
        self.assertEqual(xml, fixtures.metadata_xml())
        self.assertEqual(len(http.calls), 3)
        self.assertNotIn("Authorization", http.calls[0][3])


class ServiceProviderValues(NoSleep):
    ROUTES = {}

    def routes(self, extra):
        merged = dict(self.ROUTES)
        merged.update(extra)
        return merged

    def test_only_the_identifier_and_reply_url_are_sent(self):
        g, http = graph(self.routes({("PATCH", "/v1.0/applications/obj"): (204, None)}))
        g.set_service_provider("obj", "https://gw/id", ["https://gw/acs"])
        body = [c[2] for c in http.calls if c[0] == "PATCH"][0]
        self.assertEqual(body["identifierUris"], ["https://gw/id"])
        # Nothing read back from the application is echoed: PATCH merges, and stale entries would conflict.
        self.assertEqual(body, {"identifierUris": ["https://gw/id"], "web": {"redirectUris": ["https://gw/acs"]}})
        self.assertEqual(http.paths("GET"), [])

    def test_retries_while_saml_mode_is_still_propagating(self):
        refused = (400, {"error": {"code": "HostNameNotOnVerifiedDomain", "message": "Failed to add identifier URI https://gw/id"}})
        g, http = graph(self.routes({("PATCH", "/v1.0/applications/obj"): [refused, (204, None)],
                                    ("PATCH", "/v1.0/servicePrincipals/sp"): (204, None)}))
        g.set_service_provider("obj", "https://gw/id", ["https://gw/acs"], sp_id="sp")
        self.assertEqual(http.paths("PATCH"), ["/v1.0/applications/obj", "/v1.0/servicePrincipals/sp", "/v1.0/applications/obj"])

    def test_other_errors_are_not_retried(self):
        g, http = graph(self.routes({("PATCH", "/v1.0/applications/obj"): (403, {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}})}))
        with self.assertRaises(entra.GraphError) as cm:
            g.set_service_provider("obj", "https://gw/id", ["https://gw/acs"], sp_id="sp")
        self.assertIn("consent", str(cm.exception))
        self.assertEqual(len(http.paths("PATCH")), 1)


class Assignment(NoSleep):
    ROLES = (200, {"appRoles": [
        {"id": "role-access", "displayName": "msiam_access", "isEnabled": True, "allowedMemberTypes": ["User"]},
        {"id": "role-user", "displayName": "User", "isEnabled": True, "allowedMemberTypes": ["User"]}]})

    def test_assigns_with_the_user_role(self):
        g, http = graph({("GET", "/v1.0/servicePrincipals/sp/appRoleAssignedTo"): (200, {"value": []}),
                         ("GET", "/v1.0/servicePrincipals/sp"): self.ROLES,
                         ("POST", "/v1.0/servicePrincipals/sp/appRoleAssignedTo"): (201, {"id": "a1"})})
        self.assertTrue(g.assign("sp", "user1"))
        self.assertEqual(http.calls[-1][2], {"principalId": "user1", "resourceId": "sp", "appRoleId": "role-user"})

    def test_existing_assignment_is_left_alone(self):
        g, http = graph({("GET", "/v1.0/servicePrincipals/sp/appRoleAssignedTo"): (200, {"value": [{"principalId": "user1"}]})})
        self.assertFalse(g.assign("sp", "user1"))
        self.assertEqual(http.paths("POST"), [])

    def test_user_is_resolved_by_upn_and_group_by_name(self):
        g, _ = graph({("GET", "/v1.0/users/a@x.com"): (200, {"id": "u", "userPrincipalName": "a@x.com"}),
                      ("GET", "/v1.0/groups"): (200, {"value": [{"id": "g", "displayName": "VPN Users"}]})})
        self.assertEqual(g.resolve_principal("a@x.com")["kind"], "user")
        self.assertEqual(g.resolve_principal("VPN Users"), {"id": "g", "name": "VPN Users", "kind": "group"})

    def test_object_id_is_looked_up_as_user_then_group(self):
        gid = "11111111-2222-3333-4444-555555555555"
        g, http = graph({("GET", "/v1.0/users/" + gid): (404, {"error": {"code": "Request_ResourceNotFound"}}),
                         ("GET", "/v1.0/groups/" + gid): (200, {"id": gid, "displayName": "VPN Users"})})
        self.assertEqual(g.resolve_principal(gid), {"id": gid, "name": "VPN Users", "kind": "group"})

    def test_ambiguous_group_name_is_refused(self):
        g, _ = graph({("GET", "/v1.0/groups"): (200, {"value": [{"id": "1"}, {"id": "2"}]})})
        with self.assertRaises(entra.GraphError):
            g.resolve_principal("Sales")


class Retries(NoSleep):
    def test_a_post_whose_answer_is_lost_is_not_sent_again(self):
        made = {"application": {"id": "obj", "appId": "app"}, "servicePrincipal": {"id": "sp"}}
        g, http = graph({("POST", "/v1.0/applicationTemplates/%s/instantiate" % entra.NON_GALLERY_TEMPLATE): (201, made),
                         ("GET", "/v1.0/servicePrincipals/sp"): (200, {"id": "sp"}),
                         ("GET", "/v1.0/applications/obj"): (200, {"id": "obj"})})
        g.create_saml_application("App")
        self.assertIn(("POST", False), http.idempotent)
        self.assertIn(("GET", True), http.idempotent)

    def test_device_code_survives_a_transient_token_endpoint_failure(self):
        http = FakeHttp({("POST", "/%s/oauth2/v2.0/devicecode" % TENANT): DEVICE,
                         ("POST", TOKEN_PATH): [(503, b"<html>busy</html>"), (400, {"error": "temporarily_unavailable"}),
                                                (200, {"access_token": "AT"})]})
        self.assertEqual(entra.device_code_login(http, TENANT, prompt=lambda m: None), "AT")


class Removal(NoSleep):
    def test_application_first_then_leftover_service_principal(self):
        g, http = graph({("DELETE", "/v1.0/applications/obj"): (204, None),
                         ("DELETE", "/v1.0/servicePrincipals/sp"): (404, {"error": {"code": "Request_ResourceNotFound"}})})
        g.delete_application("obj", "sp")
        self.assertEqual(http.paths("DELETE"), ["/v1.0/applications/obj", "/v1.0/servicePrincipals/sp"])


if __name__ == "__main__":
    unittest.main()
