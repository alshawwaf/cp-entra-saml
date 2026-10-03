import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cp_entra_saml import checkpoint, httpc  # noqa: E402


class FakeClient:
    """Answers Management API commands from a table; records what was asked."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def request(self, method, url, headers=None, body=None, json_body=None):
        command = url.rsplit("/", 1)[-1]
        self.calls.append((command, json_body, dict(headers or {})))
        answer = self.answers[command]
        if callable(answer):
            answer = answer(json_body)
        status, payload = answer if isinstance(answer, tuple) else (200, answer)
        return httpc.Response(status, [], json.dumps(payload).encode(), url)

    def commands(self):
        return [c[0] for c in self.calls]


def gateway(method="username and password", idps=None, main_url="https://gw.example.com/connect"):
    return {"name": "GW", "identity-awareness": True, "identity-awareness-settings": {
        "browser-based-authentication": True,
        "browser-based-authentication-settings": {
            "authentication-settings": {"authentication-method": method, "identity-provider": idps or []},
            "browser-based-authentication-portal-settings": {"portal-web-settings": {"main-url": main_url}}}}}


IDP_REPLY = {"name": "EntraID_GW", "service": "identity awareness", "gateway": {"name": "GW"},
             "required-identifier": "https://gw.example.com/connect/spPortal/ACS/ID/u1",
             "reply-urls": ["https://gw.example.com/connect/spPortal/ACS/Login/u1"]}
NOT_FOUND = (404, {"code": "generic_err_object_not_found", "message": "Requested object not found"})


def logged_in(answers):
    answers = dict({"login": {"sid": "SID1", "api-server-version": "2.2"}}, **answers)
    client = FakeClient(answers)
    m = checkpoint.Management("mgmt.example.com", client)
    m.login(api_key="k")
    return m, client


class Session(unittest.TestCase):
    def test_login_sends_key_and_later_calls_carry_the_session(self):
        m, client = logged_in({"show-identity-providers": {"objects": [], "total": 0}})
        m.require_identity_provider_api()
        self.assertEqual(client.calls[0][1]["api-key"], "k")
        self.assertNotIn("X-chkp-sid", client.calls[0][2])
        self.assertEqual(client.calls[1][2]["X-chkp-sid"], "SID1")
        self.assertEqual(m.api_version, "2.2")

    def test_domain_is_passed_on_a_multi_domain_server(self):
        client = FakeClient({"login": {"sid": "S"}})
        m = checkpoint.Management("https://mds.example.com:4434/", client, domain="Customer1")
        m.login(user="u", password="p")
        self.assertEqual(client.calls[0][1]["domain"], "Customer1")
        self.assertEqual(m.base, "https://mds.example.com:4434/web_api/")

    def test_old_management_is_reported_as_unsupported(self):
        m, _ = logged_in({"show-identity-providers": (404, {"code": "generic_err_command_not_found", "message": "x"})})
        with self.assertRaises(checkpoint.Unsupported):
            m.require_identity_provider_api()

    def test_error_message_includes_blocking_errors(self):
        m, _ = logged_in({"publish": (400, {"code": "err_validation_failed", "message": "Validation failed",
                                            "blocking-errors": [{"message": "Object X is locked"}]})})
        with self.assertRaises(checkpoint.ApiError) as cm:
            m.publish()
        self.assertIn("Object X is locked", str(cm.exception))

    def test_logout_discards_unpublished_changes(self):
        m, client = logged_in({"set-simple-gateway": {}, "discard": {}, "logout": {}})
        m.set_portal_identity_providers("simple-gateway", "GW", ["A"])
        m.logout(discard=True)
        self.assertEqual(client.commands()[-2:], ["discard", "logout"])


class Gateway(unittest.TestCase):
    def test_cluster_is_found_when_not_a_single_gateway(self):
        m, client = logged_in({"show-simple-gateway": NOT_FOUND, "show-simple-cluster": gateway()})
        kind, obj = m.show_gateway("GW")
        self.assertEqual(kind, "simple-cluster")

    def test_portal_state_reads_names_from_objects(self):
        st = checkpoint.Management.portal_state(gateway("identity provider", [{"name": "A", "uid": "1"}, "B"]))
        self.assertEqual(st["identity_providers"], ["A", "B"])
        self.assertEqual(st["method"], "identity provider")
        self.assertEqual(st["main_url"], "https://gw.example.com/connect")
        self.assertTrue(st["browser_based_authentication"])

    def test_switching_the_portal_sets_method_and_list_together(self):
        m, client = logged_in({"set-simple-cluster": {}})
        m.set_portal_identity_providers("simple-cluster", "CL", ["A", "B"])
        auth = client.calls[-1][1]["identity-awareness-settings"]["browser-based-authentication-settings"]["authentication-settings"]
        self.assertEqual(auth, {"authentication-method": "identity provider", "identity-provider": ["A", "B"]})
        self.assertTrue(m.changed)


class IdentityProviderObject(unittest.TestCase):
    def test_created_with_metadata_when_absent(self):
        m, client = logged_in({"show-identity-provider": NOT_FOUND, "add-identity-provider": IDP_REPLY})
        obj = m.put_identity_provider("EntraID_GW", "GW", b"<xml/>")
        body = client.calls[-1][1]
        self.assertEqual(client.commands()[-1], "add-identity-provider")
        self.assertEqual(body["service"], "identity awareness")
        self.assertEqual(body["usage"], "gateway_policy_and_logs")
        self.assertEqual(body["data-receiving"], "metadata_file")
        self.assertEqual(body["base64-metadata-file"], "PHhtbC8+")
        self.assertEqual(checkpoint.service_provider_values(obj)["reply_urls"], IDP_REPLY["reply-urls"])

    def test_existing_object_is_refreshed_not_duplicated(self):
        m, client = logged_in({"show-identity-provider": IDP_REPLY, "set-identity-provider": IDP_REPLY})
        m.put_identity_provider("EntraID_GW", "GW", b"<xml/>")
        self.assertEqual(client.commands()[-1], "set-identity-provider")
        self.assertNotIn("gateway", client.calls[-1][1])

    def test_object_of_another_gateway_is_not_taken_over(self):
        other = dict(IDP_REPLY, gateway={"name": "OtherGW"})
        m, client = logged_in({"show-identity-provider": other})
        with self.assertRaises(checkpoint.ApiError):
            m.put_identity_provider("EntraID_GW", "GW", b"<xml/>")
        self.assertNotIn("set-identity-provider", client.commands())

    def test_object_of_another_service_is_not_taken_over(self):
        vpn = dict(IDP_REPLY, service="vpn")
        m, _ = logged_in({"show-identity-provider": vpn})
        with self.assertRaises(checkpoint.ApiError):
            m.put_identity_provider("EntraID_GW", "GW", b"<xml/>")


class Tasks(unittest.TestCase):
    def test_publish_waits_for_the_task(self):
        states = iter(["in progress", "succeeded"])
        m, client = logged_in({"publish": {"task-id": "t1"},
                               "show-task": lambda body: {"tasks": [{"task-id": "t1", "status": next(states)}]}})
        import time
        real, time.sleep = time.sleep, lambda s: None
        try:
            m.publish()
        finally:
            time.sleep = real
        self.assertEqual(client.commands().count("show-task"), 2)

    def test_failed_install_reports_the_gateway_message(self):
        task = {"task-name": "Policy installation", "status": "failed",
                "task-details": [{"stagesInfo": [{"messages": [{"message": "Gateway GW: SIC failed"}]}]}]}
        m, _ = logged_in({"install-policy": {"task-id": "t2"}, "show-task": {"tasks": [task]}})
        with self.assertRaises(checkpoint.TaskFailed) as cm:
            m.install_policy("Standard", ["GW"])
        self.assertIn("SIC failed", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
