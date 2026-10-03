import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

import fixtures  # noqa: E402
from cp_entra_saml import checkpoint, ops  # noqa: E402

ENTITY = "https://gw.example.com/connect/spPortal/ACS/ID/u1"
REPLY = "https://gw.example.com/connect/spPortal/ACS/Login/u1"


class FakeMgmt:
    api_version = "2.2"

    def __init__(self, method="username and password", attached=None, main_url="https://gw.example.com/connect",
                 objects=None, bba=True):
        self.method, self.attached, self.main_url, self.bba = method, list(attached or []), main_url, bba
        self.objects = dict(objects or {})
        self.log = []
        self.changed = False

    def require_identity_provider_api(self):
        self.log.append("check-api")

    def show_gateway(self, name):
        return "simple-gateway", {"fake": True}

    def portal_state(self, obj):
        return {"identity_awareness": True, "browser_based_authentication": self.bba, "method": self.method,
                "identity_providers": list(self.attached), "users_directories": None, "main_url": self.main_url}

    def show_identity_provider(self, name):
        return self.objects.get(name)

    def list_identity_providers(self):
        return list(self.objects.values())

    def put_identity_provider(self, name, gateway, metadata, comments=""):
        self.log.append("put-idp:" + name)
        self.changed = True
        self.objects[name] = {"name": name, "service": checkpoint.IA_SERVICE, "gateway": {"name": gateway},
                              "required-identifier": ENTITY, "reply-urls": [REPLY]}
        return self.objects[name]

    def set_portal_identity_providers(self, kind, name, idps):
        self.log.append("portal:" + ",".join(idps))
        self.method, self.attached, self.changed = checkpoint.METHOD_IDP, list(idps), True

    def set_portal_method(self, kind, name, method):
        self.log.append("method:" + method)
        self.method, self.attached, self.changed = method, [], True

    def delete_identity_provider(self, name):
        self.log.append("delete-idp:" + name)
        self.objects.pop(name, None)
        self.changed = True

    def publish(self):
        self.log.append("publish")
        self.changed = False

    def install_policy(self, package, targets):
        self.log.append("install:%s:%s" % (package, ",".join(targets)))


class FakeGraph:
    def __init__(self, existing=None):
        self.app = existing
        self.log = []

    def tenant(self):
        return {"id": fixtures.IDP_TENANT, "name": "Example", "domain": "example.com"}

    def find_application(self, name):
        return self.app

    def service_principal_for(self, app_id):
        return {"id": "sp1"} if self.app else None

    def create_saml_application(self, name):
        self.log.append("create-app")
        self.app = {"id": "obj1", "appId": "app1", "displayName": name}
        return {"application": self.app, "servicePrincipal": {"id": "sp1"}}

    def enable_saml(self, sp_id, sign_on_url=None):
        self.log.append("saml:%s" % sign_on_url)

    def ensure_signing_certificate(self, sp_id, name):
        self.log.append("cert")
        return "THUMB"

    def federation_metadata(self, tenant_id, app_id, thumbprint=None):
        self.log.append("metadata:%s" % thumbprint)
        return fixtures.metadata_xml()

    def set_service_provider(self, app_object_id, entity_id, reply_urls, sp_id=None):
        self.log.append("sp-values:%s|%s" % (entity_id, ",".join(reply_urls)))
        self.app["identifierUris"] = [entity_id]
        self.app["web"] = {"redirectUris": list(reply_urls)}

    def set_assignment_required(self, sp_id, required):
        self.log.append("assignment-required:%s" % required)

    def resolve_principal(self, ref):
        return {"id": "p-" + ref, "name": ref, "kind": "user" if "@" in ref else "group"}

    def assign(self, sp_id, principal_id):
        self.log.append("assign:" + principal_id)
        return True

    def delete_application(self, app_object_id, sp_id):
        self.log.append("delete-app")
        self.app = None


def run_setup(mgmt, graph=None, confirm=True, **kw):
    out = []
    kw.setdefault("app_name", "App")
    summary = ops.setup(out.append, lambda q: confirm, mgmt, "GW", "EntraID_GW", graph=graph, **kw)
    return summary, "\n".join(out)


class Setup(unittest.TestCase):
    def test_full_run_in_the_right_order(self):
        mgmt, graph = FakeMgmt(), FakeGraph()
        summary, text = run_setup(mgmt, graph, principals=["user@example.com", "VPN Users"], policy_package="Standard")
        self.assertEqual(graph.log, [
            "create-app", "saml:https://gw.example.com/connect", "cert", "metadata:THUMB",
            "sp-values:%s|%s" % (ENTITY, REPLY), "assign:p-user@example.com", "assign:p-VPN Users"])
        self.assertEqual(mgmt.log, ["check-api", "put-idp:EntraID_GW", "portal:EntraID_GW", "publish", "install:Standard:GW"])
        self.assertEqual(summary["entity_id"], ENTITY)
        self.assertTrue(summary["policy_installed"])
        self.assertIn(ENTITY, text)

    def test_root_published_portal_is_refused_before_any_change(self):
        mgmt, graph = FakeMgmt(main_url="https://gw.example.com/"), FakeGraph()
        with self.assertRaises(ops.Abort) as cm:
            run_setup(mgmt, graph)
        self.assertIn("//Login", str(cm.exception))
        self.assertEqual(mgmt.log, ["check-api"])
        self.assertEqual(graph.log, [])

    def test_root_published_portal_can_be_forced(self):
        mgmt = FakeMgmt(main_url="https://gw.example.com")
        run_setup(mgmt, FakeGraph(), allow_root_portal=True)
        self.assertIn("publish", mgmt.log)

    def test_dry_run_changes_nothing(self):
        mgmt = FakeMgmt()
        summary, text = run_setup(mgmt, None, dry_run=True, metadata_source="x")
        self.assertEqual(summary, {"dry_run": True})
        self.assertEqual(mgmt.log, ["check-api"])
        self.assertIn("Plan", text)

    def test_declined_confirmation_changes_nothing(self):
        mgmt, graph = FakeMgmt(), FakeGraph()
        with self.assertRaises(ops.Abort):
            run_setup(mgmt, graph, confirm=False)
        self.assertEqual(mgmt.log, ["check-api"])
        self.assertEqual(graph.log, [])

    def test_other_identity_providers_are_kept_by_default(self):
        mgmt = FakeMgmt(method=checkpoint.METHOD_IDP, attached=["Okta"])
        run_setup(mgmt, FakeGraph())
        self.assertIn("portal:Okta,EntraID_GW", mgmt.log)

    def test_only_replaces_the_list(self):
        mgmt = FakeMgmt(method=checkpoint.METHOD_IDP, attached=["Okta"])
        run_setup(mgmt, FakeGraph(), exclusive=True)
        self.assertIn("portal:EntraID_GW", mgmt.log)

    def test_stale_list_is_ignored_when_portal_uses_passwords(self):
        mgmt = FakeMgmt(method="username and password", attached=["Old"])
        run_setup(mgmt, FakeGraph())
        self.assertIn("portal:EntraID_GW", mgmt.log)

    def test_rerun_does_not_touch_the_gateway_again(self):
        mgmt, graph = FakeMgmt(), FakeGraph()
        run_setup(mgmt, graph)
        mgmt.log.clear()
        graph.log.clear()
        run_setup(mgmt, graph)
        self.assertNotIn("create-app", graph.log)
        self.assertEqual(mgmt.log, ["check-api", "put-idp:EntraID_GW", "publish"])

    def test_portal_without_browser_based_authentication_is_refused(self):
        with self.assertRaises(ops.Abort):
            run_setup(FakeMgmt(bba=False), FakeGraph())

    def test_everyone(self):
        graph = FakeGraph()
        run_setup(FakeMgmt(), graph, everyone=True)
        self.assertIn("assignment-required:False", graph.log)

    def test_unassigned_application_is_called_out(self):
        _, text = run_setup(FakeMgmt(), FakeGraph())
        self.assertIn("nobody is assigned", text)
        self.assertIn("install the Access Control policy", text)


class OtherIdentityProvider(unittest.TestCase):
    def test_metadata_file_mode_prints_values_for_the_operator(self):
        import tempfile
        with tempfile.NamedTemporaryFile("wb", suffix=".xml", delete=False) as f:
            f.write(fixtures.metadata_xml())
        try:
            mgmt = FakeMgmt()
            summary, text = run_setup(mgmt, None, metadata_source=f.name, metadata_client=object())
        finally:
            os.unlink(f.name)
        self.assertEqual(summary["application_id"], None)
        self.assertIn("enter the Identifier and Reply URL", text)
        self.assertIn(REPLY, text)

    def test_unusable_metadata_stops_before_check_point_is_changed(self):
        import tempfile
        with tempfile.NamedTemporaryFile("wb", suffix=".xml", delete=False) as f:
            f.write(b"<html>not metadata</html>")
        try:
            mgmt = FakeMgmt()
            with self.assertRaises(ops.Abort):
                run_setup(mgmt, None, metadata_source=f.name, metadata_client=object())
        finally:
            os.unlink(f.name)
        self.assertEqual(mgmt.log, ["check-api"])


class Status(unittest.TestCase):
    def test_reports_agreement(self):
        mgmt, graph = FakeMgmt(), FakeGraph()
        run_setup(mgmt, graph)
        out = []
        result = ops.status(out.append, mgmt, "GW", graph=graph, app_name="App")
        self.assertFalse(result["mismatch"])
        self.assertIn("Matches Check Point object EntraID_GW", "\n".join(out))

    def test_reports_reply_url_drift(self):
        mgmt, graph = FakeMgmt(), FakeGraph()
        run_setup(mgmt, graph)
        graph.app["web"]["redirectUris"] = ["https://old.example.com/acs"]
        out = []
        result = ops.status(out.append, mgmt, "GW", graph=graph, app_name="App")
        self.assertTrue(result["mismatch"])

    def test_warns_about_root_portal_with_saml(self):
        mgmt = FakeMgmt(method=checkpoint.METHOD_IDP, attached=["X"], main_url="https://gw.example.com/")
        out = []
        ops.status(out.append, mgmt, "GW")
        self.assertIn("WARNING", "\n".join(out))


class Teardown(unittest.TestCase):
    def test_restores_password_login_and_removes_everything(self):
        mgmt, graph = FakeMgmt(), FakeGraph()
        run_setup(mgmt, graph)
        mgmt.log.clear()
        graph.log.clear()
        ops.teardown(lambda s: None, lambda q: True, mgmt, "GW", "EntraID_GW", graph=graph, app_name="App",
                     policy_package="Standard")
        self.assertEqual(mgmt.log, ["method:username and password", "delete-idp:EntraID_GW", "publish", "install:Standard:GW"])
        self.assertEqual(graph.log, ["delete-app"])

    def test_keeps_other_identity_providers(self):
        mgmt = FakeMgmt(method=checkpoint.METHOD_IDP, attached=["Okta", "EntraID_GW"],
                        objects={"EntraID_GW": {"name": "EntraID_GW"}})
        ops.teardown(lambda s: None, lambda q: True, mgmt, "GW", "EntraID_GW")
        self.assertEqual(mgmt.log[0], "portal:Okta")

    def test_nothing_to_do_publishes_nothing(self):
        mgmt = FakeMgmt()
        ops.teardown(lambda s: None, lambda q: True, mgmt, "GW", "EntraID_GW")
        self.assertEqual(mgmt.log, [])


if __name__ == "__main__":
    unittest.main()
