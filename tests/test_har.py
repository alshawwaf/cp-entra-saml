import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

import fixtures  # noqa: E402
from cp_entra_saml import har  # noqa: E402

ROOT = "https://portal.example.com"
CONNECT = "https://portal.example.com/connect"


def ids(report):
    return [f["id"] for f in report["findings"]]


class RootPublication(unittest.TestCase):
    def setUp(self):
        self.report = har.analyze(fixtures.capture(ROOT, published_at_root=True))

    def test_handoff_bug_is_found_and_explained(self):
        f = [x for x in self.report["findings"] if x["id"] == "handoff-scheme-relative"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "error")
        self.assertIn("https://login/", f[0]["title"])
        self.assertIn('"//Login"', f[0]["detail"])

    def test_handoff_targets(self):
        targets = {t["expression"]: t for t in self.report["handoff"]["targets"]}
        self.assertEqual(targets['nacUrl + "/Login"']["resolves_to"], "https://login/")
        self.assertFalse(targets['nacUrl + "/Login"']["same_host"])
        self.assertEqual(targets['nacUrl + "PortalMain"']["resolves_to"], ROOT + "/PortalMain")

    def test_identity_provider_side_is_reported_clean(self):
        for bad in ("audience-mismatch", "recipient-mismatch", "saml-status", "idp-error", "acs-rejected"):
            self.assertNotIn(bad, ids(self.report))
        self.assertTrue(str(self.report["saml_response"]["status"]).endswith(":Success"))

    def test_bare_host_request_is_secondary_when_explained(self):
        f = [x for x in self.report["findings"] if x["id"] == "request-to-bare-host"]
        self.assertEqual([x["severity"] for x in f], ["info"])


class DefaultPublication(unittest.TestCase):
    def test_no_handoff_finding_under_a_path(self):
        report = har.analyze(fixtures.capture(CONNECT, published_at_root=False))
        self.assertNotIn("handoff-scheme-relative", ids(report))
        self.assertNotIn("request-to-bare-host", ids(report))
        targets = {t["expression"]: t for t in report["handoff"]["targets"]}
        self.assertTrue(targets['nacUrl + "/Login"']["same_host"])


class IdentityProviderMistakes(unittest.TestCase):
    def test_wrong_audience(self):
        report = har.analyze(fixtures.capture(CONNECT, False, audience="https://other.example.com/id"))
        self.assertIn("audience-mismatch", ids(report))

    def test_wrong_recipient(self):
        report = har.analyze(fixtures.capture(CONNECT, False, recipient="https://other.example.com/acs"))
        self.assertIn("recipient-mismatch", ids(report))

    def test_failed_status(self):
        report = har.analyze(fixtures.capture(CONNECT, False, status="Requester"))
        self.assertIn("saml-status", ids(report))

    def test_stale_response(self):
        report = har.analyze(fixtures.capture(CONNECT, False, request_id="_other"))
        self.assertIn("inresponseto-mismatch", ids(report))

    def test_entra_error_code_is_surfaced(self):
        cap = fixtures.capture(CONNECT, False)
        cap["log"]["entries"] = cap["log"]["entries"][:3]
        cap["log"]["entries"][2]["response"]["content"]["text"] = "<html>AADSTS50011: The reply URL does not match</html>"
        report = har.analyze(cap)
        f = [x for x in report["findings"] if x["id"] == "idp-error"]
        self.assertEqual(len(f), 1)
        self.assertIn("AADSTS50011", f[0]["title"])
        self.assertNotIn("no-assertion", ids(report))

    def test_group_claims_are_recognised(self):
        report = har.analyze(fixtures.capture(CONNECT, False, groups=["g1", "g2"]))
        f = [x for x in report["findings"] if x["id"] == "identity-shape"][0]
        self.assertIn("group claims: groups", f["title"])


class Secrets(unittest.TestCase):
    def setUp(self):
        self.capture = fixtures.capture(ROOT, published_at_root=True)

    def test_password_is_reported_without_its_value(self):
        report = har.analyze(self.capture)
        f = report["findings"][0]
        self.assertEqual(f["id"], "credential-in-capture")
        self.assertIn("passwd", f["detail"])
        text = har.render(report) + json.dumps(report)
        self.assertNotIn(fixtures.USER_PASSWORD, text)
        self.assertNotIn(fixtures.PORTAL_TOKEN, text)

    def test_portal_token_is_not_called_a_password(self):
        kinds = {(s["name"], s["kind"]) for s in har.find_secrets(self.capture)}
        self.assertIn(("one-time portal login token", "session"), kinds)
        self.assertNotIn(("password", "credential"), kinds)

    def test_sanitize_removes_every_copy(self):
        clean, n = har.sanitize(self.capture)
        blob = json.dumps(clean)
        self.assertGreater(n, 0)
        for secret in (fixtures.USER_PASSWORD, fixtures.PORTAL_TOKEN, "F" * 40, "ESTSAUTH=abcdefghijkl"):
            self.assertNotIn(secret, blob)
        self.assertEqual([s["name"] for s in har.find_secrets(clean)], ["SAMLResponse"])

    def test_sanitize_leaves_the_original_untouched(self):
        before = json.dumps(self.capture)
        har.sanitize(self.capture)
        self.assertEqual(before, json.dumps(self.capture))

    def test_sanitized_capture_still_diagnoses(self):
        clean, _ = har.sanitize(self.capture)
        report = har.analyze(clean)
        self.assertIn("handoff-scheme-relative", ids(report))
        self.assertNotIn("credential-in-capture", ids(report))

    def test_assertion_can_be_removed_too(self):
        clean, _ = har.sanitize(self.capture, redact_assertion=True)
        self.assertEqual(har.find_secrets(clean), [])


class Loading(unittest.TestCase):
    def test_rejects_non_har(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as f:
            f.write('{"hello": 1}')
        try:
            with self.assertRaises(har.HarError):
                har.load(f.name)
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
