import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

import fixtures  # noqa: E402
from cp_entra_saml import saml  # noqa: E402

BASE = "https://portal.example.com/connect"


class AuthnRequest(unittest.TestCase):
    def test_decodes_what_the_gateway_asks_for(self):
        r = saml.decode_redirect_request(fixtures.authn_request_url(BASE))
        entity_id, acs = fixtures.sp_values(BASE)
        self.assertEqual(r["issuer"], entity_id)
        self.assertEqual(r["acs_url"], acs)
        self.assertEqual(r["destination"], fixtures.IDP_SSO)
        self.assertTrue(r["nameid_format"].endswith("emailAddress"))
        self.assertIn("/spPortal/ServiceProvider", r["relay_state"])

    def test_url_without_request(self):
        with self.assertRaises(saml.SamlError):
            saml.decode_redirect_request("https://idp.example.com/sso?x=1")


class Response(unittest.TestCase):
    def test_success(self):
        r = saml.decode_response(fixtures.saml_response_b64(BASE, groups=["a"]))
        entity_id, acs = fixtures.sp_values(BASE)
        self.assertTrue(r["status"].endswith(":Success"))
        self.assertEqual(r["audiences"], [entity_id])
        self.assertEqual(r["recipient"], acs)
        self.assertEqual(r["nameid"], "user@example.com")
        self.assertTrue(r["assertion_signed"])
        self.assertFalse(r["response_signed"])
        self.assertEqual(len(r["group_claims"]), 1)

    def test_failure_has_no_assertion(self):
        r = saml.decode_response(fixtures.saml_response_b64(BASE, status="Responder"))
        self.assertFalse(r["has_assertion"])
        self.assertTrue(r["status"].endswith(":Responder"))

    def test_doctype_is_refused(self):
        evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&a;</samlp:Response>'
        with self.assertRaises(saml.SamlError):
            saml.decode_response(base64.b64encode(evil).decode())

    def test_garbage(self):
        with self.assertRaises(saml.SamlError):
            saml.decode_response("!!!! not base64 !!!!")


class Metadata(unittest.TestCase):
    def test_identity_provider_metadata(self):
        m = saml.parse_metadata(fixtures.metadata_xml())
        self.assertEqual(m["entity_id"], fixtures.IDP_ISSUER)
        self.assertEqual(m["sso_redirect_url"], fixtures.IDP_SSO)
        self.assertEqual(len(m["signing_certificates"]), 1)
        self.assertEqual(m["signing_certificates"][0]["base64"], fixtures.CERT_B64)
        self.assertEqual(len(m["signing_certificates"][0]["sha256"]), 64)

    def test_not_metadata(self):
        with self.assertRaises(saml.SamlError):
            saml.parse_metadata(b"<html/>")


if __name__ == "__main__":
    unittest.main()
