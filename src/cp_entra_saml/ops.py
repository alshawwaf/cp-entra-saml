"""The three operations that change things: setup, status, teardown.

Each takes already-connected clients and a `say` callback, so the command line
stays thin and the flow can be tested with fakes.
"""
from __future__ import annotations

import urllib.parse
from typing import Callable, List, Optional

from . import checkpoint, entra, httpc, portal, saml

Say = Callable[[str], None]

ROOT_PORTAL_EXPLANATION = (
    "The portal Main URL has no path. On a portal published at the root of its host, the page that completes "
    "a SAML sign-in has been seen to post to \"//Login\", which browsers send to a host named \"login\"; users "
    "end on a blank page. Publish the portal under a path (for example https://<host>/connect) first, or pass "
    "--allow-root-portal if SAML sign-in is known to work on this gateway.")

AFTER_SETUP_NOTES = """\
Not done by this tool (check them before the first user signs in):
  * The gateway turns the SAML name into a user. A user it cannot find in a configured user directory is
    accepted only if an External User Profile that matches all users ("generic*") exists.
  * Groups for Access Roles come from the identity provider (a claim named group_attr, matched to Identity
    Tags whose external identifier is the Entra group's Object ID) or, when the assertion has no group claim,
    from a directory lookup of the signed-in name. Entra sends an e-mail style name, so that lookup has to
    search by mail (the identity_portal realm's userLoginAttr), not by account name.
  * The gateway's policy must let clients reach login.microsoftonline.com before they are authenticated."""


class Abort(Exception):
    """Stop with a message for the operator; nothing further is changed."""


def main_url_is_root(main_url: Optional[str]) -> bool:
    if not main_url:
        return False
    return urllib.parse.urlsplit(main_url).path.strip("/") == ""


def load_metadata(source: str, client: httpc.Client) -> bytes:
    if source.lower().startswith(("https://", "http://")):
        r = client.request_retry("GET", source)
        if r.status != 200:
            raise Abort("could not download the metadata: HTTP %d from %s" % (r.status, source))
        return r.body
    try:
        with open(source, "rb") as f:
            return f.read()
    except OSError as e:
        raise Abort("could not read the metadata file: %s" % e) from e


def describe_gateway(say: Say, mgmt: checkpoint.Management, gateway: str):
    kind, obj = mgmt.show_gateway(gateway)
    state = mgmt.portal_state(obj)
    say("Gateway %s (%s), management API %s" % (gateway, kind.replace("simple-", ""), mgmt.api_version or "?"))
    say("  Portal Main URL:        %s" % (state["main_url"] or "not set"))
    say("  Portal authentication:  %s%s" % (
        state["method"] or "unknown",
        " [%s]" % ", ".join(state["identity_providers"]) if state["identity_providers"] else ""))
    if not state["identity_awareness"] or not state["browser_based_authentication"]:
        raise Abort("Identity Awareness with Browser-Based Authentication is not enabled on %s. Enable it first "
                    "(gateway object > Identity Awareness > Browser-Based Authentication)." % gateway)
    return kind, state


def setup(say: Say, confirm: Callable[[str], bool], mgmt: checkpoint.Management, gateway: str, idp_name: str,
          graph: Optional[entra.Graph] = None, app_name: Optional[str] = None,
          metadata_source: Optional[str] = None, metadata_client: Optional[httpc.Client] = None,
          principals: Optional[List[str]] = None, everyone: bool = False,
          policy_package: Optional[str] = None, exclusive: bool = False,
          allow_root_portal: bool = False, dry_run: bool = False) -> dict:
    """Returns a summary dict. Raises Abort with nothing published when a precondition fails."""
    mgmt.require_identity_provider_api()
    kind, state = describe_gateway(say, mgmt, gateway)
    if main_url_is_root(state["main_url"]) and not allow_root_portal:
        raise Abort(ROOT_PORTAL_EXPLANATION)

    existing_idp = mgmt.show_identity_provider(idp_name)
    attached = state["identity_providers"] if state["method"] == checkpoint.METHOD_IDP else []
    target_list = [idp_name] if exclusive else list(dict.fromkeys(attached + [idp_name]))

    tenant = app = sp = None
    if graph is not None:
        tenant = graph.tenant()
        app = graph.find_application(app_name or "")
        say("Entra tenant %s (%s)" % (tenant["name"], tenant["domain"] or tenant["id"]))

    say("")
    say("Plan")
    step = 0

    def plan(text: str) -> None:
        nonlocal step
        step += 1
        say("  %d. %s" % (step, text))

    if graph is not None:
        plan("Entra: %s enterprise application %r with SAML sign-on"
             % ("reuse the" if app else "create the", app_name))
    plan("Check Point: %s identity provider object %r for %s (Identity Awareness)"
         % ("refresh the" if existing_idp else "create the", idp_name, gateway))
    if graph is not None:
        plan("Entra: write the gateway's Identifier and Reply URL into the application")
        if everyone:
            plan("Entra: let every user of the tenant sign in (no assignment required)")
        elif principals:
            plan("Entra: allow sign-in for %s" % ", ".join(principals))
    else:
        plan("You: enter the Identifier and Reply URL printed below at your identity provider")
    plan("Check Point: portal authentication -> identity provider [%s]%s"
         % (", ".join(target_list), "" if exclusive or len(target_list) == 1 else " (existing providers kept; users choose)"))
    plan("Check Point: publish%s" % (", install policy %r on %s" % (policy_package, gateway) if policy_package
                                      else " (policy is NOT installed; pass --install-policy <package>)"))
    if state["method"] != checkpoint.METHOD_IDP:
        say("  Note: users of this portal sign in with %r today. After step %d they sign in through the identity provider."
            % (state["method"], step - 1))
    if dry_run:
        say("")
        say("Dry run: nothing was changed.")
        return {"dry_run": True}
    if not confirm("Apply this plan?"):
        raise Abort("cancelled; nothing was changed")

    # 1. Identity provider side: an application to take metadata from.
    say("")
    if graph is not None:
        assert tenant is not None and app_name
        if app is None:
            made = graph.create_saml_application(app_name)
            app, sp = made["application"], made["servicePrincipal"]
            say("Entra: created application %s (appId %s)" % (app_name, app["appId"]))
        else:
            sp = graph.service_principal_for(app["appId"])
            if sp is None:
                raise Abort("application %r exists in Entra but has no enterprise application (service principal). "
                            "Remove it or choose another --app-name." % app_name)
            say("Entra: using existing application %s (appId %s)" % (app_name, app["appId"]))
        graph.enable_saml(sp["id"], sign_on_url=state["main_url"])
        thumb = graph.ensure_signing_certificate(sp["id"], app_name)
        say("Entra: SAML sign-on enabled, signing certificate %s" % thumb)
        metadata = graph.federation_metadata(tenant["id"], app["appId"], thumb)
    else:
        assert metadata_source and metadata_client
        metadata = load_metadata(metadata_source, metadata_client)
    try:
        md = saml.parse_metadata(metadata)
    except saml.SamlError as e:
        raise Abort("the identity provider metadata is not usable: %s" % e) from e
    if not md["signing_certificates"]:
        raise Abort("the identity provider metadata contains no signing certificate")
    say("Identity provider: %s" % md["entity_id"])

    # 2. Check Point object. Its reply carries the values the identity provider needs.
    obj = mgmt.put_identity_provider(idp_name, gateway, metadata, comments="Created by cp-entra-saml")
    spv = checkpoint.service_provider_values(obj)
    if not spv["entity_id"] or not spv["reply_urls"]:
        shown = mgmt.show_identity_provider(idp_name) or {}
        spv = checkpoint.service_provider_values(shown)
    if not spv["entity_id"] or not spv["reply_urls"]:
        raise Abort("the management server did not return an Identifier and Reply URL for %r" % idp_name)
    say("Check Point: identity provider object %s" % idp_name)
    say("  Identifier (Entity ID): %s" % spv["entity_id"])
    for u in spv["reply_urls"]:
        say("  Reply URL (ACS):        %s" % u)

    # 3. Back to the identity provider with those values.
    if graph is not None:
        graph.set_service_provider(app["id"], spv["entity_id"], spv["reply_urls"], sp_id=sp["id"])
        say("Entra: Identifier and Reply URL written")
        if everyone:
            graph.set_assignment_required(sp["id"], False)
            say("Entra: every user of the tenant may sign in")
        for ref in principals or []:
            p = graph.resolve_principal(ref)
            new = graph.assign(sp["id"], p["id"])
            say("Entra: %s %s %s" % (p["kind"], p["name"], "assigned" if new else "was already assigned"))
        if not everyone and not principals:
            say("Entra: nobody is assigned yet. Assign users or groups to the application, or run again with "
                "--assign / --everyone.")

    # 4. Gateway.
    if state["method"] != checkpoint.METHOD_IDP or attached != target_list:
        mgmt.set_portal_identity_providers(kind, gateway, target_list)
    mgmt.publish()
    say("Check Point: published")
    if policy_package:
        say("Check Point: installing policy %s on %s ..." % (policy_package, gateway))
        mgmt.install_policy(policy_package, [gateway])
        say("Check Point: policy installed")
    else:
        say("Check Point: install the Access Control policy on %s to make this effective" % gateway)

    return {"gateway": gateway, "main_url": state["main_url"], "identity_provider_object": idp_name,
            "entity_id": spv["entity_id"], "reply_urls": spv["reply_urls"],
            "idp_entity_id": md["entity_id"], "application_id": app["appId"] if app else None,
            "policy_installed": bool(policy_package)}


def verify_portal(say: Say, main_url: str, client: httpc.Client, expected_entity_id: Optional[str] = None,
                  expected_reply_urls: Optional[List[str]] = None) -> bool:
    """Open the portal as a browser would and compare what it asks the identity provider for."""
    try:
        report = portal.check(main_url, client)
    except (portal.PortalError, httpc.HttpError) as e:
        say("Portal check skipped: %s" % e)
        return False
    say(portal.render(report).rstrip())
    ok = not any(f["severity"] == "error" for f in report["findings"])
    if expected_entity_id:
        seen = [i for i in report["identity_providers"] if i.get("entity_id") == expected_entity_id]
        if not seen:
            say("The portal does not (yet) present the identity provider configured here. If policy was just "
                "installed, wait a few seconds and run 'status'.")
            return False
        if expected_reply_urls and seen[0].get("reply_url") not in expected_reply_urls:
            say("Reply URL sent by the portal (%s) is not the one registered at the identity provider."
                % seen[0].get("reply_url"))
            return False
    return ok


def status(say: Say, mgmt: checkpoint.Management, gateway: str, graph: Optional[entra.Graph] = None,
           app_name: Optional[str] = None) -> dict:
    kind, state = describe_gateway(say, mgmt, gateway)
    try:
        mgmt.require_identity_provider_api()
        objs = [o for o in mgmt.list_identity_providers()
                if o.get("service") == checkpoint.IA_SERVICE and gateway in checkpoint._names(o.get("gateway"))]
    except checkpoint.Unsupported as e:
        say("  %s" % e)
        objs = []
    say("")
    say("Identity provider objects for this gateway's portal: %s" % (len(objs) or "none"))
    for o in objs:
        spv = checkpoint.service_provider_values(o)
        used = o.get("name") in state["identity_providers"] and state["method"] == checkpoint.METHOD_IDP
        say("  %s%s" % (o.get("name"), "" if used else "   (not attached to the portal)"))
        say("    Identifier (Entity ID): %s" % spv["entity_id"])
        for u in spv["reply_urls"]:
            say("    Reply URL (ACS):        %s" % u)
        say("    Identity provider:      %s" % (o.get("received-identifier") or "from metadata file"))
    result = {"state": state, "objects": objs, "mismatch": False}
    if graph is not None and app_name:
        app = graph.find_application(app_name)
        say("")
        if app is None:
            say("Entra: no application named %r" % app_name)
            result["mismatch"] = True
        else:
            ids = app.get("identifierUris") or []
            replies = (app.get("web") or {}).get("redirectUris") or []
            say("Entra application %s (appId %s)" % (app_name, app["appId"]))
            say("  Identifier (Entity ID): %s" % (", ".join(ids) or "not set"))
            say("  Reply URL (ACS):        %s" % (", ".join(replies) or "not set"))
            match = [o for o in objs if o.get("required-identifier") in ids]
            if not match:
                say("  MISMATCH: none of the gateway's identity provider objects has this Identifier.")
                result["mismatch"] = True
            else:
                want = checkpoint.service_provider_values(match[0])["reply_urls"]
                missing = [u for u in want if u not in replies]
                if missing:
                    say("  MISMATCH: Reply URL %s is not registered in Entra." % ", ".join(missing))
                    result["mismatch"] = True
                else:
                    say("  Matches Check Point object %s." % match[0].get("name"))
    if main_url_is_root(state["main_url"]) and state["method"] == checkpoint.METHOD_IDP:
        say("")
        say("WARNING: " + ROOT_PORTAL_EXPLANATION)
    return result


def teardown(say: Say, confirm: Callable[[str], bool], mgmt: checkpoint.Management, gateway: str, idp_name: str,
             graph: Optional[entra.Graph] = None, app_name: Optional[str] = None,
             restore_method: str = "username and password", policy_package: Optional[str] = None) -> None:
    kind, state = describe_gateway(say, mgmt, gateway)
    obj = mgmt.show_identity_provider(idp_name)
    attached = state["identity_providers"] if state["method"] == checkpoint.METHOD_IDP else []
    remaining = [n for n in attached if n != idp_name]
    app = graph.find_application(app_name) if graph is not None and app_name else None

    say("")
    say("Plan")
    if idp_name in attached:
        say("  - Check Point: portal authentication -> %s"
            % ("identity provider [%s]" % ", ".join(remaining) if remaining else restore_method))
    say("  - Check Point: %s" % ("delete identity provider object %r" % idp_name if obj else "no object named %r" % idp_name))
    say("  - Check Point: publish%s" % (", install policy %r" % policy_package if policy_package else ""))
    if graph is not None:
        say("  - Entra: %s" % ("delete application %r" % app_name if app else "no application named %r" % app_name))
    if not confirm("Remove this configuration?"):
        raise Abort("cancelled; nothing was changed")

    if idp_name in attached:
        if remaining:
            mgmt.set_portal_identity_providers(kind, gateway, remaining)
        else:
            mgmt.set_portal_method(kind, gateway, restore_method)
    if obj:
        mgmt.delete_identity_provider(idp_name)
    if mgmt.changed:
        mgmt.publish()
        say("Check Point: published")
        if policy_package:
            mgmt.install_policy(policy_package, [gateway])
            say("Check Point: policy installed")
        else:
            say("Check Point: install the Access Control policy on %s to make this effective" % gateway)
    if app is not None and graph is not None:
        sp = graph.service_principal_for(app["appId"])
        graph.delete_application(app["id"], sp["id"] if sp else None)
        say("Entra: application %s deleted (recoverable from 'Deleted applications' for 30 days)" % app_name)
