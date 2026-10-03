"""Command line for cp-entra-saml."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from typing import Dict, List, Optional

from . import __version__, checkpoint, entra, har, httpc, ops, portal

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def say(message: str = "") -> None:
    print(message, flush=True)


def fail(message: str) -> int:
    print("error: " + message, file=sys.stderr, flush=True)
    return EXIT_ERROR


def interactive() -> bool:
    """True when a person can be asked. On Windows the NUL device claims to be a terminal."""
    try:
        if not sys.stdin.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            import msvcrt
            mode = ctypes.c_uint32()
            handle = msvcrt.get_osfhandle(sys.stdin.fileno())
            return bool(ctypes.windll.kernel32.GetConsoleMode(ctypes.c_void_p(handle), ctypes.byref(mode)))
        except Exception:
            return False
    return True


# -- credentials ------------------------------------------------------------------
def read_credentials_file(path: str) -> Dict[str, str]:
    """KEY=VALUE lines. Keeps secrets out of the command line and the shell history."""
    out: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[k.strip()] = v
    return out


def management_login(args, read_only: bool = False) -> checkpoint.Management:
    creds: Dict[str, str] = {}
    if args.credentials:
        creds.update(read_credentials_file(args.credentials))
    for key in ("CP_MGMT_API_KEY", "CP_MGMT_USER", "CP_MGMT_PASSWORD"):
        if os.environ.get(key):
            creds[key] = os.environ[key]
    api_key = creds.get("CP_MGMT_API_KEY")
    user, password = creds.get("CP_MGMT_USER"), creds.get("CP_MGMT_PASSWORD")
    if not api_key and not (user and password):
        if not interactive():
            raise ops.Abort("no management credentials: set CP_MGMT_API_KEY (or CP_MGMT_USER and CP_MGMT_PASSWORD) "
                            "in the environment or in a file passed with --credentials")
        api_key = getpass.getpass("Management API key (empty to use a user name and password): ").strip() or None
        if not api_key:
            user = user or input("Management user name: ").strip()
            password = getpass.getpass("Password: ")
    client = httpc.Client(verify=not args.mgmt_insecure, ca_file=args.mgmt_ca_file,
                          fingerprint=args.mgmt_fingerprint, use_env_proxy=args.mgmt_use_proxy, timeout=60)
    mgmt = checkpoint.Management(args.mgmt, client, domain=args.domain)
    mgmt.login(api_key=api_key, user=user, password=password, read_only=read_only)
    return mgmt


def graph_login(args, assigning: bool = False) -> entra.Graph:
    client = httpc.Client(timeout=60)
    scopes = entra.SCOPES_BASE + (entra.SCOPES_ASSIGN if assigning else ())
    token = os.environ.get("GRAPH_ACCESS_TOKEN")
    if token:
        say("Entra: using the token from GRAPH_ACCESS_TOKEN")
    elif args.use_az_cli:
        token = entra.azure_cli_token(args.tenant)
    elif not args.tenant:
        raise ops.Abort("--tenant <tenant id or domain> is needed to sign in to Microsoft Entra")
    elif args.login == "browser":
        token = entra.browser_login(client, args.tenant, client_id=args.client_id, scopes=scopes)
    else:
        token = entra.device_code_login(client, args.tenant, client_id=args.client_id, scopes=scopes)
    return entra.Graph(client, token)


def confirmer(args):
    def confirm(question: str) -> bool:
        if args.yes:
            return True
        if not interactive():
            raise ops.Abort("confirmation needed: run again with --yes, or with --dry-run to see the plan only")
        return input(question + " [y/N] ").strip().lower() in ("y", "yes")
    return confirm


def portal_client(args) -> httpc.Client:
    return httpc.Client(verify=not args.portal_insecure, ca_file=getattr(args, "portal_ca_file", None),
                        fingerprint=getattr(args, "portal_fingerprint", None),
                        use_env_proxy=getattr(args, "portal_use_proxy", False), timeout=20)


# -- commands ---------------------------------------------------------------------
def cmd_setup(args) -> int:
    if not args.idp_metadata and not args.tenant and not args.use_az_cli and not os.environ.get("GRAPH_ACCESS_TOKEN"):
        return fail("say which identity provider: --tenant <tenant id or domain> for Microsoft Entra, "
                    "or --idp-metadata <file or URL> for any other SAML identity provider")
    if args.assign and args.everyone:
        return fail("--assign and --everyone are alternatives")
    idp_name = args.idp_name or ("EntraID_%s" % args.gateway if not args.idp_metadata else "SAML_IdP_%s" % args.gateway)
    app_name = args.app_name or "Check Point Captive Portal (%s)" % args.gateway
    mgmt = management_login(args, read_only=args.dry_run)
    try:
        graph = None
        if not args.idp_metadata and not args.dry_run:
            graph = graph_login(args, assigning=bool(args.assign))
        elif not args.idp_metadata:
            say("Dry run: Entra is not contacted.")
        summary = ops.setup(
            say, confirmer(args), mgmt, args.gateway, idp_name, graph=graph, app_name=app_name,
            metadata_source=args.idp_metadata, metadata_client=httpc.Client(timeout=30),
            principals=args.assign, everyone=args.everyone, policy_package=args.install_policy,
            exclusive=args.only, allow_root_portal=args.allow_root_portal, dry_run=args.dry_run)
    except BaseException:
        mgmt.logout(discard=True)
        raise
    mgmt.logout()
    if summary.get("dry_run"):
        return EXIT_OK
    say("")
    say(ops.AFTER_SETUP_NOTES)
    if summary.get("policy_installed") and summary.get("main_url") and not args.skip_portal_check:
        say("")
        say("Checking the portal ...")
        ops.verify_portal(say, summary["main_url"], portal_client(args), summary["entity_id"], summary["reply_urls"])
    say("")
    say("Done. Test with one user: open %s in a private browser window." % (summary.get("main_url") or "the portal"))
    return EXIT_OK


def cmd_status(args) -> int:
    mgmt = management_login(args, read_only=True)
    try:
        graph = graph_login(args) if (args.tenant or args.use_az_cli or os.environ.get("GRAPH_ACCESS_TOKEN")) else None
        app_name = args.app_name or "Check Point Captive Portal (%s)" % args.gateway
        result = ops.status(say, mgmt, args.gateway, graph=graph, app_name=app_name if graph else None)
    finally:
        mgmt.logout()
    main_url = result["state"].get("main_url")
    ok = True
    if main_url and not args.skip_portal_check:
        say("")
        ok = ops.verify_portal(say, main_url, portal_client(args))
    return EXIT_OK if ok and not result["mismatch"] else EXIT_FINDINGS


def cmd_teardown(args) -> int:
    idp_name = args.idp_name or "EntraID_%s" % args.gateway
    app_name = args.app_name or "Check Point Captive Portal (%s)" % args.gateway
    mgmt = management_login(args)
    try:
        graph = graph_login(args) if args.delete_entra_app else None
        ops.teardown(say, confirmer(args), mgmt, args.gateway, idp_name, graph=graph,
                     app_name=app_name if graph else None, restore_method=args.restore_method,
                     policy_package=args.install_policy)
    except BaseException:
        mgmt.logout(discard=True)
        raise
    mgmt.logout()
    return EXIT_OK


def cmd_portal(args) -> int:
    report = portal.check(args.url, portal_client(args))
    if args.json:
        say(json.dumps(report, indent=2))
    else:
        say(portal.render(report).rstrip())
    return EXIT_FINDINGS if any(f["severity"] == "error" for f in report["findings"]) else EXIT_OK


def cmd_har(args) -> int:
    capture = har.load(args.file)
    if args.sanitize:
        if os.path.abspath(args.sanitize) == os.path.abspath(args.file):
            return fail("--sanitize needs a different file name; the original is left untouched")
        clean, n = har.sanitize(capture, redact_assertion=args.redact_assertion)
        with open(args.sanitize, "w", encoding="utf-8") as f:
            json.dump(clean, f)
        print("Sanitized copy written to %s (%d values replaced). The original still holds the secrets."
              % (args.sanitize, n), file=sys.stderr)
    report = har.analyze(capture)
    if args.json:
        say(json.dumps(report, indent=2))
    else:
        say(har.render(report).rstrip())
    return EXIT_FINDINGS if any(f["severity"] == "error" for f in report["findings"]) else EXIT_OK


def cmd_fingerprint(args) -> int:
    host = args.server.split("://", 1)[-1].strip("/")
    client = httpc.Client(verify=False, use_env_proxy=args.use_proxy, timeout=20)
    client.request("GET", "https://%s/" % host)
    for peer, digest in client.seen_fingerprints.items():
        say("%s  %s" % (peer, httpc.format_fingerprint(digest)))
    say("Compare this with the certificate fingerprint shown on the server itself before trusting it.")
    return EXIT_OK


# -- parser -----------------------------------------------------------------------
def _add_mgmt(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("Check Point management")
    g.add_argument("--mgmt", required=True, metavar="HOST[:PORT]", help="Security Management Server (or Domain Server)")
    g.add_argument("--gateway", required=True, metavar="NAME", help="gateway or cluster object whose Captive Portal is configured")
    g.add_argument("--domain", metavar="NAME", help="domain, on a Multi-Domain Server")
    g.add_argument("--credentials", metavar="FILE",
                   help="file with CP_MGMT_API_KEY=..., or CP_MGMT_USER=... and CP_MGMT_PASSWORD=... "
                        "(the same names are read from the environment; otherwise you are asked)")
    t = g.add_mutually_exclusive_group()
    t.add_argument("--mgmt-fingerprint", metavar="SHA256", help="accept only the certificate with this SHA-256 fingerprint")
    t.add_argument("--mgmt-ca-file", metavar="PEM", help="CA certificate that signed the management server's certificate")
    t.add_argument("--mgmt-insecure", action="store_true", help="do not verify the management server's certificate")
    g.add_argument("--mgmt-use-proxy", action="store_true", help="reach the management server through the environment's proxy")


def _add_entra(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("Microsoft Entra ID")
    g.add_argument("--tenant", metavar="ID|DOMAIN", help="tenant to sign in to")
    g.add_argument("--login", choices=["device", "browser"], default="device",
                   help="how to sign in: a code to enter at microsoft.com/devicelogin (default), or a browser window "
                        "on this machine (for tenants that block the device code flow)")
    g.add_argument("--app-name", metavar="NAME", help="enterprise application name (default: Check Point Captive Portal (<gateway>))")
    g.add_argument("--use-az-cli", action="store_true", help="use the token of an existing 'az login' session instead of a device code")
    g.add_argument("--client-id", default=entra.DEFAULT_CLIENT_ID, metavar="GUID",
                   help="public client used for the device code sign-in (default: Microsoft Graph Command Line Tools)")


def _add_portal_tls(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("portal check")
    g.add_argument("--portal-insecure", action="store_true", help="do not verify the portal's certificate during the check")
    g.add_argument("--skip-portal-check", action="store_true", help="do not open the portal after the change")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cp-entra-saml",
        description="SAML sign-in for the Check Point Identity Awareness Captive Portal with Microsoft Entra ID "
                    "(or any SAML identity provider): set it up, check it, and read a failed sign-in capture.")
    p.add_argument("--version", action="version", version="cp-entra-saml " + __version__)
    sub = p.add_subparsers(dest="command", metavar="<command>")

    s = sub.add_parser("setup", help="configure both sides and switch the portal to SAML")
    _add_mgmt(s)
    _add_entra(s)
    g = s.add_argument_group("what to configure")
    g.add_argument("--idp-metadata", metavar="FILE|URL",
                   help="use this SAML metadata instead of Microsoft Entra (Okta, ADFS, a test identity provider, ...)")
    g.add_argument("--idp-name", metavar="NAME", help="name of the identity provider object in Check Point")
    g.add_argument("--assign", action="append", metavar="USER|GROUP",
                   help="Entra user (UPN) or group (name or object id) allowed to sign in; repeatable")
    g.add_argument("--everyone", action="store_true", help="let every user of the tenant sign in")
    g.add_argument("--only", action="store_true", help="make this the portal's only identity provider (default: keep others)")
    g.add_argument("--install-policy", metavar="PACKAGE", help="install this policy package on the gateway afterwards")
    g.add_argument("--allow-root-portal", action="store_true", help="proceed although the portal Main URL has no path")
    g.add_argument("--dry-run", action="store_true", help="show the plan and change nothing")
    g.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    _add_portal_tls(s)
    s.set_defaults(func=cmd_setup)

    s = sub.add_parser("status", help="show what is configured and whether both sides agree")
    _add_mgmt(s)
    _add_entra(s)
    _add_portal_tls(s)
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("teardown", help="remove the identity provider from the portal")
    _add_mgmt(s)
    _add_entra(s)
    g = s.add_argument_group("what to remove")
    g.add_argument("--idp-name", metavar="NAME")
    g.add_argument("--delete-entra-app", action="store_true", help="also delete the Entra application")
    g.add_argument("--restore-method", default="username and password",
                   choices=["username and password", "defined on user record", "radius"],
                   help="portal authentication to go back to when no identity provider is left")
    g.add_argument("--install-policy", metavar="PACKAGE")
    g.add_argument("--yes", action="store_true")
    s.set_defaults(func=cmd_teardown)

    s = sub.add_parser("portal", help="check a live portal as an anonymous browser (no sign-in)")
    s.add_argument("url", help="portal address, for example https://portal.example.com/connect")
    s.add_argument("--portal-insecure", action="store_true", help="do not verify the portal's certificate")
    s.add_argument("--portal-fingerprint", metavar="SHA256")
    s.add_argument("--portal-ca-file", metavar="PEM")
    s.add_argument("--portal-use-proxy", action="store_true", help="reach the portal through the environment's proxy")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_portal)

    s = sub.add_parser("har", help="explain a browser capture (HAR) of a failed SAML sign-in")
    s.add_argument("file")
    s.add_argument("--sanitize", metavar="OUT", help="also write a copy with passwords, cookies and tokens removed")
    s.add_argument("--redact-assertion", action="store_true", help="with --sanitize: remove the SAML assertion as well")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_har)

    s = sub.add_parser("fingerprint", help="print a server's certificate fingerprint, for --mgmt-fingerprint")
    s.add_argument("server", metavar="HOST[:PORT]")
    s.add_argument("--use-proxy", action="store_true")
    s.set_defaults(func=cmd_fingerprint)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_ERROR
    try:
        return args.func(args)
    except ops.Abort as e:
        return fail(str(e))
    except (checkpoint.ApiError, checkpoint.TaskFailed, checkpoint.Unsupported, entra.GraphError, entra.AuthError,
            httpc.HttpError, har.HarError, portal.PortalError, OSError, ValueError) as e:
        return fail(str(e))
    except KeyboardInterrupt:
        return fail("interrupted")


if __name__ == "__main__":
    sys.exit(main())
