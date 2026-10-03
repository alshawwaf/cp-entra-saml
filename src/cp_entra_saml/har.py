"""Analysis of a browser HAR capture of a Captive Portal SAML sign-in.

Answers three questions an engineer has when a customer sends a capture:
where did the flow stop, do the identity provider's values match what the
gateway asked for, and what secrets does the file contain.

Secret values are never printed. Findings name the field and the entry only.
"""
from __future__ import annotations

import base64
import copy
import json
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

from . import saml

REDACTED = "[redacted]"

# name pattern -> kind. "credential" means: rotate it. "session" means: it expires
# on its own, but treat the file as sensitive until then.
_SECRET_PARAMS = (
    (re.compile(r"^(passwd|password|pwd|passphrase|pin|client_secret|secret)$", re.I), "credential"),
    (re.compile(r"^(flowtoken|ctx|canary|access_token|refresh_token|id_token|code|assertion|otp|otc)$", re.I), "session"),
    (re.compile(r"^SAMLResponse$"), "assertion"),
)
_SECRET_HEADERS = re.compile(r"^(cookie|set-cookie|authorization|proxy-authorization|x-chkp-sid|x-api-key)$", re.I)
_HANDOFF_PASSWORD = re.compile(r"(password\s*:\s*')([0-9A-Fa-f]{16,})(')")
_HEX_TOKEN = re.compile(r"^[0-9A-Fa-f]{16,}$")
_NAC_URL = re.compile(r'var\s+nacUrl\s*=\s*("(?:[^"\\]|\\.)*")')
_NAC_CONCAT = re.compile(r'nacUrl\s*\+\s*"([^"]*)"')
_AADSTS = re.compile(r"AADSTS\d{5,7}")
_IDP_HOSTS = ("login.microsoftonline.com", "login.microsoftonline.us", "login.partner.microsoftonline.cn",
              "login.windows.net", "sts.windows.net")


class HarError(Exception):
    pass


def load(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "cp1252"):
        try:
            data = json.loads(raw.decode(enc))
            break
        except UnicodeDecodeError:
            continue
        except ValueError as e:
            raise HarError("%s is not JSON: %s" % (path, e)) from e
    else:
        raise HarError("%s is not a text file" % path)
    if not isinstance(data, dict) or "entries" not in data.get("log", {}):
        raise HarError("%s is not a HAR file (no log.entries)" % path)
    return data


# -- helpers ------------------------------------------------------------------
def _body(entry: dict) -> str:
    c = entry.get("response", {}).get("content", {}) or {}
    t = c.get("text") or ""
    if c.get("encoding") == "base64":
        try:
            t = base64.b64decode(t).decode("utf-8", "replace")
        except Exception:
            t = ""
    return t


def _post_params(entry: dict) -> List[Tuple[str, str]]:
    pd = entry.get("request", {}).get("postData") or {}
    if pd.get("params"):
        return [(p.get("name", ""), urllib.parse.unquote_plus(p.get("value") or "")) for p in pd["params"]]
    text = pd.get("text") or ""
    mime = (pd.get("mimeType") or "").lower()
    if "x-www-form-urlencoded" in mime and text:
        return urllib.parse.parse_qsl(text, keep_blank_values=True)
    if "json" in mime and text:
        try:
            obj = json.loads(text)
        except ValueError:
            return []
        if isinstance(obj, dict):
            return [(k, v if isinstance(v, str) else json.dumps(v)) for k, v in obj.items()]
    return []


def _short(url: str, limit: int = 110) -> str:
    u = urllib.parse.urlsplit(url)
    s = "%s://%s%s" % (u.scheme, u.netloc, u.path)
    if u.query:
        names = [p.split("=", 1)[0] for p in u.query.split("&")]
        s += "?" + "&".join(n + "=…" for n in names[:6])
    return s if len(s) <= limit else s[:limit - 1] + "…"


def _browser_url(url: str) -> str:
    """The way a browser shows a resolved URL: host lower-cased, path never empty."""
    u = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((u.scheme, u.netloc.lower(), u.path or "/", u.query, u.fragment))


def _host(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def _finding(fid: str, severity: str, title: str, detail: str, entries: List[int], fix: str = "") -> dict:
    return {"id": fid, "severity": severity, "title": title, "detail": detail, "entries": entries, "fix": fix}


# -- analysis -----------------------------------------------------------------
def analyze(har: dict) -> dict:
    entries = har["log"]["entries"]
    findings: List[dict] = []
    report: dict = {"entry_count": len(entries), "findings": findings}

    # 1. AuthnRequest (redirect binding): the URL that left the portal for the IdP.
    authn: Optional[dict] = None
    authn_idx: Optional[int] = None
    for i, e in enumerate(entries):
        for url in (e.get("response", {}).get("redirectURL") or "", e.get("request", {}).get("url") or ""):
            if "SAMLRequest=" in url:
                try:
                    authn = saml.decode_redirect_request(url)
                    authn["idp_url"] = _short(url)
                    authn_idx = i
                except saml.SamlError as ex:
                    findings.append(_finding("authn-request-unreadable", "warning",
                                             "The SAML request could not be decoded", str(ex), [i]))
                break
        if authn or authn_idx is not None:
            break
    report["authn_request"] = authn
    sp_host = _host(authn["acs_url"]) if authn and authn.get("acs_url") else ""

    # 2. SAML response posted to the gateway's ACS.
    resp: Optional[dict] = None
    acs_idx: Optional[int] = None
    for i, e in enumerate(entries):
        if e.get("request", {}).get("method") != "POST":
            continue
        for name, value in _post_params(e):
            if name == "SAMLResponse":
                acs_idx = i
                try:
                    resp = saml.decode_response(value)
                except saml.SamlError as ex:
                    findings.append(_finding("saml-response-unreadable", "warning",
                                             "The SAML response could not be decoded", str(ex), [i]))
                break
        if acs_idx is not None:
            break
    report["saml_response"] = resp
    if not sp_host and acs_idx is not None:
        sp_host = _host(entries[acs_idx]["request"]["url"])
    report["portal_host"] = sp_host

    # 3. Identity-provider error pages.
    for i, e in enumerate(entries):
        url = e.get("request", {}).get("url", "")
        if _host(url) in _IDP_HOSTS and e.get("_resourceType", "document") in ("document", "xhr", "fetch"):
            codes = sorted(set(_AADSTS.findall(_body(e))) | set(_AADSTS.findall(urllib.parse.unquote(url))))
            if codes:
                findings.append(_finding(
                    "idp-error", "error", "Microsoft Entra returned an error: %s" % ", ".join(codes),
                    "The sign-in stopped at the identity provider, before any assertion was issued.", [i],
                    "Look the code up at https://login.microsoftonline.com/error and compare the Identifier and "
                    "Reply URL of the enterprise application with the values in the SAML request below."))

    if authn and acs_idx is None and not any(f["id"] == "idp-error" for f in findings):
        findings.append(_finding(
            "no-assertion", "warning", "The browser never posted a SAML response back to the portal",
            "The capture shows the redirect to the identity provider but no POST with a SAMLResponse. "
            "Either the sign-in was not completed or the capture ended early.", [authn_idx or 0]))

    # 4. Consistency between request and response.
    if resp:
        status = str(resp.get("status") or "")
        if not status.endswith(":Success"):
            findings.append(_finding(
                "saml-status", "error", "The identity provider answered with status %s" % status.rsplit(":", 1)[-1],
                "Status detail: %s %s" % (", ".join(s.rsplit(":", 1)[-1] for s in resp.get("status_detail") or []) or "none",
                                         resp.get("status_message") or ""), [acs_idx or 0]))
        if authn:
            auds = resp.get("audiences") or []
            if auds and authn.get("issuer") and authn["issuer"] not in auds:
                findings.append(_finding(
                    "audience-mismatch", "error", "Audience in the assertion is not the gateway's Entity ID",
                    "Gateway Entity ID: %s. Audience sent by the identity provider: %s."
                    % (authn["issuer"], ", ".join(auds)), [acs_idx or 0],
                    "Set the Identifier (Entity ID) of the application at the identity provider to the gateway's value."))
            if resp.get("recipient") and authn.get("acs_url") and resp["recipient"] != authn["acs_url"]:
                findings.append(_finding(
                    "recipient-mismatch", "error", "Recipient in the assertion is not the gateway's Reply URL",
                    "Gateway Reply URL: %s. Recipient sent: %s." % (authn["acs_url"], resp["recipient"]), [acs_idx or 0],
                    "Set the Reply URL (ACS) of the application at the identity provider to the gateway's value."))
            if resp.get("in_response_to") and authn.get("id") and resp["in_response_to"] != authn["id"]:
                findings.append(_finding(
                    "inresponseto-mismatch", "warning", "The response answers a different request",
                    "InResponseTo does not match the ID of the request in this capture (a second sign-in "
                    "attempt, or a stale browser tab).", [acs_idx or 0]))
        if resp.get("encrypted_assertion"):
            findings.append(_finding(
                "encrypted-assertion", "warning", "The assertion is encrypted",
                "Its content cannot be checked from the capture. Token encryption is not part of the documented "
                "Check Point setup; turn it off at the identity provider unless it was configured deliberately.", [acs_idx or 0]))

    # 5. What the gateway did with the assertion.
    if acs_idx is not None:
        st = entries[acs_idx].get("response", {}).get("status")
        report["acs_status"] = st
        if st not in (200, 302, 303):
            findings.append(_finding(
                "acs-rejected", "error", "The gateway answered the assertion with HTTP %s" % st,
                "The portal did not accept the SAML response. Check the SAML portal log on the gateway.", [acs_idx]))

    # 6. The hand-off page: after the assertion is accepted the SAML portal serves a page
    #    that posts a one-time credential to the Captive Portal's Login action.
    handoff_idx: Optional[int] = None
    for i, e in enumerate(entries):
        if acs_idx is not None and i <= acs_idx:
            continue
        body = _body(e)
        m = _NAC_URL.search(body)
        if not m:
            continue
        handoff_idx = i
        page_url = e["request"]["url"]
        try:
            nac = json.loads(m.group(1))
        except ValueError:
            break
        report["handoff"] = {"entry": i, "nacUrl": nac, "targets": []}
        for suffix in sorted(set(_NAC_CONCAT.findall(body))):
            target = _browser_url(urllib.parse.urljoin(page_url, nac + suffix))
            ok = _host(target) == _host(page_url)
            report["handoff"]["targets"].append({"expression": 'nacUrl + "%s"' % suffix, "resolves_to": target, "same_host": ok})
            if not ok and suffix.lstrip("/").lower().startswith("login"):
                findings.append(_finding(
                    "handoff-scheme-relative", "error",
                    "The portal's own hand-off page posts the login to %s instead of the portal" % target,
                    'The page served after the assertion was accepted sets nacUrl = "%s" and calls nacUrl + "%s", '
                    'which is "%s". A browser reads a URL that starts with two slashes as a host name, so the '
                    "request leaves for a host that does not exist and the user is left on a blank page with no "
                    "session. The identity provider configuration is not involved: the gateway had already accepted "
                    "the assertion. A nacUrl of \"/\" means the Captive Portal is published at the root of its host "
                    "name; under a path such as /connect the same line stays on the portal."
                    % (nac, suffix, nac + suffix), [i],
                    "Publish the portal under a path (Main URL https://<host>/connect), install policy, then update "
                    "the Identifier and Reply URL at the identity provider, because both contain the portal path. "
                    "Report the behaviour to Check Point Support."))
        break

    # 7. Requests that never got an answer.
    for i, e in enumerate(entries):
        r = e.get("response", {})
        if r.get("status") == 0 and r.get("_error"):
            url = e["request"]["url"]
            h = _host(url)
            if "." not in h and h not in ("localhost",):
                findings.append(_finding(
                    "request-to-bare-host", "error" if handoff_idx is None else "info",
                    "A request went to the non-existent host %r" % h,
                    "%s %s failed with %s." % (e["request"]["method"], _short(url), r["_error"]), [i]))

    if acs_idx is not None and report.get("acs_status") in (302, 303) and handoff_idx is None:
        findings.append(_finding(
            "no-handoff", "info", "The capture ends after the gateway accepted the assertion",
            "No hand-off page was recorded, so the last step (the POST to the portal's Login action) cannot be judged.",
            [acs_idx]))

    # 8. What the assertion says about the user (matters for Access Roles).
    if resp and resp.get("has_assertion"):
        nameid = str(resp.get("nameid") or "")
        shape = "an e-mail style name" if "@" in nameid else ("a DOMAIN\\user name" if "\\" in nameid else "a plain name")
        groups = resp.get("group_claims") or []
        findings.append(_finding(
            "identity-shape", "info",
            "The user is identified by %s (NameID format %s)%s"
            % (shape, str(resp.get("nameid_format") or "unspecified").rsplit(":", 1)[-1],
               "; group claims: " + ", ".join(g.rsplit("/", 1)[-1] for g in groups) if groups else "; no group claim"),
            "The gateway needs to resolve this name to a user and groups before an Access Role can match. "
            + ("" if groups else "With no group claim in the assertion, group membership has to come from a "
               "directory lookup on the gateway (the name must be findable in the configured user directory)."),
            [acs_idx or 0]))

    report["secrets"] = find_secrets(har)
    creds = [s for s in report["secrets"] if s["kind"] == "credential"]
    if creds:
        findings.insert(0, _finding(
            "credential-in-capture", "error", "The capture contains a password in clear text",
            "Field %s in entry %s. Browser HAR exports remove cookies but keep form bodies."
            % (", ".join(sorted(set(s["name"] for s in creds))), ", ".join(str(s["entry"]) for s in creds)),
            [s["entry"] for s in creds],
            "Change that password now and delete every copy of the file. Use --sanitize to produce a copy that is safe to share."))

    report["timeline"] = _timeline(entries, sp_host)
    return report


def _timeline(entries: List[dict], sp_host: str) -> List[dict]:
    out = []
    for i, e in enumerate(entries):
        rq, rs = e.get("request", {}), e.get("response", {})
        url = rq.get("url", "")
        kind = e.get("_resourceType", "")
        failed = rs.get("status") == 0
        on_portal = sp_host and _host(url) == sp_host
        if not (failed or kind == "document" or rs.get("redirectURL") or (on_portal and kind in ("xhr", "fetch"))):
            continue
        out.append({"entry": i, "time": (e.get("startedDateTime") or "")[11:23], "method": rq.get("method"),
                    "status": rs.get("status"), "url": _short(url),
                    "note": rs.get("_error") or ("-> " + _short(rs["redirectURL"]) if rs.get("redirectURL") else "")})
    return out


# -- secrets ------------------------------------------------------------------
def _param_kind(name: str) -> Optional[str]:
    for pat, kind in _SECRET_PARAMS:
        if pat.match(name):
            return kind
    return None


def find_secrets(har: dict) -> List[dict]:
    """Where the file holds secrets: entry, location, field name, kind, length. No values."""
    out: List[dict] = []
    for i, e in enumerate(har["log"]["entries"]):
        rq, rs = e.get("request", {}), e.get("response", {})
        host = _host(rq.get("url", ""))
        params = _post_params(e)
        handoff = any(k == "realm" for k, _ in params)
        for name, value in params:
            kind = _param_kind(name)
            if not kind or not value or value == REDACTED:
                continue
            if handoff and name == "password" and _HEX_TOKEN.match(value):
                # The SAML portal's hand-off to the Captive Portal, not something the user typed.
                name, kind = "one-time portal login token", "session"
            out.append({"entry": i, "host": host, "where": "request body", "name": name, "kind": kind, "length": len(value)})
        for side, label in ((rq, "request header"), (rs, "response header")):
            for h in side.get("headers") or []:
                if _SECRET_HEADERS.match(h.get("name", "")) and h.get("value") and h["value"] != REDACTED:
                    out.append({"entry": i, "host": host, "where": label, "name": h["name"], "kind": "session", "length": len(h["value"])})
        if _HANDOFF_PASSWORD.search(_body(e)):
            out.append({"entry": i, "host": host, "where": "response body", "name": "one-time portal login token",
                        "kind": "session", "length": 0})
    return out


def _redact_url(url: str, secret) -> str:
    u = urllib.parse.urlsplit(url)
    if not u.query:
        return url
    pairs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    if not any(secret(k) and v for k, v in pairs):
        return url
    q = urllib.parse.urlencode([(k, REDACTED if secret(k) and v else v) for k, v in pairs])
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, q, u.fragment))


def _scrub(node, needles: List[str]):
    """Replace every occurrence of the given values in every string of a JSON tree.
    Returns (node, number of strings changed)."""
    if isinstance(node, str):
        new = node
        for v in needles:
            if v in new:
                new = new.replace(v, REDACTED)
        return new, int(new != node)
    n = 0
    if isinstance(node, list):
        for i, item in enumerate(node):
            node[i], k = _scrub(item, needles)
            n += k
    elif isinstance(node, dict):
        for key in list(node):
            node[key], k = _scrub(node[key], needles)
            n += k
    return node, n


def sanitize(har: dict, redact_assertion: bool = False) -> Tuple[dict, int]:
    """Copy of the capture with secret values replaced. Returns (copy, replacements).

    Three passes: fields known to hold secrets; identity-provider response bodies
    (sign-in pages embed the same flow tokens); then a search for any remaining
    copy of a secret value anywhere in the file.
    """
    out = copy.deepcopy(har)
    n = 0
    values = set()

    def secret(name: str) -> bool:
        kind = _param_kind(name)
        return bool(kind) and (kind != "assertion" or redact_assertion)

    for e in out["log"]["entries"]:
        rq, rs = e.get("request", {}), e.get("response", {})
        for name, value in _post_params(e):
            if secret(name) and value and value != REDACTED:
                values.add(value)
        for side in (rq, rs):
            for h in side.get("headers") or []:
                if _SECRET_HEADERS.match(h.get("name", "")) and h.get("value"):
                    h["value"] = REDACTED
                    n += 1
            for c in side.get("cookies") or []:
                if c.get("value"):
                    values.add(c["value"])
                    c["value"] = REDACTED
                    n += 1
        for q in rq.get("queryString") or []:
            if secret(q.get("name", "")) and q.get("value"):
                values.add(urllib.parse.unquote_plus(q["value"]))
                q["value"] = REDACTED
                n += 1
        for holder, key in ((rq, "url"), (rs, "redirectURL")):
            if holder.get(key):
                holder[key] = _redact_url(holder[key], secret)
        pd = rq.get("postData")
        if pd:
            had_params = bool(pd.get("params"))
            for p in pd.get("params") or []:
                if secret(p.get("name", "")) and p.get("value"):
                    p["value"] = REDACTED
                    n += 1
            text = pd.get("text") or ""
            mime = (pd.get("mimeType") or "").lower()
            if text and "x-www-form-urlencoded" in mime:
                pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
                hits = sum(1 for k, v in pairs if secret(k) and v)
                if hits:
                    pd["text"] = urllib.parse.urlencode([(k, REDACTED if secret(k) and v else v) for k, v in pairs])
                    n += 0 if had_params else hits
            elif text and "json" in mime:
                try:
                    obj = json.loads(text)
                except ValueError:
                    obj = None
                if isinstance(obj, dict):
                    hits = [k for k in obj if secret(k) and obj[k]]
                    for k in hits:
                        obj[k] = REDACTED
                    if hits:
                        pd["text"] = json.dumps(obj)
                        n += len(hits)
        c = rs.get("content") or {}
        if c.get("text"):
            if _host(rq.get("url", "")) in _IDP_HOSTS and e.get("_resourceType", "document") in ("document", "xhr", "fetch"):
                # Sign-in pages and their JSON calls carry flow tokens; keep only the error codes.
                codes = sorted(set(_AADSTS.findall(_body(e))))
                c["text"] = "[response body removed by sanitize]" + (" " + " ".join(codes) if codes else "")
                c.pop("encoding", None)
                n += 1
            elif c.get("encoding") != "base64":
                m = _HANDOFF_PASSWORD.search(c["text"])
                if m:
                    values.add(m.group(2))
                    c["text"] = _HANDOFF_PASSWORD.sub(lambda mm: mm.group(1) + REDACTED + mm.group(3), c["text"])
                    n += 1

    # Last pass: the same value can sit elsewhere (another body, a URL, a referrer).
    needles = set()
    for v in values:
        if len(v) < 6:
            continue  # too short to search for without damaging unrelated text
        needles.update((v, urllib.parse.quote(v, safe=""), urllib.parse.quote_plus(v)))
    needles.discard(REDACTED)
    _, k = _scrub(out, sorted(needles, key=len, reverse=True))
    return out, n + k


# -- text report --------------------------------------------------------------
def render(report: dict) -> str:
    lines: List[str] = []
    w = lines.append
    order = {"error": 0, "warning": 1, "info": 2}
    fs = sorted(report["findings"], key=lambda f: order.get(f["severity"], 3))
    w("Findings")
    if not fs:
        w("  none")
    for f in fs:
        w("  [%s] %s" % (f["severity"].upper(), f["title"]))
        w("      " + f["detail"].strip())
        if f.get("fix"):
            w("      Fix: " + f["fix"])
        w("      Capture entries: " + ", ".join(str(x) for x in f["entries"]))
    a = report.get("authn_request")
    if a:
        w("")
        w("What the gateway asked for (SAML request)")
        w("  Entity ID (Identifier): %s" % a.get("issuer"))
        w("  Reply URL (ACS):        %s" % a.get("acs_url"))
        w("  Sent to:                %s" % a.get("destination"))
        w("  NameID format asked:    %s" % (a.get("nameid_format") or "none"))
    r = report.get("saml_response")
    if r:
        w("")
        w("What the identity provider answered (SAML response)")
        w("  Status:     %s" % str(r.get("status")).rsplit(":", 1)[-1])
        w("  Issuer:     %s" % r.get("issuer"))
        if r.get("has_assertion"):
            w("  Audience:   %s" % ", ".join(r.get("audiences") or []))
            w("  Recipient:  %s" % r.get("recipient"))
            w("  NameID:     %s (%s)" % (r.get("nameid"), str(r.get("nameid_format") or "").rsplit(":", 1)[-1]))
            w("  Valid:      %s to %s" % (r.get("not_before"), r.get("not_on_or_after")))
            w("  Signed:     assertion %s, response %s" % ("yes" if r.get("assertion_signed") else "no",
                                                         "yes" if r.get("response_signed") else "no"))
            w("  Attributes: %s" % ", ".join(n.rsplit("/", 1)[-1] for n in (r.get("attributes") or {})))
    h = report.get("handoff")
    if h:
        w("")
        w("Portal hand-off page (entry %d): nacUrl = %s" % (h["entry"], json.dumps(h["nacUrl"])))
        for t in h["targets"]:
            w("  %-22s -> %s%s" % (t["expression"], t["resolves_to"], "" if t["same_host"] else "   <-- leaves the portal"))
    w("")
    w("Flow")
    for t in report.get("timeline", []):
        w("  %3d %s %-4s %3s %s %s" % (t["entry"], t["time"], t["method"], t["status"], t["url"], t["note"]))
    s = report.get("secrets") or []
    w("")
    w("Secrets in this file (values are not shown)")
    if not s:
        w("  none found")
    seen = set()
    for x in s:
        key = (x["kind"], x["where"], x["name"], x["host"])
        if key in seen:
            continue
        seen.add(key)
        count = sum(1 for y in s if (y["kind"], y["where"], y["name"], y["host"]) == key)
        w("  %-10s %-15s %-28s %s%s" % (x["kind"], x["where"], x["name"], x["host"], " (x%d)" % count if count > 1 else ""))
    return "\n".join(lines) + "\n"
