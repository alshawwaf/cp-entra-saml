"""Small HTTPS client on top of http.client.

The standard library is used on purpose: the tool has to run on an administrator
workstation and on a Check Point management server without installing anything.

What this adds over urllib:
  * redirects are never followed implicitly (the portal checks need to see them)
  * certificate pinning by SHA-256 fingerprint, checked before any request is sent
  * a per-client choice between a direct connection and the environment's proxy
"""
from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

USER_AGENT = "cp-entra-saml"


class HttpError(Exception):
    """Transport-level failure: no HTTP response was obtained."""


class PinMismatch(HttpError):
    """The server certificate does not match the pinned fingerprint."""


class Response:
    def __init__(self, status: int, headers: List[Tuple[str, str]], body: bytes, url: str):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url

    def header(self, name: str) -> Optional[str]:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def header_all(self, name: str) -> List[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.body.decode("utf-8-sig", "replace"))


def normalize_fingerprint(value: str) -> str:
    """'SHA256:AB:CD..', 'ab cd', 'abcd' -> lower-case hex without separators."""
    v = value.strip()
    if v.lower().startswith("sha256:"):
        v = v[7:]
    v = v.replace(":", "").replace(" ", "").replace("-", "").lower()
    if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
        raise ValueError("a certificate fingerprint is 64 hexadecimal characters (SHA-256)")
    return v


def format_fingerprint(hexdigest: str) -> str:
    h = hexdigest.upper()
    return "SHA256:" + ":".join(h[i:i + 2] for i in range(0, len(h), 2))


class Client:
    """One client per remote system (management server, portal, Microsoft)."""

    def __init__(self, verify: bool = True, ca_file: Optional[str] = None,
                 fingerprint: Optional[str] = None, use_env_proxy: bool = True,
                 timeout: float = 30.0):
        self.timeout = timeout
        self.use_env_proxy = use_env_proxy
        self.fingerprint = normalize_fingerprint(fingerprint) if fingerprint else None
        self.verify = verify and not self.fingerprint
        if self.verify:
            self.context = ssl.create_default_context(cafile=ca_file)
        else:
            # Either pinned (checked in _connect) or explicitly insecure.
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.seen_fingerprints: Dict[str, str] = {}

    # -- connection -----------------------------------------------------------
    def _proxy_for(self, scheme: str, host: str) -> Optional[Tuple[str, int]]:
        if not self.use_env_proxy:
            return None
        try:
            if urllib.request.proxy_bypass(host):
                return None
        except Exception:
            pass
        proxy = urllib.request.getproxies().get(scheme)
        if not proxy:
            return None
        p = urllib.parse.urlsplit(proxy if "//" in proxy else "//" + proxy)
        if not p.hostname:
            return None
        return p.hostname, p.port or (443 if p.scheme == "https" else 8080)

    def _connect(self, scheme: str, host: str, port: int) -> http.client.HTTPConnection:
        proxy = self._proxy_for(scheme, host)
        if scheme == "https":
            if proxy:
                conn = http.client.HTTPSConnection(proxy[0], proxy[1], timeout=self.timeout, context=self.context)
                conn.set_tunnel(host, port)
            else:
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=self.context)
        else:
            if proxy:
                raise HttpError("plain http through a proxy is not supported; use https")
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
        conn.connect()
        if scheme == "https":
            der = conn.sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
            digest = hashlib.sha256(der or b"").hexdigest()
            self.seen_fingerprints["%s:%d" % (host, port)] = digest
            if self.fingerprint and digest != self.fingerprint:
                conn.close()
                raise PinMismatch(
                    "certificate of %s:%d is %s, which is not the pinned fingerprint"
                    % (host, port, format_fingerprint(digest)))
        return conn

    # -- request --------------------------------------------------------------
    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None,
                body: Optional[bytes] = None, json_body=None) -> Response:
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise HttpError("not an http(s) URL: %r" % url)
        port = u.port or (443 if u.scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        conn = None
        try:
            conn = self._connect(u.scheme, u.hostname, port)
            conn.request(method, path, body=body, headers=hdrs)
            r = conn.getresponse()
            data = r.read()
            return Response(r.status, r.getheaders(), data, url)
        except HttpError:
            raise
        except ValueError:
            # http.client quotes the offending header in its message, and a header can hold a token.
            raise HttpError("%s %s was not sent: a request header contains characters that are not allowed"
                            % (method, _origin(url))) from None
        except ssl.SSLCertVerificationError as e:
            raise HttpError(
                "TLS certificate of %s was not accepted (%s). Pin it with its SHA-256 fingerprint, "
                "supply a CA file, or disable verification explicitly." % (u.hostname, e.verify_message)) from e
        except (OSError, http.client.HTTPException, socket.timeout) as e:
            raise HttpError("%s %s failed: %s" % (method, _origin(url), e)) from e
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def request_retry(self, method: str, url: str, attempts: int = 4, idempotent: bool = True, **kw) -> Response:
        """Retry on 429, honouring Retry-After. An idempotent request is also retried on transport
        errors and on 502/503/504. A request that creates something may have been carried out even
        though its answer was lost, so it is not sent twice."""
        retry_status = (429, 502, 503, 504) if idempotent else (429,)
        delay = 2.0
        last: Optional[Exception] = None
        for i in range(attempts):
            try:
                r = self.request(method, url, **kw)
            except PinMismatch:
                raise
            except HttpError as e:
                if not idempotent:
                    raise
                last = e
            else:
                if r.status not in retry_status or i == attempts - 1:
                    return r
                ra = r.header("Retry-After")
                if ra and ra.isdigit():
                    delay = min(float(ra), 60.0)
            if i < attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 30.0)
        assert last is not None
        raise last


def _origin(url: str) -> str:
    """scheme://host[:port]/path without the query string, for error messages."""
    u = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "", ""))
