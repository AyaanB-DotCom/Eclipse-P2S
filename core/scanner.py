"""Bounded, non-destructive HTTP inspection.

Only HEAD (and at most one GET, with the body never read) requests are sent.
Hostnames are resolved once per hop, every resolved address must be public
unless ``allow_local`` is set, and the connection is pinned to the validated
address, which closes the usual resolve-then-connect (DNS rebinding) gap for the
connection itself. Environment proxies are never used. See docs/DETECTION.md
for residual limitations.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import threading
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

from . import fingerprint
from .textsafe import sanitize_text

USER_AGENT = "Eclipse-P2S/1.0 (passive PHP version auditor)"
MAX_URL_LENGTH = 2048
MAX_HEADER_COUNT = 100
MAX_HEADER_VALUE = 2048
MAX_ADDRESSES = 3
REDIRECT_STATUSES = (301, 302, 303, 307, 308)

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


class ScanError(Exception):
    """A readable inspection failure. `kind` is a short machine-friendly tag."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass
class Observation:
    requested_url: str
    final_url: str
    status: int
    headers: List[Tuple[str, str]]
    methods: List[str] = field(default_factory=list)
    redirects: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


# ------------------------------------------------------------ URL handling

def normalize_url(raw: object) -> str:
    """Validate user input and return a canonical http(s) URL (HTTPS if no scheme)."""
    if not isinstance(raw, str):
        raise ScanError("invalid_url", "The target must be text.")
    text = raw.strip()
    if not text:
        raise ScanError("invalid_url", "Enter a URL or hostname.")
    if len(text) > MAX_URL_LENGTH:
        raise ScanError("invalid_url", "The URL is too long.")
    if any(ch.isspace() or unicodedata.category(ch)[0] == "C" for ch in text):
        raise ScanError("invalid_url", "The URL contains spaces or control characters.")
    match = _SCHEME_RE.match(text)
    if match:
        scheme = match.group(1).lower()
        if scheme not in ("http", "https"):
            raise ScanError("invalid_url", "Unsupported URL scheme '%s'. Only http and https are allowed."
                            % sanitize_text(scheme, 20))
        text = scheme + text[match.end() - 3:]
    else:
        scheme = "https"
        text = "https://" + text
    try:
        parts = urllib.parse.urlsplit(text)
        port = parts.port
    except ValueError:
        raise ScanError("invalid_url", "The URL could not be parsed (check host and port).")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise ScanError("invalid_url", "URLs with embedded credentials are not accepted.")
    host = parts.hostname
    if not host:
        raise ScanError("invalid_url", "The URL has no hostname.")
    if port is not None and not 1 <= port <= 65535:
        raise ScanError("invalid_url", "The port must be between 1 and 65535.")
    host = _validate_host(host)
    netloc = "[%s]" % host if ":" in host else host
    if port is not None:
        netloc += ":%d" % port
    path = parts.path or "/"
    return urllib.parse.urlunsplit((scheme, netloc, path, parts.query, ""))


def _validate_host(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.rstrip(".")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ScanError("invalid_url", "The hostname is not valid.")
    labels = ascii_host.split(".")
    if not ascii_host or len(ascii_host) > 253 or not all(_LABEL_RE.match(label) for label in labels):
        raise ScanError("invalid_url", "The hostname is not valid.")
    return ascii_host.lower()


def is_public_address(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def resolve_host(host: str, port: int, resolver: Callable = socket.getaddrinfo,
                 allow_local: bool = False) -> List[str]:
    """Resolve a host and enforce the address policy. Every address must pass."""
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        try:
            infos = resolver(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ScanError("dns", "DNS lookup failed for %s (%s)." % (sanitize_text(host, 100),
                                                                       sanitize_text(exc.strerror or exc, 100)))
        except UnicodeError:
            raise ScanError("dns", "The hostname could not be resolved.")
        addresses = []
        for info in infos:
            ip = info[4][0]
            if ip not in addresses:
                addresses.append(ip)
    if not addresses:
        raise ScanError("dns", "DNS lookup returned no addresses for %s." % sanitize_text(host, 100))
    if not allow_local:
        for ip in addresses:
            if not is_public_address(ip):
                raise ScanError("blocked_target",
                                "Blocked: %s resolves to a non-public address (%s). Loopback, private, "
                                "link-local and metadata addresses are refused by default."
                                % (sanitize_text(host, 100), sanitize_text(ip, 64)))
    return addresses[:MAX_ADDRESSES]


# --------------------------------------------------------- HTTP exchange

class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def http_exchange(scheme: str, host: str, port: int, ip: str, target: str, method: str,
                  timeout: float) -> Tuple[int, List[Tuple[str, str]]]:
    """Send one request to a pinned address and return (status, headers). Body is never read."""
    cls = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
    conn = cls(host, port, ip, timeout)
    watchdog = threading.Timer(timeout * 2, conn.close)
    watchdog.daemon = True
    watchdog.start()
    try:
        conn.request(method, target, headers={
            "User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity",
            "Connection": "close"})
        resp = conn.getresponse()
        headers = [(sanitize_text(k, 128), sanitize_text(v, MAX_HEADER_VALUE))
                   for k, v in resp.getheaders()[:MAX_HEADER_COUNT]]
        return resp.status, headers
    finally:
        watchdog.cancel()
        conn.close()


def _map_exception(exc: BaseException, host: str) -> ScanError:
    h = sanitize_text(host, 100)
    if isinstance(exc, ssl.SSLCertVerificationError):
        return ScanError("tls", "TLS certificate verification failed for %s: %s"
                         % (h, sanitize_text(getattr(exc, "verify_message", None) or exc, 150)))
    if isinstance(exc, ssl.SSLError):
        return ScanError("tls", "TLS handshake with %s failed: %s" % (h, sanitize_text(exc, 150)))
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ScanError("timeout", "The connection to %s timed out." % h)
    if isinstance(exc, ConnectionRefusedError):
        return ScanError("refused", "Connection to %s was refused." % h)
    if isinstance(exc, socket.gaierror):
        return ScanError("dns", "DNS lookup failed for %s." % h)
    if isinstance(exc, http.client.HTTPException):
        return ScanError("protocol", "%s sent a malformed or oversized HTTP response." % h)
    if isinstance(exc, OSError):
        return ScanError("connection", "Could not connect to %s: %s"
                         % (h, sanitize_text(exc.strerror or type(exc).__name__, 100)))
    return ScanError("connection", "Unexpected network failure (%s)." % type(exc).__name__)


def _header(headers: Sequence[Tuple[str, str]], name: str) -> Optional[str]:
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


# ---------------------------------------------------------------- driver

def inspect_url(raw_url: str, *, allow_local: bool = False, timeout: float = 8.0,
                max_redirects: int = 3, resolver: Callable = socket.getaddrinfo,
                progress: Optional[Callable[[str], None]] = None) -> Observation:
    """Fetch response headers for a URL within a small, explicit request budget."""

    def tell(stage: str) -> None:
        if progress:
            progress(stage)

    url = normalize_url(raw_url)
    requested = url
    redirects: List[str] = []
    notes: List[str] = []
    for hop in range(max_redirects + 1):
        parts = urllib.parse.urlsplit(url)
        scheme, host = parts.scheme, parts.hostname or ""
        port = parts.port or (443 if scheme == "https" else 80)
        target = (parts.path or "/") + ("?" + parts.query if parts.query else "")

        tell("resolve")
        addresses = resolve_host(host, port, resolver, allow_local)
        tell("connect")
        status, headers = _try_addresses(scheme, host, port, addresses, target, "HEAD", timeout)
        tell("inspect")
        methods = ["HEAD"]

        location = _header(headers, "location")
        if status in REDIRECT_STATUSES and location:
            if hop == max_redirects:
                raise ScanError("redirect", "Stopped after %d redirects." % max_redirects)
            try:
                nxt = normalize_url(urllib.parse.urljoin(url, location))
            except ScanError as exc:
                raise ScanError("redirect", "Redirect refused: %s" % exc.message)
            redirects.append(sanitize_text(nxt.split("?")[0], 200))
            url = nxt
            continue

        if not fingerprint.extract_php_version(headers).evidence:
            try:
                status_g, headers_g = _try_addresses(scheme, host, port, addresses, target, "GET", timeout)
                methods.append("GET")
                status, headers = status_g, headers_g
            except ScanError as exc:
                notes.append("Follow-up GET failed (%s); HEAD response used." % exc.kind)
        return Observation(requested_url=requested, final_url=url, status=status, headers=headers,
                           methods=methods, redirects=redirects, notes=notes)
    raise ScanError("redirect", "Stopped after %d redirects." % max_redirects)  # pragma: no cover


def _try_addresses(scheme: str, host: str, port: int, addresses: Sequence[str], target: str,
                   method: str, timeout: float) -> Tuple[int, List[Tuple[str, str]]]:
    last: Optional[ScanError] = None
    for ip in addresses:
        try:
            return http_exchange(scheme, host, port, ip, target, method, timeout)
        except ScanError:
            raise
        except BaseException as exc:  # noqa: BLE001 - mapped to a readable error below
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            last = _map_exception(exc, host)
            if last.kind in ("tls", "protocol"):
                break
    assert last is not None
    raise last
