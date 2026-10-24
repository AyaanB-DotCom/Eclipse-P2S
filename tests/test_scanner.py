import http.server
import socket
import ssl
import threading
import unittest
from unittest import mock

from tests.helpers import load_db
from core import assessment as A
from core import scanner
from core.scanner import ScanError, inspect_url, is_public_address, normalize_url


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self):
        path = self.path.split("?")[0]
        if path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/final")
        elif path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
        elif path == "/bad":
            self.send_response(302)
            self.send_header("Location", "ftp://example.com/x")
        elif path == "/meta":
            self.send_response(301)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data")
        elif path == "/getonly":
            self.send_response(405 if self.command == "HEAD" else 200)
            if self.command == "GET":
                self.send_header("X-Powered-By", "PHP/8.3.35")
        elif path == "/nophp":
            self.send_response(200)
            self.send_header("Server", "nginx")
        elif path == "/err":
            self.send_response(500)
            self.send_header("X-Powered-By", "PHP/8.2.34")
        else:
            self.send_response(200)
            self.send_header("X-Powered-By", "PHP/8.3.35")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET = _send


class LocalServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.db = load_db()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def url(self, path="/"):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def test_loopback_blocked_by_default(self):
        with self.assertRaises(ScanError) as cm:
            inspect_url(self.url())
        self.assertEqual(cm.exception.kind, "blocked_target")

    def test_basic_head_with_local_opt_in(self):
        obs = inspect_url(self.url(), allow_local=True)
        self.assertEqual(obs.status, 200)
        self.assertEqual(obs.methods, ["HEAD"])

    def test_redirect_followed_and_recorded(self):
        obs = inspect_url(self.url("/redir"), allow_local=True)
        self.assertTrue(obs.final_url.endswith("/final"))
        self.assertEqual(len(obs.redirects), 1)

    def test_redirect_loop_limited(self):
        with self.assertRaises(ScanError) as cm:
            inspect_url(self.url("/loop"), allow_local=True, max_redirects=2)
        self.assertEqual(cm.exception.kind, "redirect")

    def test_redirect_to_bad_scheme_refused(self):
        with self.assertRaises(ScanError) as cm:
            inspect_url(self.url("/bad"), allow_local=True)
        self.assertEqual(cm.exception.kind, "redirect")

    def test_redirect_to_metadata_address_refused(self):
        # allow_local is NOT set, so the first hop (loopback) is refused; use a public-looking
        # first hop through a mocked resolver and mocked exchange to test redirect validation.
        def fake_exchange(scheme, host, port, ip, target, method, timeout):
            return 301, [("Location", "http://169.254.169.254/latest/meta-data")]
        resolver = lambda host, port, type=0: [(2, 1, 6, "", ("93.184.216.34", port))]
        with mock.patch.object(scanner, "http_exchange", fake_exchange):
            with self.assertRaises(ScanError) as cm:
                inspect_url("http://example.test/", resolver=resolver)
        self.assertEqual(cm.exception.kind, "blocked_target")

    def test_get_fallback_when_head_has_no_version(self):
        obs = inspect_url(self.url("/getonly"), allow_local=True)
        self.assertEqual(obs.methods, ["HEAD", "GET"])
        self.assertEqual(obs.status, 200)

    def test_single_get_when_no_php(self):
        obs = inspect_url(self.url("/nophp"), allow_local=True)
        self.assertEqual(obs.methods, ["HEAD", "GET"])

    def test_http_error_still_yields_headers(self):
        a = A.assess_url(self.url("/err"), self.db, allow_local=True)
        self.assertEqual(a.http_status, 500)
        self.assertEqual(a.classification, A.POTENTIAL_EXPOSURE)

    def test_end_to_end_url_assessment(self):
        stages = []
        a = A.assess_url(self.url(), self.db, allow_local=True, progress=stages.append)
        self.assertEqual((a.version, a.classification, a.mode), ("8.3.35", A.POTENTIAL_EXPOSURE, "url"))
        self.assertEqual(stages[0], "resolve")
        self.assertEqual(stages[-3:], ["identify", "compare", "prepare"])

    def test_connection_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(ScanError) as cm:
            inspect_url("http://127.0.0.1:%d/" % port, allow_local=True, timeout=2)
        self.assertEqual(cm.exception.kind, "refused")

    def test_timeout(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)  # accepts at kernel level but never answers
        self.addCleanup(srv.close)
        with self.assertRaises(ScanError) as cm:
            inspect_url("http://127.0.0.1:%d/" % srv.getsockname()[1], allow_local=True, timeout=0.5)
        self.assertEqual(cm.exception.kind, "timeout")


class UrlAndPolicyTests(unittest.TestCase):
    def test_normalisation(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com/")
        self.assertEqual(normalize_url("HTTP://Example.COM/a?b=1#frag"), "http://example.com/a?b=1")
        self.assertEqual(normalize_url("example.com:8443/x"), "https://example.com:8443/x")
        self.assertEqual(normalize_url("https://[2001:db8::1]:8080/"), "https://[2001:db8::1]:8080/")

    def test_invalid_urls(self):
        bad = ["", "   ", "ftp://example.com", "file:///etc/passwd", "javascript:alert(1)", "https://",
               "https://user:pw@example.com/", "https://user@example.com", "exa mple.com",
               "https://example.com:99999", "https://example.com:0", "https://-bad-.com",
               "https://exa\x1b[2Jmple.com", "https://" + "a" * 70 + ".com", "x" * 3000, None,
               "https://ex..ample.com"]
        for url in bad:
            with self.assertRaises(ScanError, msg=repr(url)) as cm:
                normalize_url(url)
            self.assertEqual(cm.exception.kind, "invalid_url")

    def test_public_address_policy(self):
        for ip in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "::1",
                   "fe80::1", "fc00::1", "0.0.0.0", "100.64.0.1", "::ffff:127.0.0.1", "224.0.0.1", "garbage"):
            self.assertFalse(is_public_address(ip), ip)
        for ip in ("93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"):
            self.assertTrue(is_public_address(ip), ip)

    def test_private_resolution_blocked(self):
        resolver = lambda host, port, type=0: [(2, 1, 6, "", ("10.0.0.5", port))]
        with self.assertRaises(ScanError) as cm:
            inspect_url("https://internal.example/", resolver=resolver)
        self.assertEqual(cm.exception.kind, "blocked_target")

    def test_mixed_resolution_blocked(self):
        resolver = lambda host, port, type=0: [(2, 1, 6, "", ("93.184.216.34", port)), (2, 1, 6, "", ("127.0.0.1", port))]
        with self.assertRaises(ScanError):
            inspect_url("https://rebind.example/", resolver=resolver)

    def test_literal_private_ip_blocked(self):
        for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/", "http://[::1]/", "http://10.0.0.1:8080/"):
            with self.assertRaises(ScanError) as cm:
                inspect_url(url)
            self.assertEqual(cm.exception.kind, "blocked_target")

    def test_dns_failure(self):
        def resolver(host, port, type=0):
            raise socket.gaierror(-2, "Name or service not known")
        with self.assertRaises(ScanError) as cm:
            inspect_url("https://nope.invalid/", resolver=resolver)
        self.assertEqual(cm.exception.kind, "dns")

    def _mapped(self, exc):
        resolver = lambda host, port, type=0: [(2, 1, 6, "", ("93.184.216.34", port))]
        with mock.patch.object(scanner, "http_exchange", side_effect=exc):
            with self.assertRaises(ScanError) as cm:
                inspect_url("https://example.test/", resolver=resolver)
        return cm.exception.kind

    def test_error_mapping(self):
        self.assertEqual(self._mapped(ssl.SSLCertVerificationError(1, "bad cert")), "tls")
        self.assertEqual(self._mapped(ssl.SSLError("handshake")), "tls")
        self.assertEqual(self._mapped(socket.timeout("t")), "timeout")
        self.assertEqual(self._mapped(ConnectionRefusedError()), "refused")
        self.assertEqual(self._mapped(ConnectionResetError()), "connection")
        import http.client
        self.assertEqual(self._mapped(http.client.BadStatusLine("x")), "protocol")

    def test_no_environment_proxy_used(self):
        import os
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1"}):
            # The scanner uses http.client with direct pinned sockets; proxies are never consulted.
            self.assertNotIn("urllib.request", scanner.__dict__)


if __name__ == "__main__":
    unittest.main()
