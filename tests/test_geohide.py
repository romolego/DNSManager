"""Тесты для dnsmgr.geohide: валидация публичных IPv4 и разбор ссылок."""

import unittest

from dnsmgr.geohide import _is_valid_public_ipv4, _normalize_link_input


class IsValidPublicIpv4Test(unittest.TestCase):
    def test_valid_public(self):
        for ip in ("8.8.8.8", "1.1.1.1", "45.155.204.190", "94.140.14.14", "203.0.114.1"):
            self.assertTrue(_is_valid_public_ipv4(ip), ip)

    def test_private_ranges_rejected(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.255.255"):
            self.assertFalse(_is_valid_public_ipv4(ip), ip)

    def test_special_ranges_rejected(self):
        for ip in (
            "0.0.0.0",          # this-network
            "127.0.0.1",        # loopback
            "169.254.1.1",      # link-local
            "100.64.0.1",       # CGNAT
            "224.0.0.1",        # multicast
            "255.255.255.255",  # broadcast
            "192.0.2.1",        # TEST-NET-1
            "198.51.100.1",     # TEST-NET-2
            "203.0.113.1",      # TEST-NET-3
            "198.18.0.1",       # benchmark
        ):
            self.assertFalse(_is_valid_public_ipv4(ip), ip)

    def test_malformed_rejected(self):
        for ip in ("", "1.2.3", "1.2.3.4.5", "256.1.1.1", "a.b.c.d", "1.1.1.-1"):
            self.assertFalse(_is_valid_public_ipv4(ip), ip)

    def test_172_public_boundary(self):
        # 172.15 и 172.32 — публичные (вне приватного 172.16-31).
        self.assertTrue(_is_valid_public_ipv4("172.15.0.1"))
        self.assertTrue(_is_valid_public_ipv4("172.32.0.1"))


class NormalizeLinkInputTest(unittest.TestCase):
    def test_bare_domain(self):
        host, url = _normalize_link_input("dns.geohide.ru")
        self.assertEqual(host, "dns.geohide.ru")
        self.assertEqual(url, "https://dns.geohide.ru")

    def test_https_url_with_path(self):
        host, url = _normalize_link_input("https://example.com/page")
        self.assertEqual(host, "example.com")
        self.assertEqual(url, "https://example.com/page")

    def test_http_preserved(self):
        host, url = _normalize_link_input("http://example.com")
        self.assertEqual(host, "example.com")
        self.assertEqual(url, "http://example.com")

    def test_domain_with_path_no_scheme(self):
        host, url = _normalize_link_input("example.com/info")
        self.assertEqual(host, "example.com")
        self.assertEqual(url, "https://example.com/info")

    def test_uppercase_host_lowered(self):
        host, _ = _normalize_link_input("DNS.GeoHide.RU")
        self.assertEqual(host, "dns.geohide.ru")

    def test_empty_input(self):
        self.assertEqual(_normalize_link_input(""), (None, None))
        self.assertEqual(_normalize_link_input("   "), (None, None))
        self.assertEqual(_normalize_link_input(None), (None, None))

    def test_no_dot_rejected(self):
        # Хост без точки (например, "localhost") не считается доменом.
        self.assertEqual(_normalize_link_input("localhost"), (None, None))


if __name__ == "__main__":
    unittest.main()
