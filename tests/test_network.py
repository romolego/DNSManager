"""Тесты для dnsmgr.network: распознавание режима DNS и хелперы IP."""

import unittest

from dnsmgr.network import _norm_ip, _profile_ip_set, detect_dns_mode


CF = {"id": "cf", "name": "Cloudflare", "type": "static", "primary": "1.1.1.1", "secondary": "1.0.0.1"}
ADG = {"id": "adg", "name": "AdGuard", "type": "static", "primary": "94.140.14.14", "secondary": "94.140.15.15"}
GEO = {
    "id": "geohide",
    "name": "GeoHide",
    "type": "geohide",
    "primary": "45.155.204.190",
    "secondary": "37.230.192.51",
}
PROFILES = [GEO, CF, ADG]


class NormIpTest(unittest.TestCase):
    def test_trims(self):
        self.assertEqual(_norm_ip("  1.1.1.1 "), "1.1.1.1")

    def test_none(self):
        self.assertEqual(_norm_ip(None), "")


class ProfileIpSetTest(unittest.TestCase):
    def test_both(self):
        self.assertEqual(_profile_ip_set(CF), {"1.1.1.1", "1.0.0.1"})

    def test_primary_only(self):
        self.assertEqual(_profile_ip_set({"primary": "9.9.9.9", "secondary": ""}), {"9.9.9.9"})

    def test_empty(self):
        self.assertEqual(_profile_ip_set({"primary": "", "secondary": ""}), set())


class DetectDnsModeTest(unittest.TestCase):
    def test_dhcp_is_standard(self):
        self.assertEqual(detect_dns_mode([], is_dhcp=True), ("standard", "Стандартный DNS (DHCP)"))

    def test_empty_servers_is_standard(self):
        pid, _ = detect_dns_mode([], dns_profiles=PROFILES)
        self.assertEqual(pid, "standard")

    def test_exact_match(self):
        pid, name = detect_dns_mode(["1.1.1.1", "1.0.0.1"], dns_profiles=PROFILES)
        self.assertEqual(pid, "cf")
        self.assertEqual(name, "Cloudflare")

    def test_order_independent(self):
        # Порядок primary/secondary не важен — сравнение множествами.
        pid, _ = detect_dns_mode(["1.0.0.1", "1.1.1.1"], dns_profiles=PROFILES)
        self.assertEqual(pid, "cf")

    def test_whitespace_normalized(self):
        pid, _ = detect_dns_mode([" 1.1.1.1 ", "1.0.0.1"], dns_profiles=PROFILES)
        self.assertEqual(pid, "cf")

    def test_single_server_partial_not_matching_static(self):
        # Один адрес из пары статического профиля — это НЕ точное совпадение.
        pid, _ = detect_dns_mode(["1.1.1.1"], dns_profiles=PROFILES)
        self.assertIsNone(pid)

    def test_geohide_fallback_ips_match(self):
        # Захардкоженные резервы GeoHide распознаются как geohide.
        pid, _ = detect_dns_mode(["45.155.204.190", "37.230.192.51"], dns_profiles=PROFILES)
        self.assertEqual(pid, "geohide")

    def test_geohide_legacy_fallback_ips_still_match(self):
        # Старые fallback-адреса распознаются как geohide, чтобы приложение
        # могло корректно мигрировать уже применённый DNS.
        pid, _ = detect_dns_mode(["45.131.7.1", "45.131.7.2"], dns_profiles=PROFILES)
        self.assertEqual(pid, "geohide")

    def test_geohide_subset_with_known_ips(self):
        # Свежерезолвленные IP geohide — подмножество допускается.
        pid, _ = detect_dns_mode(
            ["45.131.7.50"], geohide_known_ips=["45.131.7.50", "45.131.7.51"],
            dns_profiles=PROFILES,
        )
        self.assertEqual(pid, "geohide")

    def test_unknown_dns_no_match(self):
        pid, name = detect_dns_mode(["77.88.8.8", "77.88.8.1"], dns_profiles=PROFILES)
        self.assertIsNone(pid)
        self.assertIn("не соответствует", name)

    def test_no_profiles_unknown(self):
        pid, _ = detect_dns_mode(["1.1.1.1", "1.0.0.1"], dns_profiles=[])
        self.assertIsNone(pid)


if __name__ == "__main__":
    unittest.main()
