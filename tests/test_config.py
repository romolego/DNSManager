"""Тесты для dnsmgr.config: валидация DNS-профилей и хелперы режимов."""

import unittest

from dnsmgr.config import (
    _get_default_dns_profiles,
    _sanitize_dns_profiles,
    get_desired_mode_label,
    get_profile_by_id,
)


class SanitizeDnsProfilesTest(unittest.TestCase):
    def test_none_returns_none(self):
        # None означает «ключа нет» → вызывающая сторона подставит дефолт.
        self.assertIsNone(_sanitize_dns_profiles(None))

    def test_non_list_returns_none(self):
        self.assertIsNone(_sanitize_dns_profiles("garbage"))
        self.assertIsNone(_sanitize_dns_profiles({"id": "x"}))
        self.assertIsNone(_sanitize_dns_profiles(42))

    def test_empty_list_preserved(self):
        # Пустой список — намеренное состояние «Удалить все кнопки».
        self.assertEqual(_sanitize_dns_profiles([]), [])

    def test_all_garbage_items_returns_none(self):
        # Непустой список, но все элементы мусорные → повреждённые данные.
        self.assertIsNone(_sanitize_dns_profiles([1, 2, "x", {}]))
        self.assertIsNone(_sanitize_dns_profiles([{"id": "", "name": "", "primary": ""}]))

    def test_valid_profile_normalized(self):
        result = _sanitize_dns_profiles([
            {
                "id": "cf",
                "name": "  Cloudflare ",
                "primary": " 1.1.1.1 ",
                "secondary": "1.0.0.1",
                "source_url": " https://one.one.one.one/dns/ ",
                "fetch_url": " one.one.one.one ",
            }
        ])
        self.assertEqual(len(result), 1)
        p = result[0]
        self.assertEqual(p["id"], "cf")
        self.assertEqual(p["name"], "Cloudflare")     # обрезаны пробелы
        self.assertEqual(p["primary"], "1.1.1.1")     # обрезаны пробелы
        self.assertEqual(p["secondary"], "1.0.0.1")
        self.assertEqual(p["type"], "static")          # дефолтный тип
        self.assertEqual(p["source_url"], "https://one.one.one.one/dns/")
        self.assertEqual(p["fetch_url"], "one.one.one.one")

    def test_unknown_type_coerced_to_static(self):
        result = _sanitize_dns_profiles([
            {"id": "x", "name": "X", "primary": "9.9.9.9", "type": "exotic"}
        ])
        self.assertEqual(result[0]["type"], "static")

    def test_geohide_type_preserved(self):
        result = _sanitize_dns_profiles([
            {"id": "g", "name": "G", "primary": "45.131.7.1", "type": "geohide"}
        ])
        self.assertEqual(result[0]["type"], "geohide")

    def test_duplicate_ids_made_unique(self):
        result = _sanitize_dns_profiles([
            {"id": "dup", "name": "A", "primary": "1.1.1.1"},
            {"id": "dup", "name": "B", "primary": "2.2.2.2"},
            {"id": "dup", "name": "C", "primary": "3.3.3.3"},
        ])
        ids = [p["id"] for p in result]
        self.assertEqual(len(set(ids)), 3)         # все уникальны
        self.assertIn("dup", ids)
        self.assertIn("dup_2", ids)
        self.assertIn("dup_3", ids)

    def test_missing_required_field_skipped(self):
        # Профиль без primary пропускается, валидный остаётся.
        result = _sanitize_dns_profiles([
            {"id": "ok", "name": "OK", "primary": "8.8.8.8"},
            {"id": "bad", "name": "Bad"},  # нет primary
        ])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "ok")

    def test_missing_secondary_becomes_empty_string(self):
        result = _sanitize_dns_profiles([
            {"id": "ok", "name": "OK", "primary": "8.8.8.8"}
        ])
        self.assertEqual(result[0]["secondary"], "")


class DefaultDnsProfilesTest(unittest.TestCase):
    def test_returns_fresh_copies(self):
        a = _get_default_dns_profiles()
        b = _get_default_dns_profiles()
        self.assertIsNot(a, b)
        self.assertIsNot(a[0], b[0])      # вложенные dict тоже свежие
        a[0]["name"] = "MUTATED"
        self.assertNotEqual(a[0]["name"], b[0]["name"])  # мутация не протекает

    def test_first_profile_is_geohide(self):
        profiles = _get_default_dns_profiles()
        self.assertEqual(profiles[0]["type"], "geohide")

    def test_default_profile_order(self):
        profiles = _get_default_dns_profiles()
        self.assertEqual(
            [p["id"] for p in profiles],
            [
                "geohide",
                "xbox_dns",
                "comss",
                "cloudflare",
                "adguard",
                "malw_link",
                "mafioznik",
                "astracat",
            ],
        )

    def test_geohide_defaults(self):
        profile = _get_default_dns_profiles()[0]
        self.assertEqual(profile["primary"], "45.155.204.190")
        self.assertEqual(profile["secondary"], "37.230.192.51")
        self.assertTrue(profile["source_url"].startswith("https://"))
        self.assertEqual(profile["fetch_url"], "dns.geohide.ru")

    def test_legacy_default_profiles_are_migrated(self):
        old_profiles = [
            {"id": "geohide", "name": "GeoHide", "type": "geohide", "primary": "45.131.7.1", "secondary": "45.131.7.2"},
            {"id": "cloudflare", "name": "Cloudflare", "type": "static", "primary": "1.1.1.1", "secondary": "1.0.0.1"},
            {"id": "adguard", "name": "AdGuard", "type": "static", "primary": "94.140.14.14", "secondary": "94.140.15.15"},
            {"id": "xbox_dns", "name": "Xbox-dns", "type": "static", "primary": "176.99.11.77", "secondary": "80.78.247.254"},
            {"id": "malw_link", "name": "MalwareDefender", "type": "static", "primary": "84.21.189.133", "secondary": "193.23.209.189"},
            {"id": "mafioznik", "name": "MFZ", "type": "static", "primary": "103.27.157.38", "secondary": "103.27.157.100"},
            {"id": "astracat", "name": "Astracat", "type": "static", "primary": "185.139.69.24", "secondary": "77.239.113.0"},
            {"id": "comss", "name": "Comss", "type": "static", "primary": "83.220.169.155", "secondary": "212.109.195.93"},
        ]

        migrated = _sanitize_dns_profiles(old_profiles)

        self.assertEqual([p["id"] for p in migrated[:3]], ["geohide", "xbox_dns", "comss"])
        self.assertEqual(migrated[0]["primary"], "45.155.204.190")
        self.assertEqual(migrated[0]["secondary"], "37.230.192.51")
        self.assertTrue(all(p.get("source_url") for p in migrated))
        self.assertEqual(migrated[0]["fetch_url"], "dns.geohide.ru")
        self.assertEqual(migrated[4]["fetch_url"], "dns.adguard-dns.com")


class GetProfileByIdTest(unittest.TestCase):
    def setUp(self):
        self.profiles = [
            {"id": "a", "name": "Alpha", "type": "static", "primary": "1.1.1.1"},
            {"id": "b", "name": "Beta", "type": "static", "primary": "2.2.2.2"},
        ]

    def test_found(self):
        self.assertEqual(get_profile_by_id(self.profiles, "b")["name"], "Beta")

    def test_not_found(self):
        self.assertIsNone(get_profile_by_id(self.profiles, "zzz"))

    def test_empty_list(self):
        self.assertIsNone(get_profile_by_id([], "a"))


class GetDesiredModeLabelTest(unittest.TestCase):
    def setUp(self):
        self.profiles = [{"id": "cf", "name": "Cloudflare", "type": "static", "primary": "1.1.1.1"}]

    def test_standard(self):
        self.assertEqual(get_desired_mode_label("standard"), "Стандартный DNS (DHCP)")

    def test_none(self):
        self.assertEqual(get_desired_mode_label(None), "Не задан")

    def test_known_profile(self):
        self.assertEqual(get_desired_mode_label("cf", self.profiles), "Cloudflare")

    def test_unknown_profile_returns_id(self):
        # id, которого нет в списке — отдаём как есть (не падаем).
        self.assertEqual(get_desired_mode_label("ghost", self.profiles), "ghost")


if __name__ == "__main__":
    unittest.main()
