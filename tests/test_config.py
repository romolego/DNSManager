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
            {"id": "cf", "name": "  Cloudflare ", "primary": " 1.1.1.1 ", "secondary": "1.0.0.1"}
        ])
        self.assertEqual(len(result), 1)
        p = result[0]
        self.assertEqual(p["id"], "cf")
        self.assertEqual(p["name"], "Cloudflare")     # обрезаны пробелы
        self.assertEqual(p["primary"], "1.1.1.1")     # обрезаны пробелы
        self.assertEqual(p["secondary"], "1.0.0.1")
        self.assertEqual(p["type"], "static")          # дефолтный тип

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
