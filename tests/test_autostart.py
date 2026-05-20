"""Тесты для dnsmgr.autostart: разбор команд автозапуска и опознание exe."""

import os
import unittest

from dnsmgr.autostart import _extract_exe_from_command, _is_our_app_exe, _norm_path


class ExtractExeFromCommandTest(unittest.TestCase):
    def test_quoted_path(self):
        self.assertEqual(
            _extract_exe_from_command('"C:\\Program Files\\DNSManager.exe"'),
            "C:\\Program Files\\DNSManager.exe",
        )

    def test_quoted_path_with_args(self):
        self.assertEqual(
            _extract_exe_from_command('"C:\\app\\DNSManager.exe" --minimized'),
            "C:\\app\\DNSManager.exe",
        )

    def test_unquoted_path_no_args(self):
        self.assertEqual(
            _extract_exe_from_command("C:\\app\\DNSManager.exe"),
            "C:\\app\\DNSManager.exe",
        )

    def test_unquoted_path_with_args(self):
        # Без кавычек путь обрезается по первому пробелу (известное ограничение).
        self.assertEqual(
            _extract_exe_from_command("C:\\app\\dns.exe --minimized"),
            "C:\\app\\dns.exe",
        )

    def test_empty_and_none(self):
        self.assertEqual(_extract_exe_from_command(""), "")
        self.assertEqual(_extract_exe_from_command(None), "")
        self.assertEqual(_extract_exe_from_command(123), "")


class IsOurAppExeTest(unittest.TestCase):
    def test_recognizes_variants(self):
        for path in (
            "C:\\x\\DNSManager.exe",
            "C:\\x\\dns_manager.py",
            "C:\\x\\DNS Manager.exe",
            "/home/u/dnsmanager",
        ):
            self.assertTrue(_is_our_app_exe(path), path)

    def test_rejects_others(self):
        for path in ("C:\\x\\python.exe", "C:\\x\\notepad.exe", "", None):
            self.assertFalse(_is_our_app_exe(path), path)


class NormPathTest(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(_norm_path(""), "")
        self.assertEqual(_norm_path(None), "")

    def test_same_path_normalizes_equal(self):
        a = _norm_path("C:/Users/x/../x/App.exe")
        b = _norm_path("C:\\Users\\x\\App.exe")
        # На Windows регистр и слэши нормализуются к одному виду.
        if os.name == "nt":
            self.assertEqual(a, b)
        else:
            # На прочих ОS хотя бы не падаем и возвращаем строку.
            self.assertIsInstance(a, str)


if __name__ == "__main__":
    unittest.main()
