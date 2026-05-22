"""Тесты для DNS-пакета: _encode_dns_query / _parse_dns_response.

Сетевой ввод/вывод (dns_query) не тестируем — он требует реального сервера;
а вот сборка запроса и разбор ответа — чистые функции, и их проверяем
полностью, включая компрессию имён и коды ошибок (NXDOMAIN и т.п.).
"""

import struct
import unittest

from dnsmgr.network import (
    _encode_dns_query,
    _normalize_domain,
    _parse_dns_response,
    _skip_dns_name,
)


class NormalizeDomainTest(unittest.TestCase):
    def test_plain_domain(self):
        self.assertEqual(_normalize_domain("chatgpt.com"), "chatgpt.com")

    def test_strips_https_scheme(self):
        self.assertEqual(_normalize_domain("https://chatgpt.com"), "chatgpt.com")

    def test_strips_http_scheme(self):
        self.assertEqual(_normalize_domain("http://example.com"), "example.com")

    def test_strips_path_and_query(self):
        self.assertEqual(_normalize_domain("https://chatgpt.com/foo/bar?x=1"), "chatgpt.com")

    def test_strips_trailing_slash(self):
        self.assertEqual(_normalize_domain("https://chatgpt.com/"), "chatgpt.com")

    def test_strips_port(self):
        self.assertEqual(_normalize_domain("example.com:443"), "example.com")

    def test_strips_userinfo(self):
        self.assertEqual(_normalize_domain("user@example.com"), "example.com")

    def test_lowercases(self):
        self.assertEqual(_normalize_domain("ChatGPT.COM"), "chatgpt.com")

    def test_strips_trailing_dot(self):
        self.assertEqual(_normalize_domain("example.com."), "example.com")

    def test_empty(self):
        self.assertEqual(_normalize_domain(""), "")
        self.assertEqual(_normalize_domain("   "), "")
        self.assertEqual(_normalize_domain(None), "")

    def test_combined(self):
        self.assertEqual(
            _normalize_domain("HTTPS://User@ChatGPT.com:8443/path?q=1#frag"),
            "chatgpt.com",
        )


def _build_response(query_id, flags, questions=1, answers=None, qname=b"\x06google\x03com\x00"):
    """Собирает фикстурный DNS-ответ. answers — список (rtype, rdata-bytes)."""
    answers = answers or []
    header = struct.pack(">HHHHHH", query_id, flags, questions, len(answers), 0, 0)
    body = b""
    if questions:
        body += qname + struct.pack(">HH", 1, 1)
    for rtype, rdata in answers:
        # имя ответа через указатель сжатия на смещение 12 (начало qname)
        body += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + body


class EncodeDnsQueryTest(unittest.TestCase):
    def test_header_fields(self):
        q = _encode_dns_query("google.com", 0xABCD)
        rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", q[:12])
        self.assertEqual(rid, 0xABCD)
        self.assertEqual(flags, 0x0100)   # recursion desired
        self.assertEqual(qd, 1)
        self.assertEqual((an, ns, ar), (0, 0, 0))

    def test_qname_encoding(self):
        q = _encode_dns_query("google.com", 1)
        self.assertIn(b"\x06google\x03com\x00", q)

    def test_qtype_qclass_a_in(self):
        q = _encode_dns_query("a.b", 1)
        self.assertEqual(q[-4:], struct.pack(">HH", 1, 1))  # A, IN

    def test_trailing_dot_ignored(self):
        q1 = _encode_dns_query("example.com", 1)
        q2 = _encode_dns_query("example.com.", 1)
        self.assertEqual(q1, q2)

    def test_label_too_long_raises(self):
        with self.assertRaises(ValueError):
            _encode_dns_query("a" * 64 + ".com", 1)

    def test_idn_domain_punycode(self):
        # Кириллический домен не должен падать (кодируется в punycode).
        q = _encode_dns_query("яндекс.рф", 1)
        self.assertIn(b"xn--", q)


class ParseDnsResponseTest(unittest.TestCase):
    def test_single_a_record(self):
        resp = _build_response(0xABCD, 0x8180, answers=[(1, bytes([1, 2, 3, 4]))])
        self.assertEqual(_parse_dns_response(resp, 0xABCD), ["1.2.3.4"])

    def test_multiple_a_records(self):
        resp = _build_response(0x1111, 0x8180, answers=[
            (1, bytes([8, 8, 8, 8])),
            (1, bytes([8, 8, 4, 4])),
        ])
        self.assertEqual(_parse_dns_response(resp, 0x1111), ["8.8.8.8", "8.8.4.4"])

    def test_non_a_records_skipped(self):
        # CNAME (type 5) игнорируется, A (type 1) берётся.
        resp = _build_response(0x2222, 0x8180, answers=[
            (5, b"\xc0\x0c"),               # CNAME-подобная запись
            (1, bytes([93, 184, 216, 34])),  # A
        ])
        self.assertEqual(_parse_dns_response(resp, 0x2222), ["93.184.216.34"])

    def test_no_answers_empty_list(self):
        resp = _build_response(0x3333, 0x8180, answers=[])
        self.assertEqual(_parse_dns_response(resp, 0x3333), [])

    def test_id_mismatch_raises(self):
        resp = _build_response(0x4444, 0x8180, answers=[(1, bytes([1, 1, 1, 1]))])
        with self.assertRaises(ValueError):
            _parse_dns_response(resp, 0x9999)

    def test_not_a_response_raises(self):
        # QR-бит не установлен (0x0100 вместо 0x8180)
        resp = _build_response(0x5555, 0x0100)
        with self.assertRaises(ValueError):
            _parse_dns_response(resp, 0x5555)

    def test_nxdomain_raises(self):
        # RCODE=3 (NXDOMAIN) — домен не резолвится этим сервером
        resp = _build_response(0x6666, 0x8183)
        with self.assertRaises(ValueError):
            _parse_dns_response(resp, 0x6666)

    def test_refused_raises(self):
        # RCODE=5 (REFUSED) — частый признак блокировки
        resp = _build_response(0x7777, 0x8185)
        with self.assertRaises(ValueError):
            _parse_dns_response(resp, 0x7777)

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            _parse_dns_response(b"\x00\x01", 0x0001)


class SkipDnsNameTest(unittest.TestCase):
    def test_plain_name(self):
        data = b"\x06google\x03com\x00rest"
        self.assertEqual(_skip_dns_name(data, 0), len(b"\x06google\x03com\x00"))

    def test_compression_pointer(self):
        # Указатель сжатия — ровно 2 байта.
        data = b"\xc0\x0cXXXX"
        self.assertEqual(_skip_dns_name(data, 0), 2)

    def test_truncated_raises(self):
        with self.assertRaises(ValueError):
            _skip_dns_name(b"\x06goo", 0)  # длина 6, но байтов нет


if __name__ == "__main__":
    unittest.main()
