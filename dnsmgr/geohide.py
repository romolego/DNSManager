"""Резолв GeoHide и полуавтоматическое получение DNS по ссылке.

Содержит:
  - resolve_geohide — резолвит dns.geohide.ru в IP, с fallback на nslookup
    и захардкоженный список;
  - fetch_dns_from_link — пытается определить primary/secondary DNS по
    ссылке или домену (A-запись или поиск IPv4 в HTML-странице);
  - _is_valid_public_ipv4 — фильтр публичных IPv4 (без 10.*, 192.168.*, CGNAT и т.п.).
"""

import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from dnsmgr.constants import (
    DNS_HOST_PREFIXES,
    DNS_RESOLVE_TIMEOUT,
    GEOHIDE_DOMAIN,
    GEOHIDE_FALLBACK_IPS,
    LINK_FETCH_MAX_BYTES,
    LINK_FETCH_TIMEOUT,
    LINK_FETCH_USER_AGENT,
    NO_WINDOW_FLAG,
    socket_timeout_lock,
)
from dnsmgr.logger import app_logger


def resolve_geohide():
    """Резолвит dns.geohide.ru в IP-адреса. Возвращает (ips, used_fallback)."""
    try:
        results = socket.getaddrinfo(GEOHIDE_DOMAIN, None, socket.AF_INET, socket.SOCK_DGRAM)
        ips = []
        for r in results:
            ip = r[4][0]
            if ip not in ips:
                ips.append(ip)
        if ips:
            app_logger.info(f"Резолв {GEOHIDE_DOMAIN} -> {', '.join(ips)}")
            return ips, False
    except Exception as e:
        app_logger.warn(f"socket-резолв {GEOHIDE_DOMAIN} не удался: {e}")

    try:
        result = subprocess.run(
            ["nslookup", GEOHIDE_DOMAIN],
            capture_output=True, timeout=DNS_RESOLVE_TIMEOUT,
            creationflags=NO_WINDOW_FLAG
        )
        output = result.stdout.decode("utf-8", errors="replace")
        ip_pattern = re.compile(r'Address:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        all_ips = ip_pattern.findall(output)
        if len(all_ips) >= 2:
            ips = all_ips[1:]
            app_logger.info(f"Резолв {GEOHIDE_DOMAIN} (nslookup) -> {', '.join(ips)}")
            return ips, False
    except Exception as e:
        app_logger.warn(f"nslookup-резолв {GEOHIDE_DOMAIN} не удался: {e}")

    app_logger.warn(f"Используются резервные IP GeoHide: {', '.join(GEOHIDE_FALLBACK_IPS)}")
    return list(GEOHIDE_FALLBACK_IPS), True


# ── Получение DNS по ссылке ──────────────────────────────────────────────────
#
# Реалистичные ограничения механизма:
#   1. Если ввод — спец-домен вида dns.geohide.ru / doh.example / resolver.example,
#      то A-записи такого домена обычно указывают прямо на DNS-серверы. Берём их.
#   2. Если ввод — обычный URL/домен, скачиваем HTTPS-страницу и ищем на ней
#      публичные IPv4. Это работает только для страниц, где провайдер явно
#      опубликовал IP в текстовом виде. Не работает для JS-рендера, страниц
#      под Cloudflare-челленджем и сайтов без явных IP в HTML.
#   3. Никогда ничего не выдумываем: если оба способа не дали уверенного результата,
#      возвращаем честную ошибку, и пользователь вводит DNS вручную.
#
# Этот хелпер делает только попытку распознавания. Сохранение профиля происходит
# только после явного подтверждения пользователем в форме редактора.

_IPV4_RE = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')


def _is_valid_public_ipv4(ip):
    """Проверяет, что строка — корректный публичный IPv4 (не приватный/служебный)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    a, b, c, d = nums
    # Запрещённые/служебные диапазоны
    if a == 0:                                            # 0.0.0.0/8
        return False
    if a == 10:                                           # 10.0.0.0/8
        return False
    if a == 127:                                          # loopback
        return False
    if a == 169 and b == 254:                             # link-local
        return False
    if a == 172 and 16 <= b <= 31:                        # 172.16.0.0/12
        return False
    if a == 192 and b == 168:                             # 192.168.0.0/16
        return False
    if a == 100 and 64 <= b <= 127:                       # CGNAT
        return False
    if a >= 224:                                          # multicast и выше
        return False
    if a == 192 and b == 0 and c == 2:                    # TEST-NET-1
        return False
    if a == 198 and b in (18, 19):                        # benchmark
        return False
    if a == 198 and b == 51 and c == 100:                 # TEST-NET-2
        return False
    if a == 203 and b == 0 and c == 113:                  # TEST-NET-3
        return False
    if a == 255 and b == 255 and c == 255 and d == 255:   # broadcast
        return False
    return True


def _normalize_link_input(text):
    """Нормализует пользовательский ввод. Возвращает (host, url).

    Принимает:
      "dns.geohide.ru"            -> ("dns.geohide.ru", "https://dns.geohide.ru")
      "https://example.com/page"  -> ("example.com",    "https://example.com/page")
      "example.com/info"          -> ("example.com",    "https://example.com/info")
    """
    text = (text or "").strip()
    if not text:
        return None, None
    if not text.lower().startswith(("http://", "https://")):
        candidate = "https://" + text
    else:
        candidate = text
    try:
        parsed = urllib.parse.urlparse(candidate)
    except ValueError:
        return None, None
    host = (parsed.hostname or "").strip().lower()
    if not host or "." not in host:
        return None, None
    return host, candidate


def _resolve_host_to_ipv4(host, timeout=DNS_RESOLVE_TIMEOUT):
    """Возвращает уникальный список IPv4-адресов, в которые резолвится host."""
    ips = []
    try:
        with socket_timeout_lock:
            old_to = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            try:
                results = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
            finally:
                socket.setdefaulttimeout(old_to)
        for r in results:
            ip = r[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def _http_fetch_text(url, timeout=LINK_FETCH_TIMEOUT, max_bytes=LINK_FETCH_MAX_BYTES):
    """Скачивает страницу и возвращает её текст. None при ошибке."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": LINK_FETCH_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ru,en;q=0.9",
        })
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raw = raw[:max_bytes]
            charset = None
            try:
                charset = resp.headers.get_content_charset()
            except Exception:
                charset = None
            try:
                return raw.decode(charset or "utf-8", errors="replace")
            except (LookupError, TypeError):
                return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def fetch_dns_from_link(text):
    """Пытается определить primary/secondary DNS по ссылке/домену.

    Возвращает dict:
        {
            "ok": bool,
            "primary": str|None,
            "secondary": str|None,
            "source": str,
            "error": str|None,
        }
    Никогда не выдумывает IP. На любой неудаче возвращает ok=False с описанием.
    """
    host, url = _normalize_link_input(text)
    if not host:
        return {"ok": False, "primary": None, "secondary": None,
                "source": "", "error": "Введите ссылку или домен"}

    site_ips = _resolve_host_to_ipv4(host)
    public_resolved = [ip for ip in site_ips if _is_valid_public_ipv4(ip)]

    # Стратегия 1: явно DNS-публикующий хост (dns.*, doh.*, resolver.* и т.п.)
    first_label = host.split(".", 1)[0]
    if first_label in DNS_HOST_PREFIXES and 1 <= len(public_resolved) <= 2:
        primary = public_resolved[0]
        secondary = public_resolved[1] if len(public_resolved) > 1 else ""
        app_logger.info(
            f"DNS по домену {host}: A-запись -> {primary}"
            + (f", {secondary}" if secondary else "")
        )
        return {"ok": True, "primary": primary, "secondary": secondary,
                "source": f"A-запись {host}", "error": None}

    # Стратегия 2: скачать страницу и поискать публичные IPv4 в её тексте.
    if url:
        page_text = _http_fetch_text(url)
        if page_text:
            seen = set()
            candidates = []
            for m in _IPV4_RE.finditer(page_text):
                ip = m.group(1)
                if ip in seen:
                    continue
                seen.add(ip)
                if not _is_valid_public_ipv4(ip):
                    continue
                if ip in site_ips:  # IP самой страницы — почти точно не DNS
                    continue
                candidates.append(ip)
                if len(candidates) >= 2:
                    break
            if candidates:
                primary = candidates[0]
                secondary = candidates[1] if len(candidates) > 1 else ""
                app_logger.info(
                    f"DNS со страницы {url}: {primary}"
                    + (f", {secondary}" if secondary else "")
                )
                return {"ok": True, "primary": primary, "secondary": secondary,
                        "source": f"страница {host}", "error": None}
        else:
            return {"ok": False, "primary": None, "secondary": None, "source": "",
                    "error": "Страница недоступна или не отдала текст"}

    return {"ok": False, "primary": None, "secondary": None, "source": "",
            "error": "Не удалось распознать DNS по этой ссылке"}
