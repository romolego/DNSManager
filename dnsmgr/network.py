"""Сетевой уровень: адаптеры, DNS, проверки связи.

Содержит:
  - subprocess-обёртки `_run_powershell` / `_run_netsh` с корректной
    обработкой UTF-8/cp866-вывода;
  - работу с адаптерами (Get-NetAdapter, фильтрация виртуальных, выбор
    активного через default route);
  - чтение/применение/сброс DNS (`get_current_dns`, `set_dns`, `reset_dns`,
    `get_dhcp_offered_dns`);
  - проверку готовности сети и реального интернета (NCSI-пробы);
  - распознавание текущего режима DNS (`detect_dns_mode`);
  - адресный DNS-запрос к конкретному серверу для замера времени отклика и
    проверки, резолвит ли этот сервер заданный домен (`dns_query`,
    `check_resource_via_dns`).

Зависит только от constants и logger.
"""

import json
import os
import re
import socket
import struct
import subprocess
import time

from dnsmgr.constants import (
    DNS_RESOLVE_TIMEOUT,
    NETWORK_NO_CONNECTION,
    NETWORK_READY,
    NETWORK_UNSTABLE,
    TEST_DOMAIN,
    socket_timeout_lock,
)
from dnsmgr.logger import app_logger


# ── Subprocess-обёртки ──────────────────────────────────────────────────────

def _run_powershell(ps_command, timeout=15):
    """Запускает PowerShell-команду с корректной UTF-8 кодировкой."""
    cmd = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command",
        f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {ps_command}"
    ]
    result = subprocess.run(
        cmd, capture_output=True, timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    stdout = result.stdout.decode("utf-8", errors="replace").strip()
    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    return result.returncode, stdout, stderr


def _run_netsh(args, timeout=15):
    """Запускает netsh-команду с корректной кодировкой."""
    cmd = ["netsh"] + args
    result = subprocess.run(
        cmd, capture_output=True, timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    raw = result.stdout
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            stdout = raw.decode(enc)
            if enc == "utf-8" or any(ord(c) > 127 for c in stdout):
                break
        except (UnicodeDecodeError, ValueError):
            continue
    else:
        stdout = raw.decode("utf-8", errors="replace")

    stderr_raw = result.stderr
    stderr = stderr_raw.decode("cp866", errors="replace").strip()
    return result.returncode, stdout, stderr


# ── Адаптеры ────────────────────────────────────────────────────────────────

def get_network_adapters():
    """Получает список сетевых адаптеров через PowerShell."""
    try:
        ps_cmd = (
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
            "Select-Object -Property Name, InterfaceDescription, Status, ifIndex | "
            "ConvertTo-Json -Compress"
        )
        returncode, stdout, stderr = _run_powershell(ps_cmd)

        if returncode != 0:
            app_logger.error(f"Ошибка PowerShell Get-NetAdapter: {stderr}")
            return []

        if not stdout:
            return []

        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]

        adapters = []
        for item in data:
            name = item.get("Name", "")
            desc = item.get("InterfaceDescription", "")
            if name:
                adapters.append({
                    "name": name,
                    "description": desc,
                    "index": item.get("ifIndex", 0),
                })
        return adapters

    except subprocess.TimeoutExpired:
        app_logger.error("Таймаут при получении списка адаптеров")
        return []
    except json.JSONDecodeError as e:
        app_logger.error(f"Ошибка разбора JSON от Get-NetAdapter: {e}")
        return []
    except Exception as e:
        app_logger.error(f"Ошибка получения адаптеров: {e}")
        return []


_ADAPTER_SKIP_KEYWORDS = [
    # Виртуальные / служебные
    "virtual", "loopback", "bluetooth", "wi-fi direct",
    "microsoft wi-fi direct", "vmware", "virtualbox",
    "hyper-v", "docker", "wsl",
    # VPN-туннели и сторонние tun/tap-адаптеры. Применять системный DNS
    # к туннелю обычно бессмысленно (туннель надстроен над физическим
    # адаптером), а ещё опаснее — выбрать туннель как «активный» физический
    # адаптер: он часто имеет default-маршрут с минимальной метрикой и
    # `get_active_internet_adapter` без этого фильтра отдал бы именно его.
    "tap-windows", "tap adapter", "tap-win", "openvpn",
    "wireguard", "wintun", "anyconnect", "cisco anyconnect",
    "fortissl", "fortinet ssl", "tailscale", "zerotier",
    "nordlynx", "expressvpn", "proton vpn", "protonvpn",
    "mullvad", "windscribe", "outline",
    "vpn",
]


def filter_suitable_adapters(adapters):
    """Возвращает список «нормальных» адаптеров, отсекая виртуальные/служебные.

    Используется как единый фильтр везде, где нужно перечислить адаптеры,
    к которым приложение имеет право применять DNS.
    """
    if not adapters:
        return []
    filtered = []
    for a in adapters:
        desc_lower = a.get("description", "").lower()
        name_lower = a.get("name", "").lower()
        skip = False
        for kw in _ADAPTER_SKIP_KEYWORDS:
            if kw in desc_lower or kw in name_lower:
                skip = True
                break
        if not skip:
            filtered.append(a)
    return filtered


def get_active_internet_adapter(adapters=None):
    """Определяет адаптер, через который сейчас идёт интернет — по default-маршруту.

    Берёт `Get-NetRoute -DestinationPrefix '0.0.0.0/0'`, сортирует по сумме
    `RouteMetric + InterfaceMetric` (то, что Windows реально использует для
    выбора маршрута) и возвращает имя первого адаптера, который:
      - присутствует в `adapters` (т.е. в `Get-NetAdapter | Where Status -eq Up`);
      - проходит `filter_suitable_adapters` (не виртуальный/служебный).

    Возвращает None, если ни один подходящий default-маршрут не найден или
    PowerShell-запрос не сработал.
    """
    try:
        ps_cmd = (
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 "
            "-ErrorAction SilentlyContinue | "
            "Sort-Object -Property "
            "@{Expression={[int]$_.RouteMetric + [int]$_.InterfaceMetric}} | "
            "Select-Object -Property InterfaceAlias, ifIndex | "
            "ConvertTo-Json -Compress"
        )
        rc, stdout, stderr = _run_powershell(ps_cmd, timeout=8)
        if rc != 0 or not stdout:
            return None
        data = json.loads(stdout)
        if isinstance(data, dict):
            data = [data]
        if not data:
            return None
        if adapters is None:
            adapters = get_network_adapters()
        suitable_names = {a["name"] for a in filter_suitable_adapters(adapters)}
        up_names = {a["name"] for a in adapters}
        for entry in data:
            alias = (entry.get("InterfaceAlias") or "").strip()
            if alias and alias in up_names and alias in suitable_names:
                return alias
        return None
    except subprocess.TimeoutExpired:
        return None
    except json.JSONDecodeError:
        return None
    except Exception as e:
        try:
            app_logger.warn(f"Ошибка определения активного адаптера: {e}")
        except Exception:
            pass
        return None


def select_best_adapter(adapters):
    """Выбирает наиболее подходящий активный адаптер.

    Приоритет: адаптер с активным default-маршрутом (тот, через который
    сейчас идёт интернет). Если определить через маршрут не удалось —
    эвристика по описанию: первый Ethernet, иначе первый не-виртуальный.
    """
    if not adapters:
        return None

    active = get_active_internet_adapter(adapters)
    if active:
        return active

    filtered = filter_suitable_adapters(adapters)
    if not filtered:
        filtered = adapters

    for a in filtered:
        desc_lower = a["description"].lower()
        if "ethernet" in desc_lower or "ethernet" in a["name"].lower():
            return a["name"]

    return filtered[0]["name"]


# ── DNS: чтение / применение / сброс ────────────────────────────────────────

def get_current_dns(adapter_name):
    """Читает текущие DNS-серверы для адаптера через netsh."""
    try:
        returncode, output, stderr = _run_netsh(
            ["interface", "ip", "show", "dnsservers", adapter_name], timeout=10
        )

        dns_servers = []
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

        for line in output.split('\n'):
            match = ip_pattern.search(line)
            if match:
                dns_servers.append(match.group(1))

        is_dhcp = False
        output_lower = output.lower()
        if "dhcp" in output_lower or "настроен через dhcp" in output_lower or "configured through dhcp" in output_lower:
            is_dhcp = True
        if not dns_servers and "нет" not in output_lower and "none" not in output_lower:
            is_dhcp = True

        return {
            "servers": dns_servers,
            "is_dhcp": is_dhcp,
            "raw": output.strip(),
        }

    except Exception as e:
        app_logger.error(f"Ошибка чтения DNS для {adapter_name}: {e}")
        return {"servers": [], "is_dhcp": False, "raw": str(e)}


def get_dhcp_offered_dns(adapter_name):
    """Возвращает DNS-серверы, выданные DHCP-сервером для адаптера, даже если
    в системе сейчас прописан статический DNS-override.

    Использует запись `DhcpNameServer` в реестре для интерфейса — Windows
    хранит там DNS из последней DHCP-аренды независимо от того, перекрыты
    ли они статической настройкой (`NameServer`).

    Возвращает список IP (может быть пустым), либо None при ошибке/отсутствии
    данных.
    """
    try:
        # Экранируем одинарную кавычку в имени адаптера для PowerShell-литерала
        # (см. также check_network_ready). Имена адаптеров с ' встречаются редко,
        # но Windows их разрешает.
        safe_name = adapter_name.replace("'", "''")
        ps_cmd = (
            f"$g = (Get-NetAdapter -Name '{safe_name}' -ErrorAction Stop).InterfaceGuid; "
            f"$p = Get-ItemProperty "
            f"-Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$g\" "
            f"-Name DhcpNameServer -ErrorAction Stop; "
            f"$p.DhcpNameServer"
        )
        rc, stdout, stderr = _run_powershell(ps_cmd, timeout=10)
        if rc != 0 or not stdout:
            return None
        # DhcpNameServer — строка с DNS-адресами, разделёнными пробелом или запятой
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        ips = ip_pattern.findall(stdout)
        return ips or None
    except Exception:
        return None


def set_dns(adapter_name, primary, secondary=None):
    """Устанавливает DNS-серверы для адаптера через netsh."""
    try:
        rc1, stdout1, stderr1 = _run_netsh(
            ["interface", "ip", "set", "dnsservers", adapter_name, "static", primary, "primary"],
            timeout=15
        )
        if rc1 != 0:
            combined = (stderr1 + " " + stdout1).lower()
            if "доступ" in combined or "access" in combined or "запрошенная операция" in combined:
                return {"success": False, "error": "Требуются права администратора для изменения DNS.", "access_denied": True}
            return {"success": False, "error": f"Ошибка netsh: {stderr1 or stdout1}"}

        if secondary:
            rc2, stdout2, stderr2 = _run_netsh(
                ["interface", "ip", "add", "dnsservers", adapter_name, secondary, "index=2"],
                timeout=15
            )
            if rc2 != 0:
                app_logger.warn(f"Не удалось добавить вторичный DNS {secondary}: {stderr2}")

        return {"success": True}

    except Exception as e:
        error_msg = str(e)
        if "winerror 740" in error_msg.lower() or "elevation" in error_msg.lower():
            return {"success": False, "error": "Требуются права администратора.", "access_denied": True}
        return {"success": False, "error": f"Ошибка: {e}"}


def reset_dns(adapter_name):
    """Сбрасывает DNS на автоматическое получение (DHCP)."""
    try:
        rc, stdout, stderr = _run_netsh(
            ["interface", "ip", "set", "dnsservers", adapter_name, "dhcp"],
            timeout=15
        )
        if rc != 0:
            combined = (stderr + " " + stdout).lower()
            if "доступ" in combined or "access" in combined or "запрошенная операция" in combined:
                return {"success": False, "error": "Требуются права администратора.", "access_denied": True}
            return {"success": False, "error": f"Ошибка netsh: {stderr or stdout}"}

        return {"success": True}

    except Exception as e:
        return {"success": False, "error": f"Ошибка: {e}"}


def flush_dns_cache():
    """Очищает системный DNS-кеш Windows (ipconfig /flushdns)."""
    try:
        result = subprocess.run(
            ["ipconfig", "/flushdns"],
            capture_output=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            app_logger.info("DNS-кеш Windows очищен")
            return True
        else:
            stderr = result.stderr.decode("cp866", errors="replace").strip()
            app_logger.warn(f"Не удалось очистить DNS-кеш: {stderr}")
            return False
    except Exception as e:
        app_logger.warn(f"Ошибка очистки DNS-кеша: {e}")
        return False


# ── Распознавание текущего режима DNS ───────────────────────────────────────

def _norm_ip(ip):
    """Нормализует строку IP для сравнения (trim пробелов)."""
    return (ip or "").strip()


def _profile_ip_set(profile):
    """Возвращает множество нормализованных IP профиля (primary + secondary)."""
    ips = set()
    p = _norm_ip(profile.get("primary"))
    s = _norm_ip(profile.get("secondary"))
    if p:
        ips.add(p)
    if s:
        ips.add(s)
    return ips


def detect_dns_mode(dns_servers, geohide_known_ips=None, is_dhcp=False, dns_profiles=None):
    """Распознаёт текущий режим DNS. Возвращает (profile_id | None, display_name).

    Порядок сопоставления:
      1. DHCP / пустой список DNS → стандартный системный DNS (id="standard").
      2. Точное совпадение множества системных DNS с (primary, secondary)
         какого-либо пользовательского профиля. Сравнение идёт множествами,
         поэтому порядок primary/secondary не важен, а лишние пробелы
         нормализуются.
      3. Для профилей типа "geohide" допускается подмножество: их адреса
         резолвятся динамически, поэтому в системе могут стоять как
         захардкоженные резервы (GEOHIDE_FALLBACK_IPS), так и свежие IP
         (geohide_known_ips). Если все системные DNS принадлежат этому
         расширенному множеству — считаем профиль активным.
      4. Иначе — DNS не соответствует ни одной кнопке приложения.
    """
    from dnsmgr.constants import GEOHIDE_FALLBACK_IPS

    # 1. DHCP / нет данных → стандартный DNS.
    if is_dhcp or not dns_servers:
        return ("standard", "Стандартный DNS (DHCP)")

    servers_set = set(_norm_ip(x) for x in dns_servers if _norm_ip(x))
    if not servers_set:
        return ("standard", "Стандартный DNS (DHCP)")

    profiles = dns_profiles or []

    # 2. Точное совпадение с профилем (порядок primary/secondary не важен).
    for profile in profiles:
        profile_ips = _profile_ip_set(profile)
        if profile_ips and profile_ips == servers_set:
            return (profile["id"], profile["name"])

    # 3. Geohide: допускаем подмножество с учётом динамически резолвленных IP.
    geohide_extra = set(_norm_ip(x) for x in GEOHIDE_FALLBACK_IPS)
    if geohide_known_ips:
        geohide_extra.update(_norm_ip(x) for x in geohide_known_ips)
    for profile in profiles:
        if profile.get("type") != "geohide":
            continue
        allowed = _profile_ip_set(profile) | geohide_extra
        if servers_set <= allowed:
            return (profile["id"], profile["name"])

    # 4. Совпадений нет — DNS установлен вручную, и такой кнопки в приложении нет.
    return (None, "DNS не соответствует ни одной кнопке")


# ── Проверка DNS: nslookup + getaddrinfo ────────────────────────────────────

def _nslookup_resolve(domain, timeout=DNS_RESOLVE_TIMEOUT):
    """Резолвит домен через nslookup (fallback если socket не работает)."""
    try:
        result = subprocess.run(
            ["nslookup", domain],
            capture_output=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        output = result.stdout.decode("utf-8", errors="replace")
        ip_pattern = re.compile(r'Address:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        ips = ip_pattern.findall(output)
        if len(ips) >= 2:
            return ips[1]
        elif len(ips) == 1:
            return ips[0]
        return None
    except Exception:
        return None


def verify_dns_working():
    """Проверяет, что DNS действительно работает, резолвя тестовый домен."""
    try:
        with socket_timeout_lock:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(DNS_RESOLVE_TIMEOUT)
            try:
                results = socket.getaddrinfo(TEST_DOMAIN, 80, socket.AF_INET)
            finally:
                socket.setdefaulttimeout(old_timeout)
        if results:
            ip = results[0][4][0]
            return {"working": True, "resolved_ip": ip}
    except Exception:
        pass

    try:
        ip = _nslookup_resolve(TEST_DOMAIN)
        if ip:
            return {"working": True, "resolved_ip": ip}
        return {"working": False, "error": "DNS не отвечает (nslookup не вернул IP)"}
    except Exception as e:
        return {"working": False, "error": f"Ошибка проверки DNS: {e}"}


# ── Проверка готовности сети / интернета ────────────────────────────────────

def _check_internet_connectivity():
    """Быстрая проверка реальной интернет-связности через TCP-подключение."""
    targets = [("1.1.1.1", 53), ("8.8.8.8", 53), ("77.88.8.8", 53)]
    for host, port in targets:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                sock.connect((host, port))
                return True
            finally:
                sock.close()
        except Exception:
            continue
    return False


# Microsoft NCSI — стандартный механизм, которым сама Windows определяет
# наличие интернета. Запросы идут по IP без DNS, чтобы детект работал даже
# при сломанном DNS на текущем адаптере. Captive portal обычно перехватывает
# HTTP и возвращает HTML портала вместо ожидаемого тела — так его и ловим.
# Известные anchor-IP NCSI могут со временем меняться: это не страшно, на
# уровне приложения худшим исходом будет пропуск авто-перепривязки (скатимся
# к существующему «нет сети»), а не ложное срабатывание.
_NCSI_PROBES = [
    # (ip, path, host_header, expected_substring)
    ("13.107.4.52", "/connecttest.txt", "www.msftconnecttest.com", "Microsoft Connect Test"),
    ("23.218.52.222", "/ncsi.txt", "www.msftncsi.com", "Microsoft NCSI"),
]


def _verify_real_internet():
    """Строгая проверка реального интернета: TCP + HTTP-проба по IP.

    Используется ТОЛЬКО там, где ложноположительный «интернет есть» приведёт
    к деструктивному действию (авто-перепривязка адаптера). Этап 1 — быстрый
    TCP-чек на public DNS (порт 53). Этап 2 — HTTP-запрос к anchor-IP NCSI
    (без DNS): если в теле ответа найдена ожидаемая подпись, интернет
    действительно есть; если ответ пришёл, но тело другое — это captive
    portal, считаем «нет интернета» и не перепривязываемся.

    Если все NCSI-пробы фейлятся (anchor-IP сменился или firewall блокирует
    HTTP к ним) — возвращаем False. Цена ошибки: пропуск авто-перепривязки.
    """
    if not _check_internet_connectivity():
        return False
    try:
        import http.client
    except Exception:
        # http.client недоступен — fallback на TCP-результат, чтобы не блокировать
        # перепривязку в нереалистичном окружении.
        return True
    for ip, path, host_header, expected in _NCSI_PROBES:
        try:
            conn = http.client.HTTPConnection(ip, 80, timeout=3)
            try:
                conn.request("GET", path, headers={
                    "Host": host_header,
                    "User-Agent": "Microsoft NCSI",
                    "Connection": "close",
                })
                resp = conn.getresponse()
                if resp.status == 200:
                    body = resp.read(256).decode("ascii", errors="replace")
                    if expected in body:
                        return True
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        except Exception:
            continue
    return False


def check_network_ready(adapter_name):
    """Проверяет базовую готовность сети: адаптер подключён, есть IP, шлюз доступен."""
    if not adapter_name:
        return {"state": NETWORK_NO_CONNECTION, "reason": "no_adapter"}
    try:
        safe_name = adapter_name.replace("'", "''")
        ps_cmd = (
            f"Get-NetIPConfiguration -InterfaceAlias '{safe_name}' | "
            "Select-Object -Property "
            "@{N='IP';E={($_.IPv4Address.IPAddress -join ',')}}, "
            "@{N='GW';E={($_.IPv4DefaultGateway.NextHop -join ',')}} | "
            "ConvertTo-Json -Compress"
        )
        rc, stdout, stderr = _run_powershell(ps_cmd, timeout=5)
        if rc != 0 or not stdout:
            return {"state": NETWORK_NO_CONNECTION, "reason": "adapter_error"}

        data = json.loads(stdout)
        ip_addr = (data.get("IP") or "").split(",")[0].strip()
        gateway = (data.get("GW") or "").split(",")[0].strip()

        if not ip_addr:
            return {"state": NETWORK_NO_CONNECTION, "reason": "no_ip"}
        if not gateway:
            return {"state": NETWORK_NO_CONNECTION, "reason": "no_gateway"}

        # Ping шлюза — проверка базовой сетевой связности
        ping_result = subprocess.run(
            ["ping", "-n", "1", "-w", "2000", gateway],
            capture_output=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if ping_result.returncode == 0:
            return {"state": NETWORK_READY, "ip": ip_addr, "gateway": gateway}

        # Ping не прошёл — это НЕ обязательно означает проблему.
        # Многие роутеры блокируют/игнорируют ICMP, а единичный пакет может быть потерян.
        # Проверяем реальную интернет-связность через TCP-подключение.
        if _check_internet_connectivity():
            return {"state": NETWORK_READY, "ip": ip_addr, "gateway": gateway}

        # Повторный ping (2-я попытка) перед объявлением проблемы
        try:
            ping_result2 = subprocess.run(
                ["ping", "-n", "2", "-w", "2000", gateway],
                capture_output=True, timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if ping_result2.returncode == 0:
                return {"state": NETWORK_READY, "ip": ip_addr, "gateway": gateway}
        except Exception:
            pass

        return {"state": NETWORK_UNSTABLE, "reason": "gateway_unreachable", "gateway": gateway}

    except subprocess.TimeoutExpired:
        # Таймаут — проверяем реальную связность прежде чем объявлять проблему
        if _check_internet_connectivity():
            return {"state": NETWORK_READY, "ip": "?", "gateway": "?"}
        return {"state": NETWORK_UNSTABLE, "reason": "timeout"}
    except json.JSONDecodeError:
        return {"state": NETWORK_NO_CONNECTION, "reason": "parse_error"}
    except Exception:
        return {"state": NETWORK_NO_CONNECTION, "reason": "check_error"}


# ── Адресный DNS-запрос: время отклика и проверка резолва домена ─────────────
#
# Чтобы измерить латентность конкретного DNS-сервера и проверить, резолвит ли
# он нужный домен, нельзя пользоваться обычным socket.getaddrinfo — тот идёт
# через системный резолвер (текущий DNS адаптера), а не через выбранный сервер.
# Поэтому формируем «сырой» DNS-запрос (A-запись) и шлём его UDP напрямую на
# <dns_ip>:53. Это ровно то, что делает DNS Jumper при «Проверить время
# отклика» / «Fastest DNS», и работает без сторонних библиотек.
#
# encode/parse вынесены в отдельные чистые функции — их покрывают юнит-тесты,
# а сетевой ввод/вывод изолирован в dns_query().

def _normalize_domain(text):
    """Извлекает чистое доменное имя из произвольного пользовательского ввода.

    Примеры:
        'https://chatgpt.com/foo?x=1' -> 'chatgpt.com'
        'CHATGPT.com:443'             -> 'chatgpt.com'
        'user@example.com'            -> 'example.com'
        'example.com.'                -> 'example.com'

    Нужна, потому что пользователь часто копирует ссылку целиком, а в DNS-запрос
    должен идти только хост — иначе QNAME получается мусорным («https://chatgpt»),
    и сервер отвечает ошибкой. Чистая функция.
    """
    s = (text or "").strip()
    if not s:
        return ""
    if "://" in s:                       # убрать схему http(s)://, и т.п.
        s = s.split("://", 1)[1]
    for sep in ("/", "?", "#", "\\"):    # убрать путь/параметры/якорь
        if sep in s:
            s = s.split(sep, 1)[0]
    if "@" in s:                         # убрать user@ (если вставили креды)
        s = s.split("@", 1)[1]
    if ":" in s:                         # убрать :порт
        s = s.split(":", 1)[0]
    return s.strip().strip(".").lower()


def _encode_dns_query(domain, query_id):
    """Собирает байты DNS-запроса A-записи для домена. Чистая функция.

    Заголовок: ID, flags=0x0100 (стандартный запрос, recursion desired),
    QDCOUNT=1, остальные счётчики 0. Затем QNAME (метки), QTYPE=A(1), QCLASS=IN(1).
    """
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    qname = bytearray()
    for label in domain.strip(".").split("."):
        if not label:
            continue
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError:
            # IDN-домены (кириллица и т.п.) → punycode
            raw = label.encode("idna")
        if len(raw) > 63:
            raise ValueError("метка домена длиннее 63 байт")
        qname.append(len(raw))
        qname.extend(raw)
    qname.append(0)  # корень
    question = bytes(qname) + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def _skip_dns_name(data, off):
    """Пропускает доменное имя в DNS-сообщении (с учётом сжатия). Возвращает
    смещение сразу после имени."""
    while True:
        if off >= len(data):
            raise ValueError("обрыв имени")
        length = data[off]
        if length == 0:
            return off + 1
        if (length & 0xC0) == 0xC0:  # указатель сжатия (2 байта)
            return off + 2
        off += 1 + length


def _parse_dns_response(data, query_id):
    """Извлекает список IPv4 (A-записи) из DNS-ответа. Чистая функция.

    Бросает ValueError при несовпадении ID, не-ответе или ненулевом RCODE
    (например, NXDOMAIN — домен не резолвится этим сервером).
    """
    if len(data) < 12:
        raise ValueError("слишком короткий ответ")
    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if rid != query_id:
        raise ValueError("несовпадение ID запроса")
    if not (flags & 0x8000):
        raise ValueError("это не ответ")
    rcode = flags & 0x000F
    if rcode != 0:
        # 3 = NXDOMAIN (домена нет), 2 = SERVFAIL, 5 = REFUSED (часто блокировка)
        raise ValueError(f"RCODE={rcode}")
    off = 12
    for _ in range(qd):           # пропускаем секцию вопросов
        off = _skip_dns_name(data, off)
        off += 4                  # QTYPE + QCLASS
    ips = []
    for _ in range(an):           # секция ответов
        off = _skip_dns_name(data, off)
        if off + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:  # A-запись
            ips.append(".".join(str(b) for b in rdata))
    return ips


def dns_query(dns_ip, domain, timeout=2.5, retries=1):
    """Шлёт UDP DNS A-запрос напрямую на dns_ip:53 и замеряет время ответа.

    Ввод домена нормализуется (схема/путь/порт отбрасываются). При таймауте
    делается до `retries` повторов — UDP-пакеты теряются, и единичный таймаут
    не означает, что сервер недоступен.

    Возвращает dict:
        {"ok": bool, "latency_ms": float|None, "ips": [str], "error": str|None}
    ok=True означает: сервер ответил И ответ корректно разобран (домен
    резолвится). ok=False с latency_ms!=None — сервер ответил, но отказал
    (NXDOMAIN/REFUSED) либо ответ не разобран.
    """
    domain = _normalize_domain(domain)
    if not domain:
        return {"ok": False, "latency_ms": None, "ips": [], "error": "пустой домен"}

    last_err = "таймаут"
    for _attempt in range(retries + 1):
        try:
            query_id = int.from_bytes(os.urandom(2), "big")
        except Exception:
            query_id = 0x1234
        try:
            packet = _encode_dns_query(domain, query_id)
        except Exception as e:
            return {"ok": False, "latency_ms": None, "ips": [], "error": f"домен: {e}"}

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            t0 = time.perf_counter()
            sock.sendto(packet, (dns_ip, 53))
            data, _ = sock.recvfrom(2048)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        except socket.timeout:
            last_err = "таймаут"
            continue  # повторяем (UDP мог потеряться)
        except Exception as e:
            return {"ok": False, "latency_ms": None, "ips": [], "error": str(e)}
        finally:
            try:
                sock.close()
            except Exception:
                pass

        try:
            ips = _parse_dns_response(data, query_id)
        except Exception as e:
            return {"ok": False, "latency_ms": elapsed_ms, "ips": [], "error": str(e)}
        return {"ok": True, "latency_ms": elapsed_ms, "ips": ips, "error": None}

    return {"ok": False, "latency_ms": None, "ips": [], "error": last_err}


def _tcp_connect_ok(ip, port, timeout=2.0):
    """True, если до ip:port удаётся установить TCP-соединение."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def check_resource_via_dns(dns_ip, domain, timeout=2.5):
    """Проверяет, откроется ли `domain` через конкретный DNS-сервер `dns_ip`.

    Шаг 1 — резолв домена напрямую через этот сервер (dns_query, с повтором
    при таймауте).
    Шаг 2 (только при успешном резолве) — лёгкая TCP-проба к полученному IP
    на 443/80: отвечает ли ресурс. Это отделяет «DNS вернул адрес» от «адрес
    реально доступен».

    Возвращает dict:
        {"resolved": bool, "latency_ms": float|None, "ips": [str],
         "reachable": bool|None, "error": str|None}
    reachable=None означает, что проба не проводилась (домен не зарезолвился).
    """
    q = dns_query(dns_ip, domain, timeout=timeout)
    if not q["ok"] or not q["ips"]:
        return {
            "resolved": False,
            "latency_ms": q.get("latency_ms"),
            "ips": [],
            "reachable": None,
            "error": q.get("error") or "нет A-записи",
        }
    ip = q["ips"][0]
    reachable = _tcp_connect_ok(ip, 443, timeout) or _tcp_connect_ok(ip, 80, timeout)
    return {
        "resolved": True,
        "latency_ms": q["latency_ms"],
        "ips": q["ips"],
        "reachable": reachable,
        "error": None,
    }
