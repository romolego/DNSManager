"""Константы приложения.

Этот модуль не имеет зависимостей от других модулей пакета и может быть
импортирован первым. Все «магические» числа и пути живут здесь.
"""

import os
import subprocess
import sys
import threading

# ── Платформа ────────────────────────────────────────────────────────────────
# DNS Manager изначально написан под Windows; ветка macos добавляет поддержку
# macOS, не ломая Windows-поведение. Эти флаги — единственный источник правды
# о платформе для всего пакета.
IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"

# Флаг «не показывать консольное окно» существует только в Windows-сборке
# subprocess. На macOS/Linux его нет, поэтому подставляем 0 (нейтральное
# значение, которое subprocess.run игнорирует на POSIX). Все вызовы
# subprocess в пакете используют именно этот флаг.
NO_WINDOW_FLAG = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0

# ── Идентификация приложения ─────────────────────────────────────────────────
APP_NAME = "DNS Manager"
APP_VERSION = "1.0.0"
APP_MUTEX_NAME = "Global\\DNSManagerMutex_v1"
APP_WINDOW_CLASS = "DNSManagerMainWindow"

# ── GeoHide ──────────────────────────────────────────────────────────────────
GEOHIDE_DOMAIN = "dns.geohide.ru"
GEOHIDE_FALLBACK_IPS = ["45.155.204.190", "37.230.192.51"]
GEOHIDE_LEGACY_FALLBACK_IPS = ["45.131.7.1", "45.131.7.2"]

# ── DNS-профили по умолчанию ─────────────────────────────────────────────────
# Применяется при первом запуске, при сбросе DNS-кнопок к стандартному набору
# и при полном сбросе настроек. Первый профиль автоматически считается
# приоритетным. Тип «geohide» — служебный: соответствующий профиль динамически
# резолвится через dns.geohide.ru, остальные («static») применяются как есть.
DEFAULT_DNS_PROFILES = [
    {
        "id": "geohide", "name": "GeoHide", "type": "geohide",
        "primary": "45.155.204.190", "secondary": "37.230.192.51",
        "source_url": "https://status.dns.geohide.ru/",
        "fetch_url": "dns.geohide.ru",
    },
    {
        "id": "xbox_dns", "name": "Xbox-dns", "type": "static",
        "primary": "176.99.11.77", "secondary": "80.78.247.254",
        "source_url": "https://t.me/s/xbox_dns",
        "fetch_url": "",
    },
    {
        "id": "comss", "name": "Comss", "type": "static",
        "primary": "83.220.169.155", "secondary": "212.109.195.93",
        "source_url": "https://www.comss.ru/page.php?id=7315",
        "fetch_url": "",
    },
    {
        "id": "cloudflare", "name": "Cloudflare", "type": "static",
        "primary": "1.1.1.1", "secondary": "1.0.0.1",
        "source_url": "https://one.one.one.one/dns/",
        "fetch_url": "",
    },
    {
        "id": "adguard", "name": "AdGuard", "type": "static",
        "primary": "94.140.14.14", "secondary": "94.140.15.15",
        "source_url": "https://adguard-dns.io/en/public-dns.html",
        "fetch_url": "dns.adguard-dns.com",
    },
    {
        "id": "malw_link", "name": "MalwareDefender", "type": "static",
        "primary": "84.21.189.133", "secondary": "193.23.209.189",
        "source_url": "https://info.dns.malw.link/",
        "fetch_url": "https://info.dns.malw.link/",
    },
    {
        "id": "mafioznik", "name": "MFZ", "type": "static",
        "primary": "103.27.157.38", "secondary": "103.27.157.100",
        "source_url": "https://dns.mafioznik.xyz/",
        "fetch_url": "dns.mafioznik.xyz",
    },
    {
        "id": "astracat", "name": "Astracat", "type": "static",
        "primary": "185.139.69.24", "secondary": "77.239.113.0",
        "source_url": "https://github.com/ASTRACAT2022/AstracatDNS",
        "fetch_url": "",
    },
]

DEFAULT_DNS_BUTTONS_PER_ROW = 4

# ── Проверка DNS ─────────────────────────────────────────────────────────────
TEST_DOMAIN = "google.com"
DNS_PROFILE_TEST_DOMAIN = "chatgpt.com"
DNS_RESOLVE_TIMEOUT = 5

# Сериализация доступа к socket.setdefaulttimeout: getaddrinfo не принимает
# per-call таймаут, поэтому единственный способ ограничить его — глобальная
# настройка. Без этого лока параллельные вызовы из HealthMonitor / диалога
# редактора профиля могут читать и перезаписывать «old_timeout» друг друга,
# оставляя процесс с неожиданным глобальным таймаутом сокетов.
socket_timeout_lock = threading.Lock()

# Пауза после netsh-операции перед контрольным чтением DNS из системы.
# Эмпирическое значение: Windows иногда возвращает «старое» состояние, если
# опрашивать его сразу после set/reset. 1 сек хватает на типовом железе.
DNS_APPLY_SETTLE_DELAY = 1

# ── Мониторинг здоровья DNS ──────────────────────────────────────────────────
HEALTH_CHECK_INTERVAL = 15       # секунд между проверками
HEALTH_CHECK_INTERVAL_MIN = 5    # минимально допустимый интервал
FAILURE_THRESHOLD = 3            # последовательных неудач до восстановления
MAX_RECOVERY_ATTEMPTS = 3        # максимум автовосстановлений за сессию
INTERNET_WAIT_INTERVAL = 5       # секунд между проверками интернета при восстановлении
INTERNET_WAIT_TIMEOUT = 120      # максимум секунд ожидания интернета
RESUME_TIME_JUMP_FACTOR = 3      # множитель интервала для детекции resume-from-sleep
RESUME_ADAPTER_RETRY_DELAYS = [2, 3, 5, 5, 5, 5]  # задержки (сек) при ожидании адаптера после resume

# Состояния сетевого подключения
NETWORK_NO_CONNECTION = "no_network"   # адаптер не подключён / нет IP / нет шлюза
NETWORK_UNSTABLE = "unstable"          # адаптер подключён, но шлюз недоступен
NETWORK_READY = "ready"                # адаптер подключён, шлюз доступен

# ── Файловые пути ────────────────────────────────────────────────────────────
# Каталог данных приложения зависит от платформы:
#   Windows — %APPDATA%\DNSManager
#   macOS   — ~/Library/Application Support/DNSManager
#   прочее  — ~/.config/DNSManager
if IS_WINDOWS:
    APPDATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "DNSManager")
elif IS_MACOS:
    APPDATA_DIR = os.path.join(os.path.expanduser("~/Library/Application Support"), "DNSManager")
else:
    APPDATA_DIR = os.path.join(os.path.expanduser("~/.config"), "DNSManager")
SETTINGS_PATH = os.path.join(APPDATA_DIR, "settings.json")
LOG_PATH = os.path.join(APPDATA_DIR, "dns_manager.log")
MAX_LOG_LINES = 10000
MAX_GUI_LOG_LINES = 200

# ── Автозапуск ───────────────────────────────────────────────────────────────
AUTOSTART_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_REG_VALUE = "DNSManager"
TASK_SCHEDULER_TASK_NAME = "DNSManagerAutostart"

# ── Получение DNS по ссылке ──────────────────────────────────────────────────
LINK_FETCH_TIMEOUT = 8
LINK_FETCH_MAX_BYTES = 512 * 1024
LINK_FETCH_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
DNS_HOST_PREFIXES = ("dns", "doh", "dot", "doq", "resolver", "ns", "ns1", "ns2")
