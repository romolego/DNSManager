"""Настройки приложения и DNS-профили.

Все операции с settings.json и валидацией DNS-профилей собраны здесь.
Чистые функции (без побочных эффектов): _sanitize_dns_profiles,
get_profile_by_id, get_desired_mode_label, _get_default_dns_profiles —
их и тестируем юнит-тестами.
"""

import json

from dnsmgr.constants import (
    DEFAULT_DNS_BUTTONS_PER_ROW,
    DEFAULT_DNS_PROFILES,
    HEALTH_CHECK_INTERVAL,
    HEALTH_CHECK_INTERVAL_MIN,
    SETTINGS_PATH,
)
from dnsmgr.logger import app_logger, ensure_appdata_dir


DEFAULT_SETTINGS = {
    "autostart": True,
    "start_minimized": True,
    "autostart_admin": True,
    "autostart_show_admin_prompt": True,
    "selected_adapter": None,
    "manual_adapter": None,          # Явный выбор пользователя — должен переживать рестарт
    "geohide_resolved_ips": [],
    "desired_mode": None,
    "selected_dns_recovery_mode": "reset_and_restore",
    "failure_threshold": 3,
    "health_check_interval": 15,
    "require_admin": True,
    "close_to_tray": True,
    "apply_to_all_adapters": False,
    "external_dns_change_mode": "notify",
    "dns_profiles": None,            # Миграция: None → DEFAULT_DNS_PROFILES при первом запуске
    "dns_buttons_per_row": DEFAULT_DNS_BUTTONS_PER_ROW,
    "cleanup_done_for_version": "",
}


def get_desired_mode_label(mode, dns_profiles=None):
    """Возвращает человекочитаемое название режима по profile_id."""
    if mode == "standard":
        return "Стандартный DNS (DHCP)"
    if mode is None:
        return "Не задан"
    if dns_profiles:
        for p in dns_profiles:
            if p["id"] == mode:
                return p["name"]
    return mode


def get_profile_by_id(dns_profiles, profile_id):
    """Возвращает профиль по id или None."""
    for p in dns_profiles:
        if p["id"] == profile_id:
            return p
    return None


def _get_default_dns_profiles():
    """Возвращает свежую копию дефолтного набора DNS-профилей."""
    return [dict(p) for p in DEFAULT_DNS_PROFILES]


def _sanitize_dns_profiles(profiles):
    """Валидирует и нормализует загруженный список DNS-профилей.

    Возвращает:
      - list (в т.ч. пустой []) — корректно загруженные профили;
        пустой список означает намеренно пустое пользовательское
        состояние (после действия «Удалить все кнопки») и сохраняется
        как есть, без подстановки дефолтного набора;
      - None — данные в настройках отсутствуют или мусорные (не list);
        в этом случае вызывающая сторона подставит дефолтный набор
        (поведение первого запуска / миграции со старой версии).
    """
    if profiles is None:
        return None
    if not isinstance(profiles, list):
        return None
    # Пустой список на входе — намеренно пустое состояние (после
    # «Удалить все кнопки»). Возвращаем [] сразу, минуя фильтрацию,
    # чтобы не спутать его со случаем «список был непустой, но ВСЕ
    # элементы — мусор» (ниже), который трактуется как повреждённые
    # данные и сбрасывается в дефолт.
    if not profiles:
        return []
    cleaned = []
    seen_ids = set()
    for raw in profiles:
        if not isinstance(raw, dict):
            continue
        pid = str(raw.get("id") or "").strip()
        name = str(raw.get("name") or "").strip()
        primary = str(raw.get("primary") or "").strip()
        if not pid or not name or not primary:
            continue
        ptype = raw.get("type") or "static"
        if ptype not in ("geohide", "static"):
            ptype = "static"
        # Дубли id обходим: id используется как desired_mode и должен быть уникален
        unique_id = pid
        suffix = 2
        while unique_id in seen_ids:
            unique_id = f"{pid}_{suffix}"
            suffix += 1
        seen_ids.add(unique_id)
        cleaned.append({
            "id": unique_id,
            "name": name,
            "type": ptype,
            "primary": primary,
            "secondary": str(raw.get("secondary") or "").strip(),
        })
    # Если исходный список был непустой, но все элементы оказались
    # мусорными — это повреждённые данные, а не намеренная очистка.
    # Возвращаем None, чтобы вызывающая сторона подставила дефолт.
    if not cleaned:
        return None
    return cleaned


def load_settings():
    """Загружает настройки из JSON-файла."""
    ensure_appdata_dir()
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Миграция ключа восстановления: geohide_recovery_mode -> selected_dns_recovery_mode
        if "selected_dns_recovery_mode" not in data and "geohide_recovery_mode" in data:
            data["selected_dns_recovery_mode"] = data.get("geohide_recovery_mode")
        settings = dict(DEFAULT_SETTINGS)
        # Берём только известные ключи, чтобы не тащить мусор от старых версий
        for key in DEFAULT_SETTINGS:
            if key in data:
                settings[key] = data[key]
    except Exception:
        settings = dict(DEFAULT_SETTINGS)
    # Валидация минимального интервала проверки
    try:
        if int(settings.get("health_check_interval", HEALTH_CHECK_INTERVAL)) < HEALTH_CHECK_INTERVAL_MIN:
            settings["health_check_interval"] = HEALTH_CHECK_INTERVAL_MIN
    except (ValueError, TypeError):
        settings["health_check_interval"] = HEALTH_CHECK_INTERVAL
    # Валидация и нормализация dns_profiles. При отсутствии ключа или
    # мусорных данных (None, не-list) — подставляем актуальный дефолтный
    # набор (сценарий первого запуска / миграции). Намеренно пустой
    # список [] сохраняется как есть: это допустимое пользовательское
    # состояние после действия «Удалить все кнопки».
    sanitized = _sanitize_dns_profiles(settings.get("dns_profiles"))
    if sanitized is None:
        settings["dns_profiles"] = _get_default_dns_profiles()
    else:
        settings["dns_profiles"] = sanitized
    # Валидация dns_buttons_per_row
    try:
        bpr = int(settings.get("dns_buttons_per_row", DEFAULT_DNS_BUTTONS_PER_ROW))
        if bpr < 1:
            bpr = 1
        elif bpr > 5:
            bpr = 5
        settings["dns_buttons_per_row"] = bpr
    except (ValueError, TypeError):
        settings["dns_buttons_per_row"] = DEFAULT_DNS_BUTTONS_PER_ROW
    return settings


_save_settings_warned = False


def save_settings(settings):
    """Сохраняет настройки в JSON-файл. Возвращает True при успехе.

    Ошибка записи логируется один раз за сессию, чтобы при сломанном
    %APPDATA% не засорять лог при каждом изменении настроек.
    """
    global _save_settings_warned
    ensure_appdata_dir()
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
        _save_settings_warned = False
        return True
    except Exception as e:
        if not _save_settings_warned:
            _save_settings_warned = True
            try:
                app_logger.error(f"Не удалось сохранить настройки в {SETTINGS_PATH}: {e}")
            except Exception:
                pass
        return False
