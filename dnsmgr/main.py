"""Точка входа: single-instance, очистка устаревших записей, запуск GUI."""

import sys

from dnsmgr.app import DNSManagerApp
from dnsmgr.autostart import (
    cleanup_stale_autostart_entries,
    refresh_current_autostart_entries,
)
from dnsmgr.config import load_settings, save_settings
from dnsmgr.constants import APP_VERSION
from dnsmgr.logger import app_logger, ensure_appdata_dir
from dnsmgr.process import acquire_single_instance, focus_existing_instance


def main():
    if acquire_single_instance() is None:
        focus_existing_instance()
        sys.exit(0)

    ensure_appdata_dir()

    # ── Очистка устаревших записей автозапуска от старых версий ─────────────
    # Источник истины — текущий запущенный exe. Запись в HKCU\Run и
    # именованная задача Планировщика, указывающие на другой путь, удаляются;
    # затем актуальные записи пересоздаются с путём к текущему exe. Это
    # гарантирует, что после перезагрузки Windows будет запущен только
    # текущий exe.
    try:
        settings_for_refresh = load_settings()
        # Зачистка старых записей автозапуска выполняется один раз на каждую
        # версию приложения. Маркер сохраняется в settings.json, так что
        # повторный запуск той же версии не будет дёргать реестр и schtasks
        # без необходимости — это и снимает нагрузку с AV-эвристик, и
        # экономит время старта.
        if settings_for_refresh.get("cleanup_done_for_version") != APP_VERSION:
            cleanup_stale_autostart_entries()
            refresh_current_autostart_entries(settings_for_refresh)
            settings_for_refresh["cleanup_done_for_version"] = APP_VERSION
            save_settings(settings_for_refresh)
    except Exception as e:
        app_logger.warn(f"Ошибка очистки старых записей автозапуска: {e}")

    # Запуск в трей только при наличии аргумента командной строки
    # Ручной запуск — окно всегда видно
    start_hidden = "--minimized" in sys.argv

    app = DNSManagerApp(start_hidden=start_hidden)
    app.run()
