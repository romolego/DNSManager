"""Двойное логирование: в файл (с автообрезкой) и в GUI-виджет.

Синглтон `app_logger` создаётся при первом импорте модуля. Импорт безопасен
до создания AppData-папки: создание файлового хэндлера обёрнуто в try/except,
и при невозможности писать в файл логирование продолжит работать только в
GUI (если callback установлен).
"""

import logging
import os
import threading
from datetime import datetime

from dnsmgr.constants import APPDATA_DIR, LOG_PATH, MAX_LOG_LINES


def ensure_appdata_dir():
    """Создаёт директорию для данных приложения."""
    os.makedirs(APPDATA_DIR, exist_ok=True)


class AppLogger:
    """Двойное логирование: в файл и в GUI-виджет."""

    def __init__(self):
        self.gui_callback = None
        self.file_ok = True
        self._lock = threading.Lock()
        self._write_count = 0
        self._trim_every = 500  # проверять размер каждые N записей
        self.logger = logging.getLogger("DNSManager")
        self.logger.setLevel(logging.DEBUG)
        ensure_appdata_dir()
        self._trim_log_file()
        self._setup_file_logger()

    def _create_file_handler(self):
        """Создаёт и возвращает FileHandler для лог-файла."""
        handler = logging.FileHandler(LOG_PATH, encoding="utf-8", mode="a")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                                datefmt="%Y-%m-%d %H:%M:%S"))
        return handler

    def _setup_file_logger(self):
        try:
            self.logger.addHandler(self._create_file_handler())
            self.file_ok = True
        except Exception:
            self.file_ok = False

    def _trim_log_file(self):
        """Обрезает лог-файл до последних MAX_LOG_LINES строк.
        Безопасно закрывает FileHandler перед перезаписью и открывает заново после."""
        try:
            if not os.path.exists(LOG_PATH):
                return
            with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            if len(lines) <= MAX_LOG_LINES:
                return

            # Закрываем все файловые хэндлеры перед перезаписью
            for h in list(self.logger.handlers):
                if isinstance(h, logging.FileHandler):
                    self.logger.removeHandler(h)
                    h.close()

            # Перезаписываем файл — ни один FileHandler не держит его открытым
            with open(LOG_PATH, "w", encoding="utf-8") as f:
                f.writelines(lines[-MAX_LOG_LINES:])

            # Открываем новый FileHandler
            try:
                self.logger.addHandler(self._create_file_handler())
            except Exception:
                self.file_ok = False
        except Exception:
            pass

    def set_gui_callback(self, callback):
        """Устанавливает функцию для вывода в GUI."""
        self.gui_callback = callback

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] [{level}] {message}"

        with self._lock:
            try:
                if self.file_ok:
                    if level == "ERROR":
                        self.logger.error(message)
                    elif level == "WARN":
                        self.logger.warning(message)
                    else:
                        self.logger.info(message)
                    self._write_count += 1
                    if self._write_count >= self._trim_every:
                        self._write_count = 0
                        self._trim_log_file()
            except Exception:
                self.file_ok = False

        if self.gui_callback:
            try:
                self.gui_callback(entry)
            except Exception:
                pass

    def info(self, msg):
        self.log(msg, "INFO")

    def warn(self, msg):
        self.log(msg, "WARN")

    def error(self, msg):
        self.log(msg, "ERROR")


app_logger = AppLogger()
