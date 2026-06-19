"""Управление процессом: права администратора и single-instance.

Содержит:
  - is_admin / restart_as_admin — проверка и повышение прав (UAC на Windows;
    на macOS повышение делается per-команда через osascript, см. network.py);
  - acquire_single_instance / focus_existing_instance — Win32-мьютекс и
    поиск окна уже запущенной копии (на macOS — lock-файл).
"""

import ctypes
import os
import sys

from dnsmgr.constants import APP_MUTEX_NAME, APP_NAME, APPDATA_DIR, IS_MACOS


_mutex_handle = None  # Глобальная ссылка на мьютекс для предотвращения GC
_lock_file = None     # Глобальная ссылка на lock-файл (POSIX single-instance)


def is_admin():
    """Проверяет, запущен ли процесс с правами администратора.

    На macOS приложение само по себе не нуждается в root: каждое изменение
    DNS повышается отдельно через системный диалог пароля (osascript
    `with administrator privileges`). Поэтому здесь возвращаем True — это
    отключает Windows-специфичные UAC-подсказки и включает обычный поток
    действий (кнопки применения/сброса DNS работают сразу)."""
    if IS_MACOS:
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def restart_as_admin():
    """Перезапускает приложение с запросом прав администратора (UAC)."""
    if IS_MACOS:
        # На macOS повышение делается per-команда, перезапуск всего приложения
        # под root не нужен. is_admin() уже True, так что этот путь обычно не
        # вызывается; возвращаем True как «уже всё в порядке».
        return True
    try:
        if getattr(sys, 'frozen', False):
            exe = sys.executable
            params = " ".join(sys.argv[1:])
        else:
            exe = sys.executable
            params = '"' + os.path.abspath(sys.argv[0]) + '"'
            if len(sys.argv) > 1:
                params += " " + " ".join(sys.argv[1:])

        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, params, None, 1
        )
        if ret > 32:
            # Явное освобождение мьютекса перед завершением процесса.
            # Гарантирует, что новый процесс не увидит занятый мьютекс
            # и не завершится ложно из-за single instance проверки.
            global _mutex_handle
            if _mutex_handle is not None:
                kernel32 = ctypes.windll.kernel32
                kernel32.ReleaseMutex(_mutex_handle)
                kernel32.CloseHandle(_mutex_handle)
                _mutex_handle = None
            sys.exit(0)
        else:
            return False
    except Exception:
        return False


def _posix_acquire_single_instance():
    """Single-instance через эксклюзивный flock на lock-файле в каталоге данных.

    Возвращает объект файла (handle) или None, если экземпляр уже запущен."""
    global _lock_file
    try:
        import fcntl
    except Exception:
        # Нет fcntl (нереалистично на macOS) — не блокируем запуск.
        return object()
    try:
        os.makedirs(APPDATA_DIR, exist_ok=True)
    except Exception:
        pass
    path = os.path.join(APPDATA_DIR, "dnsmanager.lock")
    try:
        f = open(path, "w")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_file = f  # держим ссылку, чтобы lock не снялся при GC
        return f
    except OSError:
        # Файл уже заблокирован другим процессом → экземпляр уже запущен.
        return None
    except Exception:
        return object()


def acquire_single_instance():
    """Создаёт именованный мьютекс. Возвращает handle или None если уже запущен."""
    if IS_MACOS:
        return _posix_acquire_single_instance()
    global _mutex_handle
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(None, True, APP_MUTEX_NAME)
    last_error = kernel32.GetLastError()
    ERROR_ALREADY_EXISTS = 183
    if last_error == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return None
    _mutex_handle = handle
    return handle


def focus_existing_instance():
    """Пытается найти и показать существующее окно приложения."""
    if IS_MACOS:
        # Активировать уже запущенный экземпляр по имени надёжно нельзя без
        # бандла с известным bundle-id. Лучшее усилие: попросить активировать
        # процесс по имени; при неудаче просто выходим (новый экземпляр и так
        # завершится в main()).
        try:
            import subprocess
            subprocess.run(
                ["osascript", "-e",
                 'tell application "System Events" to set frontmost of '
                 'the first process whose name contains "DNSManager" to true'],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass
        return False

    user32 = ctypes.windll.user32
    EnumWindows = user32.EnumWindows
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
    GetWindowTextW = user32.GetWindowTextW
    GetWindowTextLengthW = user32.GetWindowTextLengthW
    IsWindowVisible = user32.IsWindowVisible
    ShowWindow = user32.ShowWindow
    SetForegroundWindow = user32.SetForegroundWindow

    SW_SHOW = 5
    SW_RESTORE = 9
    found = [False]

    def callback(hwnd, lParam):
        length = GetWindowTextLengthW(hwnd)
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            GetWindowTextW(hwnd, buf, length + 1)
            if APP_NAME in buf.value:
                if not IsWindowVisible(hwnd):
                    ShowWindow(hwnd, SW_SHOW)
                ShowWindow(hwnd, SW_RESTORE)
                SetForegroundWindow(hwnd)
                found[0] = True
                return False
        return True

    EnumWindows(EnumWindowsProc(callback), 0)
    return found[0]
