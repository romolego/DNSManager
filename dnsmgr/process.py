"""Управление процессом: права администратора и single-instance.

Содержит:
  - is_admin / restart_as_admin — проверка и повышение прав через UAC;
  - acquire_single_instance / focus_existing_instance — Win32-мьютекс и
    поиск окна уже запущенной копии.
"""

import ctypes
import os
import sys

from dnsmgr.constants import APP_MUTEX_NAME, APP_NAME


_mutex_handle = None  # Глобальная ссылка на мьютекс для предотвращения GC


def is_admin():
    """Проверяет, запущен ли процесс с правами администратора."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def restart_as_admin():
    """Перезапускает приложение с запросом прав администратора (UAC)."""
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


def acquire_single_instance():
    """Создаёт именованный мьютекс. Возвращает handle или None если уже запущен."""
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
