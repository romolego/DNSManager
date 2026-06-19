"""Управление автозапуском Windows.

Два механизма:
  - HKCU\\...\\Run — обычный автозапуск без прав администратора;
  - Планировщик заданий (LogonTrigger + RunLevel=HighestAvailable) — для
    автозапуска с правами администратора без UAC-промпта при логине.

Также содержит логику очистки устаревших записей автозапуска от предыдущих
версий приложения (cleanup_stale_autostart_entries): каноническая запись
должна указывать на текущий exe, остальные удаляются один раз на каждую
версию (маркер cleanup_done_for_version в settings.json).
"""

import os
import re
import subprocess
import sys

from dnsmgr.constants import (
    APPDATA_DIR,
    AUTOSTART_REG_KEY,
    AUTOSTART_REG_VALUE,
    IS_MACOS,
    NO_WINDOW_FLAG,
    TASK_SCHEDULER_TASK_NAME,
)
from dnsmgr.logger import app_logger


# ── macOS: автозапуск через LaunchAgent ─────────────────────────────────────
#
# На macOS аналог HKCU\Run — пользовательский LaunchAgent: plist в
# ~/Library/LaunchAgents, который launchd запускает при входе пользователя.
# Автозапуск «с правами администратора» (Планировщик заданий Windows) на macOS
# не воспроизводится напрямую и считается второстепенным — соответствующие
# функции на macOS делают no-op.

_MACOS_LAUNCH_AGENT_LABEL = "com.dnsmanager.autostart"


def _macos_launch_agent_path():
    return os.path.join(
        os.path.expanduser("~/Library/LaunchAgents"),
        f"{_MACOS_LAUNCH_AGENT_LABEL}.plist",
    )


def _macos_program_arguments(start_minimized):
    """Аргументы запуска для launchd. Для .app/обычного запуска — текущий бинарь."""
    if getattr(sys, "frozen", False):
        args = [sys.executable]
    else:
        args = [sys.executable, os.path.abspath(sys.argv[0])]
    if start_minimized:
        args.append("--minimized")
    return args


def _macos_get_autostart_enabled():
    return os.path.exists(_macos_launch_agent_path())


def _macos_set_autostart(enabled, start_minimized=False):
    from xml.sax.saxutils import escape as xml_escape
    path = _macos_launch_agent_path()
    try:
        if enabled:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            args_xml = "".join(
                f"      <string>{xml_escape(a)}</string>\n"
                for a in _macos_program_arguments(start_minimized)
            )
            plist = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                '<plist version="1.0">\n'
                '<dict>\n'
                '    <key>Label</key>\n'
                f'    <string>{_MACOS_LAUNCH_AGENT_LABEL}</string>\n'
                '    <key>ProgramArguments</key>\n'
                '    <array>\n'
                f'{args_xml}'
                '    </array>\n'
                '    <key>RunAtLoad</key>\n'
                '    <true/>\n'
                '    <key>ProcessType</key>\n'
                '    <string>Interactive</string>\n'
                '</dict>\n'
                '</plist>\n'
            )
            with open(path, "w", encoding="utf-8") as f:
                f.write(plist)
            try:
                subprocess.run(["launchctl", "load", "-w", path],
                               capture_output=True, timeout=10)
            except Exception:
                pass
            app_logger.info("Автозапуск (LaunchAgent) включён"
                            + (" (свёрнуто)" if start_minimized else ""))
        else:
            if os.path.exists(path):
                try:
                    subprocess.run(["launchctl", "unload", "-w", path],
                                   capture_output=True, timeout=10)
                except Exception:
                    pass
                try:
                    os.remove(path)
                except Exception:
                    pass
            app_logger.info("Автозапуск (LaunchAgent) выключен")
        return True
    except Exception as e:
        app_logger.error(f"Ошибка настройки автозапуска (macOS): {e}")
        return False


# ── Обычный автозапуск через HKCU\Run ───────────────────────────────────────

def get_autostart_enabled():
    """Проверяет, включён ли автозапуск в реестре."""
    if IS_MACOS:
        return _macos_get_autostart_enabled()
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0, winreg.KEY_READ)
        try:
            winreg.QueryValueEx(key, AUTOSTART_REG_VALUE)
            return True
        except FileNotFoundError:
            return False
        finally:
            winreg.CloseKey(key)
    except Exception:
        return False


def set_autostart(enabled, start_minimized=False):
    """Включает или выключает обычный автозапуск через реестр (без прав админа)."""
    if IS_MACOS:
        return _macos_set_autostart(enabled, start_minimized)
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_REG_KEY, 0,
                             winreg.KEY_SET_VALUE | winreg.KEY_READ)
        try:
            if enabled:
                if getattr(sys, 'frozen', False):
                    exe_path = f'"{sys.executable}"'
                else:
                    exe_path = f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}"'
                if start_minimized:
                    exe_path += " --minimized"
                winreg.SetValueEx(key, AUTOSTART_REG_VALUE, 0, winreg.REG_SZ, exe_path)
                app_logger.info("Автозапуск (реестр) включён" + (" (в трей)" if start_minimized else ""))
            else:
                try:
                    winreg.DeleteValue(key, AUTOSTART_REG_VALUE)
                except FileNotFoundError:
                    pass
                app_logger.info("Автозапуск (реестр) выключен")
            return True
        finally:
            winreg.CloseKey(key)
    except Exception as e:
        app_logger.error(f"Ошибка настройки автозапуска: {e}")
        return False


# ── Автозапуск с правами администратора через Планировщик заданий ───────────

def _get_app_exe_path():
    """Возвращает путь к exe или к python + скрипт для schtasks."""
    if getattr(sys, 'frozen', False):
        return sys.executable, ""
    else:
        return sys.executable, os.path.abspath(sys.argv[0])


def get_admin_task_exists():
    """Проверяет, существует ли задача DNSManagerAutostart в Планировщике."""
    if IS_MACOS:
        return False  # «Автозапуск с правами админа» на macOS не используется
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", TASK_SCHEDULER_TASK_NAME, "/FO", "LIST"],
            capture_output=True, timeout=10,
            creationflags=NO_WINDOW_FLAG
        )
        return result.returncode == 0
    except Exception:
        return False


def create_admin_scheduled_task(start_minimized=False):
    """Создаёт задачу в Планировщике заданий Windows для автозапуска с наивысшими правами."""
    if IS_MACOS:
        # Эквивалент админ-задачи на macOS не нужен (DNS повышается per-команда).
        # Включаем обычный LaunchAgent, чтобы галочка «автозапуск» работала.
        return _macos_set_autostart(True, start_minimized)
    exe, script = _get_app_exe_path()

    if script:
        task_command = exe
        task_args = f'"{script}"'
        if start_minimized:
            task_args += " --minimized"
    else:
        task_command = exe
        task_args = "--minimized" if start_minimized else ""

    try:
        # Удаляем старую задачу если есть
        subprocess.run(
            ["schtasks", "/Delete", "/TN", TASK_SCHEDULER_TASK_NAME, "/F"],
            capture_output=True, timeout=10,
            creationflags=NO_WINDOW_FLAG
        )
    except Exception:
        pass

    # Создаём XML для задачи с наивысшими правами
    from xml.sax.saxutils import escape as xml_escape

    username = os.environ.get("USERNAME", "")
    userdomain = os.environ.get("USERDOMAIN", "")
    user_id = f"{userdomain}\\{username}" if userdomain else username

    # Экранирование специальных XML-символов (<, >, &, ", ')
    user_id_safe = xml_escape(user_id, {'"': "&quot;", "'": "&apos;"})
    task_command_safe = xml_escape(task_command, {'"': "&quot;", "'": "&apos;"})
    task_args_safe = xml_escape(task_args, {'"': "&quot;", "'": "&apos;"})

    task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>DNS Manager — автозапуск с правами администратора</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user_id_safe}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user_id_safe}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{task_command_safe}</Command>
      <Arguments>{task_args_safe}</Arguments>
    </Exec>
  </Actions>
</Task>"""

    # Записываем XML во временный файл
    xml_path = os.path.join(APPDATA_DIR, "task_admin.xml")
    try:
        with open(xml_path, "w", encoding="utf-16") as f:
            f.write(task_xml)

        result = subprocess.run(
            ["schtasks", "/Create", "/TN", TASK_SCHEDULER_TASK_NAME, "/XML", xml_path, "/F"],
            capture_output=True, timeout=15,
            creationflags=NO_WINDOW_FLAG
        )

        try:
            os.remove(xml_path)
        except Exception:
            pass

        if result.returncode == 0:
            app_logger.info("Задача Планировщика заданий создана (автозапуск с правами администратора)")
            return True
        else:
            stderr = result.stderr.decode("cp866", errors="replace").strip()
            stdout_msg = result.stdout.decode("cp866", errors="replace").strip()
            app_logger.error(f"Ошибка создания задачи Планировщика: {stderr or stdout_msg}")
            return False

    except Exception as e:
        app_logger.error(f"Ошибка создания задачи Планировщика: {e}")
        try:
            os.remove(xml_path)
        except Exception:
            pass
        return False


def delete_admin_scheduled_task():
    """Удаляет задачу автозапуска из Планировщика заданий."""
    if IS_MACOS:
        return True  # На macOS админ-задачи нет — удалять нечего
    try:
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", TASK_SCHEDULER_TASK_NAME, "/F"],
            capture_output=True, timeout=10,
            creationflags=NO_WINDOW_FLAG
        )
        if result.returncode == 0:
            app_logger.info("Задача Планировщика заданий удалена")
            return True
        else:
            app_logger.warn("Задача Планировщика не найдена для удаления")
            return True  # Не считаем ошибкой — задачи и так нет
    except Exception as e:
        app_logger.error(f"Ошибка удаления задачи Планировщика: {e}")
        return False


# ── Очистка устаревших записей автозапуска от предыдущих версий ─────────────
#
# Источник истины — путь к ТЕКУЩЕМУ запущенному exe (get_current_app_exe()).
# Запись автозапуска в HKCU\Run и именованная задача Планировщика,
# указывающие на другой путь, считаются устаревшими и удаляются при первом
# запуске новой версии (см. main() и маркер cleanup_done_for_version).

def get_current_app_exe():
    """Возвращает абсолютный путь к exe/скрипту текущего процесса."""
    if getattr(sys, 'frozen', False):
        return os.path.abspath(sys.executable)
    return os.path.abspath(sys.argv[0])


def _norm_path(p):
    """Нормализует путь для сравнения (регистр/слэши/абс.)."""
    if not p:
        return ""
    try:
        return os.path.normcase(os.path.normpath(os.path.abspath(p)))
    except Exception:
        return (p or "").lower()


def _extract_exe_from_command(cmd):
    """Вытаскивает путь к exe из командной строки (reg-значение или TaskToRun)."""
    if not cmd or not isinstance(cmd, str):
        return ""
    s = cmd.strip()
    if not s:
        return ""
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 0:
            return s[1:end]
        return s.strip('"')
    sp = s.find(" ")
    return s[:sp] if sp > 0 else s


def _is_our_app_exe(path):
    """True, если путь похож на exe/скрипт нашего приложения."""
    if not path:
        return False
    name = os.path.basename(path).lower()
    # Учитываем исторические варианты имён: DNSManager.exe, dns_manager.py,
    # "DNS Manager.exe" и т. п.
    return (
        "dnsmanager" in name.replace(" ", "").replace("_", "")
    )


def _cleanup_registry_run_keys(current_norm):
    """Удаляет в HKCU\\Run все значения, указывающие на наше приложение,
    но не на текущий exe."""
    import winreg
    # Приложение пишет автозапуск только в HKCU\Run (см. set_autostart),
    # поэтому и зачищать достаточно только здесь. Просмотр других веток
    # реестра не нужен и выглядит для AV как rootkit-cleaner.
    run_locations = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]
    removed = 0
    for hive, subkey in run_locations:
        try:
            key = winreg.OpenKey(hive, subkey, 0,
                                 winreg.KEY_READ | winreg.KEY_SET_VALUE)
        except OSError:
            continue
        try:
            stale = []
            i = 0
            while True:
                try:
                    name, value, _type = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                exe = _extract_exe_from_command(
                    value if isinstance(value, str) else ""
                )
                if not exe:
                    # Попробуем также сравнить по имени значения
                    if name and name.lower().replace(" ", "") in (
                        "dnsmanager", "dnsmanagerautostart"
                    ):
                        stale.append(name)
                    continue
                if not _is_our_app_exe(exe):
                    continue
                if _norm_path(exe) == current_norm:
                    # актуальная запись — оставляем
                    continue
                stale.append(name)
            for name in stale:
                try:
                    winreg.DeleteValue(key, name)
                    removed += 1
                    app_logger.info(
                        f"Удалена устаревшая запись автозапуска: {subkey}\\{name}"
                    )
                except OSError as e:
                    app_logger.warn(
                        f"Не удалось удалить {subkey}\\{name}: {e}"
                    )
        finally:
            winreg.CloseKey(key)
    return removed


def _cleanup_scheduled_tasks(current_norm):
    """Удаляет именованную задачу автозапуска DNSManagerAutostart, если она
    указывает не на текущий exe.

    Раньше функция перебирала все задачи Планировщика и эвристически
    удаляла «наши» по подстроке в имени или TaskToRun. Этот шаблон (массовый
    перебор + удаление чужих задач) даёт сильное AV-срабатывание. Приложение
    само создаёт ровно одну задачу с фиксированным именем — её и достаточно
    проверить.
    """
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", TASK_SCHEDULER_TASK_NAME, "/XML"],
            capture_output=True, timeout=10,
            creationflags=NO_WINDOW_FLAG,
        )
    except Exception:
        return 0

    if result.returncode != 0:
        # Задачи нет — нечего чистить
        return 0

    try:
        xml = result.stdout.decode("utf-16", errors="replace")
    except Exception:
        xml = result.stdout.decode("utf-8", errors="replace")

    m = re.search(r"<Command>([^<]+)</Command>", xml)
    if not m:
        return 0

    task_exe = m.group(1).strip()
    if _norm_path(task_exe) == current_norm:
        # Актуальная — оставляем
        return 0

    try:
        del_res = subprocess.run(
            ["schtasks", "/Delete", "/TN", TASK_SCHEDULER_TASK_NAME, "/F"],
            capture_output=True, timeout=10,
            creationflags=NO_WINDOW_FLAG,
        )
        if del_res.returncode == 0:
            app_logger.info(
                f"Удалена устаревшая задача Планировщика: {TASK_SCHEDULER_TASK_NAME}"
            )
            return 1
    except Exception as e:
        app_logger.warn(f"Ошибка удаления задачи {TASK_SCHEDULER_TASK_NAME}: {e}")
    return 0


def cleanup_stale_autostart_entries():
    """Удаляет автозапуски/задачи, указывающие на старые версии DNS Manager.
    Оставляет только записи, указывающие на текущий exe.

    Поскольку приложение никогда не создаёт ярлыки в Startup-папках, ветка
    очистки ярлыков убрана — она лишь увеличивала AV-сигнатуру без пользы.
    """
    if IS_MACOS:
        return 0  # Чистить реестр/Планировщик на macOS нечего
    current_exe = get_current_app_exe()
    current_norm = _norm_path(current_exe)
    try:
        r1 = _cleanup_registry_run_keys(current_norm)
    except Exception as e:
        r1 = 0
        app_logger.warn(f"Очистка реестра Run не выполнена: {e}")
    try:
        r2 = _cleanup_scheduled_tasks(current_norm)
    except Exception as e:
        r2 = 0
        app_logger.warn(f"Очистка Планировщика не выполнена: {e}")
    total = r1 + r2
    if total:
        app_logger.info(
            f"Очистка устаревших записей автозапуска: удалено {total} шт."
        )
    return total


def refresh_current_autostart_entries(settings):
    """После очистки переустанавливает канонические записи автозапуска так,
    чтобы они указывали на текущий exe. Использует уже существующую логику
    set_autostart / create_admin_scheduled_task."""
    if IS_MACOS:
        # На macOS не трогаем автозапуск автоматически при старте: иначе при
        # первом запуске приложение само прописало бы себя в Login Items
        # (defaults autostart=True). Пусть пользователь включает это явно
        # галочкой в настройках.
        return
    try:
        want_autostart = bool(settings.get("autostart", False))
        want_admin = bool(settings.get("autostart_admin", False))
        start_minimized = bool(settings.get("start_minimized", False))

        if want_autostart and want_admin:
            # Админ-задача: реестр-запись не нужна, пересоздаём задачу
            set_autostart(False)
            create_admin_scheduled_task(start_minimized)
        elif want_autostart:
            # Только реестр: перезапишем актуальным путём
            set_autostart(True, start_minimized)
            delete_admin_scheduled_task()
        else:
            # Автозапуск отключён — убедимся, что ничего не осталось
            set_autostart(False)
            delete_admin_scheduled_task()
    except Exception as e:
        app_logger.warn(f"Не удалось обновить запись автозапуска: {e}")
