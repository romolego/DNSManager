"""Фоновый мониторинг здоровья DNS и событийная подписка на смену сети.

Содержит:
  - NetworkChangeWatcher — подписка на Win32 NotifyAddrChange;
  - HealthMonitor — периодическая проверка и автовосстановление DNS.

Оба класса хранят ссылку на DNSManagerApp и через неё дёргают UI и
сетевые операции. Обратной зависимости (app → monitor) нет, кроме
конструктора.
"""

import ctypes
import threading
import time

from dnsmgr.constants import (
    FAILURE_THRESHOLD,
    GEOHIDE_FALLBACK_IPS,
    HEALTH_CHECK_INTERVAL,
    INTERNET_WAIT_INTERVAL,
    INTERNET_WAIT_TIMEOUT,
    MAX_RECOVERY_ATTEMPTS,
    NETWORK_NO_CONNECTION,
    NETWORK_READY,
    NETWORK_UNSTABLE,
    RESUME_ADAPTER_RETRY_DELAYS,
    RESUME_TIME_JUMP_FACTOR,
    GEOHIDE_DOMAIN,
)
from dnsmgr.config import save_settings
from dnsmgr.geohide import resolve_geohide
from dnsmgr.logger import app_logger
from dnsmgr.network import (
    check_network_ready,
    detect_dns_mode,
    flush_dns_cache,
    get_active_internet_adapter,
    get_current_dns,
    get_network_adapters,
    select_best_adapter,
    verify_dns_working,
    _verify_real_internet,
)
from dnsmgr.process import is_admin


# ═══════════════════════════════════════════════════════════════════════════════
# СОБЫТИЙНАЯ ПОДПИСКА НА СМЕНУ СЕТИ (Win32 NotifyAddrChange)
# ═══════════════════════════════════════════════════════════════════════════════

class NetworkChangeWatcher:
    """Подписка на Win32 `NotifyAddrChange` (iphlpapi.dll).

    Фоновый поток блокируется внутри `NotifyAddrChange`, пока в системе не
    произойдёт изменение IP-таблицы (подключение/отключение адаптера, смена
    адреса/маршрута). После каждого события поток дебаунсит вызов и просит
    приложение перечитать сетевое состояние.

    Цель — не ждать следующего тика мониторинга (до 15 секунд), а реагировать
    на смену сети практически сразу. Поток помечен daemon, на выходе
    приложения он умирает вместе с процессом — корректно отменить
    синхронный `NotifyAddrChange` нельзя без overlapped-инфраструктуры,
    которая для нашей задачи избыточна.

    Ошибки/недоступность iphlpapi не считаются фатальными: ватчер просто
    не запустится, основное приложение продолжит работать на поллинге.
    """

    def __init__(self, on_change):
        self._on_change = on_change
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is not None:
            return
        try:
            ctypes.windll.iphlpapi.NotifyAddrChange  # проверка доступности
        except Exception:
            try:
                app_logger.warn("iphlpapi.NotifyAddrChange недоступен, событийная подписка на сеть отключена")
            except Exception:
                pass
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        try:
            app_logger.info("Событийная подписка на изменения сети активна")
        except Exception:
            pass

    def stop(self):
        # Полная отмена синхронного NotifyAddrChange невозможна без overlapped.
        # На практике потока в любом случае daemon, и он погибнет с процессом.
        self._stop_event.set()

    def _run(self):
        try:
            iphlpapi = ctypes.windll.iphlpapi
        except Exception:
            return
        # Лимит на количество ложных подряд ошибок — чтобы не уйти в busy-loop
        # при гипотетическом сломанном API.
        consecutive_errors = 0
        while not self._stop_event.is_set():
            try:
                rc = iphlpapi.NotifyAddrChange(None, None)
            except Exception:
                consecutive_errors += 1
                if consecutive_errors > 5:
                    return
                self._stop_event.wait(2)
                continue
            if self._stop_event.is_set():
                return
            if rc != 0:  # NO_ERROR == 0
                consecutive_errors += 1
                if consecutive_errors > 5:
                    return
                self._stop_event.wait(1)
                continue
            consecutive_errors = 0
            try:
                self._on_change()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# МОНИТОРИНГ ЗДОРОВЬЯ DNS
# ═══════════════════════════════════════════════════════════════════════════════

class HealthMonitor:
    """Фоновый мониторинг DNS для выбранного DNS-профиля (целевого режима).

    Источник истины для мониторинга и автовосстановления — `desired_mode`.
    Мониторинг запускается, когда выбран любой целевой режим DNS (включая DHCP),
    и при сбое пытается восстановить именно последний выбранный режим.
    """

    def __init__(self, app):
        self.app = app
        self._running = False
        self._thread = None
        self._stop_event = threading.Event()
        self.consecutive_failures = 0
        self.recovery_attempts = 0
        self._lock = threading.Lock()
        self._network_waiting = False
        self._last_net_state = None
        self._consecutive_net_failures = 0  # Счётчик последовательных проблем сети
        self._NET_FAILURE_THRESHOLD = 2     # Сколько проверок подряд до объявления проблемы
        self._resume_detected = False       # Флаг: обнаружен выход из сна
        # Счётчик последовательных «пустых» DNS-чтений с привязанного адаптера
        # (servers=[] и не is_dhcp). Один пустой чтение часто бывает транзиентным
        # (DHCP renewal, момент переключения сети) — нельзя по нему сразу
        # объявлять «внешнее изменение DNS».
        self._consecutive_empty_dns_reads = 0
        self._EMPTY_DNS_READ_THRESHOLD = 2
        # Флаг: после выхода из сна Windows мог откатить статический DNS на DHCP,
        # и нужно тихо переставить целевой профиль обратно — но только когда сеть
        # реально поднимется (шлюз). Держится между тиками, пока переустановка не
        # удастся или не станет ненужной. См. _reapply_desired_after_resume.
        self._reapply_pending = False

    def start(self):
        with self._lock:
            if self._running:
                return
            self._stop_event.clear()
            self._running = True
            self._network_waiting = False
            self._last_net_state = None
            self._reapply_pending = False
            self._thread = threading.Thread(target=self._check_loop, daemon=True)
            self._thread.start()
            app_logger.info("Мониторинг DNS запущен")
        try:
            self.app.after(100, self.app._update_monitor_label)
        except Exception:
            pass

    def stop(self):
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stop_event.set()
            self._network_waiting = False
            app_logger.info("Мониторинг DNS остановлен")
        try:
            self.app.after(100, self.app._update_monitor_label)
        except Exception:
            pass

    def reset_attempts(self):
        with self._lock:
            had_state = bool(
                self.recovery_attempts or self.consecutive_failures
                or self._network_waiting or self._consecutive_net_failures
                or self._consecutive_empty_dns_reads
                or self._resume_detected
            )
            self.recovery_attempts = 0
            self.consecutive_failures = 0
            self._network_waiting = False
            self._last_net_state = None
            self._consecutive_net_failures = 0
            self._consecutive_empty_dns_reads = 0
            self._resume_detected = False
        if had_state:
            app_logger.info("Счётчик попыток восстановления сброшен")

    def is_running(self):
        return self._running

    def _try_rediscover_adapter(self):
        """Пробует заново найти сетевой адаптер, если current_adapter == None."""
        try:
            adapters = get_network_adapters()
            if not adapters:
                return
            saved = self.app.settings.get("selected_adapter")
            adapter_names = [a["name"] for a in adapters]
            if saved and saved in adapter_names:
                new_adapter = saved
            else:
                new_adapter = select_best_adapter(adapters)
            if new_adapter:
                self.app.adapters = adapters
                self.app.current_adapter = new_adapter
                app_logger.info(f"Адаптер обнаружен автоматически: {new_adapter}")
                self.app.after(0, self.app._populate_adapters)
                self.app.after(0, self.app._refresh_state_safe)
        except Exception:
            pass

    def _handle_resume(self):
        """Обработка выхода из сна: ожидание адаптера и переинициализация состояния."""
        self._resume_detected = False
        self._consecutive_net_failures = 0
        self._last_net_state = None

        saved = self.app.settings.get("selected_adapter")
        target = saved or self.app.current_adapter

        app_logger.info("Переинициализация после выхода из сна...")
        self.app.after(0, lambda: self.app._set_operation_step(
            "Выход из сна: ожидание сетевого адаптера..."
        ))

        # Ожидание адаптера с ретраями (аналог _action_initial)
        found_adapter = None
        for attempt_i, delay in enumerate(RESUME_ADAPTER_RETRY_DELAYS):
            if self._stop_event.is_set():
                return False
            if delay > 0:
                self._stop_event.wait(delay)
                if self._stop_event.is_set():
                    return False

            adapters = get_network_adapters()
            adapter_names = [a["name"] for a in adapters]

            if target and target in adapter_names:
                found_adapter = target
                self.app.adapters = adapters
                self.app.current_adapter = found_adapter
                break
            elif adapter_names:
                # Целевой адаптер не найден, но есть другие
                if target and attempt_i < len(RESUME_ADAPTER_RETRY_DELAYS) - 1:
                    continue  # подождём ещё — адаптер может инициализироваться позже
                best = select_best_adapter(adapters)
                if best:
                    found_adapter = best
                    self.app.adapters = adapters
                    self.app.current_adapter = found_adapter
                    break

        if found_adapter:
            app_logger.info(f"Адаптер после выхода из сна: {found_adapter}")
            self.app.after(0, self.app._populate_adapters)
            self.app.after(0, self.app._refresh_state_safe)
            self.app.after(0, lambda: self.app._clear_operation_delayed(3))
            return True
        else:
            app_logger.warn("Адаптер не найден после выхода из сна, ожидание продолжается")
            self.app.current_adapter = None
            self.app.after(0, self.app._refresh_state_safe)
            return False

    def _is_adapter_available(self):
        """Проверяет, что current_adapter есть в текущем списке активных адаптеров."""
        if not self.app.current_adapter:
            return False
        try:
            adapters = get_network_adapters()
            adapter_names = [a["name"] for a in adapters]
            if self.app.current_adapter in adapter_names:
                self.app.adapters = adapters
                return True
            return False
        except Exception:
            return False

    def _apply_desired_with_retries(self, target, attempts=3):
        """Применяет целевой DNS-профиль с несколькими попытками и проверкой,
        что он реально «прижился» (фактический режим стал целевым).

        Нужно, потому что сразу после выхода из сна адаптер бывает в переходном
        состоянии: netsh формально отрабатывает, но статический DNS не
        закрепляется. Возвращает True при подтверждённом успехе.
        """
        primary = target.get("primary")
        secondary = target.get("secondary")
        if target.get("type") == "geohide":
            ips, used_fallback = resolve_geohide()
            if not used_fallback:
                self.app.geohide_known_ips = list(ips)
                self.app.settings["geohide_resolved_ips"] = self.app.geohide_known_ips
                save_settings(self.app.settings)
            primary = ips[0] if ips else GEOHIDE_FALLBACK_IPS[0]
            secondary = ips[1] if len(ips) > 1 else (
                GEOHIDE_FALLBACK_IPS[1] if len(GEOHIDE_FALLBACK_IPS) > 1 else None
            )
        if not primary:
            return False

        for _i in range(attempts):
            if self._stop_event.is_set():
                return False
            res = self.app._apply_dns_set(primary, secondary)
            if res.get("success"):
                flush_dns_cache()
                self._stop_event.wait(1)  # дать DNS «осесть» перед контрольным чтением
                dns_info = get_current_dns(self.app.current_adapter)
                actual_pid, _ = detect_dns_mode(
                    dns_info["servers"], self.app.geohide_known_ips,
                    dns_info.get("is_dhcp", False), dns_profiles=self.app._dns_profiles
                )
                if actual_pid == self.app.desired_mode:
                    return True
            # не прижилось — короткая пауза и повтор
            self._stop_event.wait(2)
        return False

    def _reapply_desired_after_resume(self):
        """Тихо возвращает целевой DNS после выхода из сна.

        Возвращает True, если переустановка больше не нужна (готово или
        неприменимо) — тогда вызывающая сторона снимет _reapply_pending; и
        False, если стоит повторить на следующем тике (сеть ещё не готова,
        операция занята или применение не прижилось).

        Ключевое отличие от обычной ветки «расхождение режима»: здесь сброс DNS
        трактуется как СОБСТВЕННАЯ задача (ОС откатила после сна), а не как
        внешнее изменение — поэтому никакого диалога и остановки мониторинга.
        """
        if not self.app._has_selected_dns_mode() or self.app.desired_mode == "standard":
            return True
        if not is_admin():
            return True  # без прав переставить не сможем, не зацикливаемся
        if not self.app.current_adapter:
            return True

        # Сеть ещё не поднялась (нет шлюза после сна) — ждём, повторим позже.
        net = check_network_ready(self.app.current_adapter)
        if net["state"] != NETWORK_READY:
            if not self._network_waiting:
                self._network_waiting = True
                self.app.after(0, self.app._update_monitor_label)
            return False

        if self._network_waiting:
            self._network_waiting = False
            self.app.after(0, self.app._update_monitor_label)

        # Уже в целевом режиме (ОС ничего не откатила) — делать нечего.
        dns_info = get_current_dns(self.app.current_adapter)
        actual_pid, _ = detect_dns_mode(
            dns_info["servers"], self.app.geohide_known_ips,
            dns_info.get("is_dhcp", False), dns_profiles=self.app._dns_profiles
        )
        if actual_pid == self.app.desired_mode:
            return True

        target = self.app._get_desired_profile()
        if target is None:
            return True

        # Атомарно берём операцию: если что-то выполняется (например, ручное
        # действие пользователя) — не вмешиваемся, повторим на следующем тике.
        if not self.app._try_begin_operation():
            return False

        try:
            self.app.after(0, lambda: self.app._set_buttons_state(False))
            self.app.after(0, lambda: self.app._set_operation_step(
                f"После сна: восстановление выбранного DNS ({target['name']})..."
            ))
            if self._apply_desired_with_retries(target):
                app_logger.info(
                    f"После выхода из сна восстановлен выбранный DNS: {target['name']}"
                )
                self.app.after(0, lambda: self.app._set_operation_step(
                    f"После сна восстановлен {target['name']}", is_success=True
                ))
                self.app.after(0, lambda: self.app._clear_operation_delayed(4))
                return True
            app_logger.warn(
                "После сна не удалось переставить выбранный DNS — повтор на следующем тике"
            )
            return False
        finally:
            self.app._end_operation()
            self.app.after(0, lambda: self.app._set_buttons_state(True))
            self.app.after(0, self.app._refresh_state_safe)

    def _try_return_to_manual_adapter(self):
        """Если у пользователя был явный выбор адаптера (manual_adapter), и сейчас
        мониторинг работает на другом (после авто-перепривязки), а явный выбор
        снова доступен и здоров — возвращаемся к нему.

        Возвращает True, если возврат состоялся.

        Это пара к `_try_rebind_to_active_adapter`: первая уводит с мёртвого
        выбора пользователя на работающий адаптер, эта возвращает обратно,
        как только пользовательский выбор снова стал рабочим. Вместе они
        дают поведение «уважаем явный выбор, пока он работает; не залипаем,
        когда он не работает».
        """
        manual = self.app.settings.get("manual_adapter")
        if not manual:
            return False
        if manual == self.app.current_adapter:
            return False
        try:
            adapters = get_network_adapters()
        except Exception:
            return False
        if manual not in [a["name"] for a in adapters]:
            return False
        net = check_network_ready(manual)
        if net["state"] != NETWORK_READY:
            return False

        old = self.app.current_adapter
        self.app.adapters = adapters
        self.app.current_adapter = manual
        self.app.settings["selected_adapter"] = manual
        save_settings(self.app.settings)
        with self._lock:
            self.consecutive_failures = 0
            self._consecutive_net_failures = 0
            self._consecutive_empty_dns_reads = 0
            self._network_waiting = False
            self._last_net_state = None
        app_logger.info(
            f"Возврат к выбранному пользователем адаптеру: '{old}' → '{manual}' (стал доступен)"
        )
        try:
            self.app.after(0, self.app._populate_adapters)
            self.app.after(0, self.app._refresh_state_safe)
        except Exception:
            pass
        if self.app._has_selected_dns_mode() and is_admin():
            try:
                self.app.after(
                    0,
                    lambda: self.app._run_action(self.app._action_restore_selected_dns)
                )
            except Exception:
                pass
        return True

    def _try_rebind_to_active_adapter(self):
        """Если интернет в системе есть, но привязанный адаптер его не обслуживает —
        перепривязывает мониторинг к адаптеру с активным default-маршрутом и
        запускает переприменение выбранного DNS на новом адаптере.

        Возвращает True, если перепривязка состоялась.

        Условие срабатывания: `_verify_real_internet` (TCP + NCSI HTTP-проба,
        ловит captive portal) возвращает True И `get_active_internet_adapter`
        находит подходящий адаптер, отличный от текущего. Это страхует от
        двух типов ложных перепривязок:
          - ни один адаптер не работает → внутренний TCP-чек упадёт, выходим;
          - сеть есть на L4, но это captive portal без реального интернета →
            NCSI-проба отловит подмену тела, выходим.
        """
        if not _verify_real_internet():
            return False
        try:
            adapters = get_network_adapters()
        except Exception:
            return False
        if not adapters:
            return False
        active = get_active_internet_adapter(adapters)
        if not active or active == self.app.current_adapter:
            return False

        old = self.app.current_adapter
        self.app.adapters = adapters
        self.app.current_adapter = active
        self.app.settings["selected_adapter"] = active
        save_settings(self.app.settings)
        with self._lock:
            self.consecutive_failures = 0
            self._consecutive_net_failures = 0
            self._network_waiting = False
            self._last_net_state = None
        app_logger.warn(
            f"Перепривязка с '{old}' на '{active}' (default route, интернет доступен)"
        )
        try:
            self.app.after(0, self.app._populate_adapters)
            self.app.after(0, self.app._refresh_state_safe)
        except Exception:
            pass
        # Если выбран DNS-режим — переприменить его к новому адаптеру.
        # Без этого DNS на новом адаптере может отличаться от desired_mode и
        # на следующем цикле монитор посчитает это «внешним изменением DNS».
        if self.app._has_selected_dns_mode() and is_admin():
            try:
                self.app.after(
                    0,
                    lambda: self.app._run_action(self.app._action_restore_selected_dns)
                )
            except Exception:
                pass
        return True

    def _check_loop(self):
        # Счётчик подряд идущих НЕОЖИДАННЫХ ошибок в _do_health_check.
        # Сбрасывается после каждого успешного тика. Защищает от двух бед:
        #   1) одна случайная ошибка (например, after() на закрывающемся окне)
        #      не должна навсегда убивать поток мониторинга — иначе UI будет
        #      врать «Мониторинг: работает», а автовосстановление DNS молча
        #      перестанет работать;
        #   2) если же ошибка устойчивая (каждый тик), не зацикливаемся в
        #      бесконечном спаме лога — после порога корректно гасим монитор.
        consecutive_errors = 0
        MAX_CONSECUTIVE_ERRORS = 5
        while not self._stop_event.is_set():
            interval = self.app.settings.get("health_check_interval", HEALTH_CHECK_INTERVAL)
            t_before = time.monotonic()
            self._stop_event.wait(interval)
            if self._stop_event.is_set():
                break
            elapsed = time.monotonic() - t_before
            if elapsed > interval * RESUME_TIME_JUMP_FACTOR:
                self._resume_detected = True
                app_logger.info(
                    f"Обнаружен выход из сна (ожидание {interval}с заняло {elapsed:.0f}с)"
                )
            try:
                self._do_health_check()
                consecutive_errors = 0
            except Exception as e:
                consecutive_errors += 1
                try:
                    app_logger.error(
                        f"Ошибка в цикле мониторинга DNS "
                        f"({consecutive_errors}/{MAX_CONSECUTIVE_ERRORS}): {e}"
                    )
                except Exception:
                    pass
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    # Устойчивый сбой — гасим монитор корректно, чтобы UI
                    # показал реальное состояние, а не врал «работает».
                    try:
                        app_logger.error(
                            "Мониторинг DNS остановлен из-за повторяющихся ошибок. "
                            "Примените выбранный DNS заново вручную, чтобы перезапустить мониторинг."
                        )
                    except Exception:
                        pass
                    self._running = False
                    self._stop_event.set()
                    try:
                        self.app.after(0, self.app._update_monitor_label)
                    except Exception:
                        pass
                    break

    def _do_health_check(self):
        # Обработка выхода из сна: переинициализация адаптера с ретраями
        if self._resume_detected:
            if not self._handle_resume():
                return  # адаптер не найден, ждём следующего цикла
            # Адаптер найден. Windows при пробуждении часто сбрасывает статический
            # DNS на DHCP — ставим задачу переустановить целевой профиль, как
            # только сеть поднимется. Сам тик завершаем: первая попытка пойдёт
            # ниже через _reapply_pending.
            if (self.app._has_selected_dns_mode()
                    and self.app.desired_mode != "standard"):
                self._reapply_pending = True

        # Если адаптер не задан — пробуем найти его заново (после загрузки Windows)
        if not self.app.current_adapter:
            self._try_rediscover_adapter()
            if not self.app.current_adapter:
                return
        if self.app.operation_in_progress:
            return
        if self.app._external_change_pending:
            return

        # Отложенная переустановка целевого DNS после выхода из сна.
        # Выполняется ДО проверки расхождения режима, чтобы временное состояние
        # «ОС откатила DNS на DHCP» не было ошибочно принято за внешнее изменение
        # (которое показало бы диалог / остановило мониторинг). Метод сам ждёт
        # готовности сети и повторяет применение, пока не приживётся.
        if self._reapply_pending:
            if self._reapply_desired_after_resume():
                self._reapply_pending = False
            return

        # Если предыдущая авто-перепривязка увела нас с manual_adapter, и сейчас
        # пользовательский выбор снова здоров — возвращаемся к нему.
        if self._try_return_to_manual_adapter():
            return

        # Проверяем, что фактический режим совпадает с выбранным целевым DNS-профилем
        dns_info = get_current_dns(self.app.current_adapter)
        actual_profile_id, actual_mode_name = detect_dns_mode(
            dns_info["servers"], self.app.geohide_known_ips,
            dns_info.get("is_dhcp", False), dns_profiles=self.app._dns_profiles
        )
        if actual_profile_id != self.app.desired_mode:
            if self.app._has_selected_dns_mode():
                # Перед объявлением внешнего изменения — убедиться что адаптер реально доступен.
                # Если адаптер временно недоступен (например, после resume), пустой DNS ≠ внешнее изменение.
                if not dns_info["servers"] and not dns_info.get("is_dhcp"):
                    if not self._is_adapter_available():
                        app_logger.warn(
                            "Адаптер временно недоступен, пропуск проверки DNS"
                        )
                        self.app.current_adapter = None
                        self._consecutive_empty_dns_reads = 0
                        return
                    # Адаптер технически в списке Up, но DNS-чтение пустое.
                    # Это бывает в момент DHCP renewal / переключения Wi-Fi.
                    # Не объявляем «внешнее изменение» по одному такому чтению —
                    # ждём подряд EMPTY_DNS_READ_THRESHOLD неудач.
                    self._consecutive_empty_dns_reads += 1
                    if self._consecutive_empty_dns_reads < self._EMPTY_DNS_READ_THRESHOLD:
                        return
                    # Достигли порога — попробуем перепривязаться к активному
                    # default-маршруту (вероятно, сеть переехала на другой
                    # адаптер). Если получилось — выходим, новая попытка
                    # на следующем тике.
                    if self._try_rebind_to_active_adapter():
                        self._consecutive_empty_dns_reads = 0
                        return
                    # Перепривязка не помогла — пусть существующая логика ниже
                    # отработает как «внешнее изменение DNS».
                else:
                    # DNS-чтение непустое — сбрасываем счётчик пустых чтений.
                    self._consecutive_empty_dns_reads = 0

                # Проверяем: сброс DNS выполнен самим приложением (recovery) или внешний?
                if self.app._self_reset_pending:
                    app_logger.warn(
                        f"DNS сброшен приложением при восстановлении (фактический режим: {actual_mode_name}). "
                        f"Это не внешнее изменение — мониторинг остановлен."
                    )
                    self.app._self_reset_pending = False
                    self._running = False
                    self._stop_event.set()
                    self.app.after(0, self.app._update_monitor_label)
                    self.app.after(0, self.app._refresh_state_safe)
                else:
                    # Реальное внешнее изменение DNS
                    app_logger.warn(f"DNS изменён вне приложения. Фактический режим: {actual_mode_name}")
                    ext_mode = self.app.settings.get("external_dns_change_mode", "notify")
                    if ext_mode == "auto_restore":
                        # Автоматический возврат выбранного DNS без диалога
                        app_logger.info("Автоматический возврат выбранного DNS (режим: auto_restore)")
                        self._running = False
                        self._stop_event.set()
                        self.app.after(0, self.app._update_monitor_label)
                        self.app.after(0, self.app._refresh_state_safe)
                        self.app.after(500, lambda: self.app._run_action(self.app._action_restore_selected_dns))
                    else:
                        # Уведомление пользователя
                        self.app._external_change_pending = True
                        self._running = False
                        self._stop_event.set()
                        self.app.after(0, self.app._update_monitor_label)
                        self.app.after(0, self.app._refresh_state_safe)
                        self.app.after(500, self.app._show_external_dns_change_dialog)
            return

        # DNS соответствует желаемому — сбрасываем счётчик пустых чтений.
        # (Случай, когда ветка mismatch не входила вовсе.)
        self._consecutive_empty_dns_reads = 0

        # --- Предварительная проверка сетевого подключения ---
        net = check_network_ready(self.app.current_adapter)

        if net["state"] != NETWORK_READY:
            # Сеть не готова — используем счётчик последовательных неудач,
            # чтобы не спамить ложными предупреждениями при единичных сбоях.
            self._consecutive_net_failures += 1

            if self._consecutive_net_failures < self._NET_FAILURE_THRESHOLD:
                # Ещё не порог — молча ждём следующей проверки
                return

            # Порог достигнут. До объявления «нет сети» — попробовать перепривязку
            # к активному default-маршруту: интернет может быть на другом адаптере.
            if self._try_rebind_to_active_adapter():
                return

            # Перепривязка не помогла — логируем (но только при смене состояния)
            if self._last_net_state != net["state"]:
                reason = net.get("reason", "unknown")
                if net["state"] == NETWORK_NO_CONNECTION:
                    if reason == "no_ip":
                        app_logger.warn("Сеть не готова: адаптер не получил IP-адрес")
                    elif reason == "no_gateway":
                        app_logger.warn("Сеть не готова: нет шлюза по умолчанию")
                    else:
                        app_logger.warn("Адаптер не подключён к сети")
                elif net["state"] == NETWORK_UNSTABLE:
                    app_logger.warn(f"Сеть нестабильна: шлюз {net.get('gateway', '?')} недоступен")
                self._last_net_state = net["state"]

            if not self._network_waiting:
                self._network_waiting = True
                self.app.after(0, self.app._update_monitor_label)
            return

        # Сеть готова — сбрасываем счётчик сетевых неудач
        self._consecutive_net_failures = 0

        if self._network_waiting:
            self._network_waiting = False
            app_logger.info(f"Сеть появилась (IP: {net.get('ip', '?')}, шлюз: {net.get('gateway', '?')}), возобновление проверки DNS")
            self.app.after(0, self.app._update_monitor_label)
        self._last_net_state = NETWORK_READY

        result = verify_dns_working()
        if result["working"]:
            with self._lock:
                self.consecutive_failures = 0
            return

        with self._lock:
            self.consecutive_failures += 1
            failures = self.consecutive_failures

        threshold = self.app.settings.get("failure_threshold", FAILURE_THRESHOLD)
        if failures < threshold:
            app_logger.warn(f"DNS-проверка неудачна ({failures}/{threshold})")
            return

        app_logger.warn(f"DNS не отвечает {failures} раз подряд. Запуск восстановления.")
        self._on_dns_failure()

    def _on_dns_failure(self):
        with self._lock:
            self.consecutive_failures = 0
            if self.recovery_attempts >= MAX_RECOVERY_ATTEMPTS:
                app_logger.error(
                    f"Лимит попыток восстановления исчерпан ({self.recovery_attempts}/{MAX_RECOVERY_ATTEMPTS}). "
                    f"Автоматика остановлена. Запустите выбранный DNS вручную через кнопки управления."
                )
                self.app.after(0, lambda: self.app._set_operation_step(
                    f"Лимит автовосстановления исчерпан ({MAX_RECOVERY_ATTEMPTS}/{MAX_RECOVERY_ATTEMPTS})",
                    is_error=True
                ))
                self._running = False
                self._stop_event.set()
                self.app.after(100, self.app._update_monitor_label)
                return
            self.recovery_attempts += 1
            attempt = self.recovery_attempts

        app_logger.info(f"Автовосстановление: попытка {attempt}/{MAX_RECOVERY_ATTEMPTS}")
        self._do_recovery(attempt)

    def _do_recovery(self, attempt):
        recovery_mode = self.app.settings.get("selected_dns_recovery_mode", "reset_and_restore")

        if not is_admin():
            app_logger.error("Автовосстановление невозможно: нет прав администратора")
            self.app.after(0, lambda: self.app._set_operation_step(
                "Автовосстановление невозможно: нет прав администратора",
                is_error=True
            ))
            self.app.after(0, self.app._show_window)
            try:
                self.app.tray_icon.notify(
                    "DNS Manager",
                    "Требуются права администратора для восстановления DNS"
                )
            except Exception:
                pass
            self._running = False
            self._stop_event.set()
            self.app.after(100, self.app._update_monitor_label)
            return

        # Атомарный захват операции. Между проверкой operation_in_progress в
        # начале _do_health_check и этим моментом проходит несколько секунд
        # (verify_dns_working и т.п.), за которые пользователь мог запустить
        # своё действие. Без атомарного захвата recovery и пользовательская
        # операция дёрнули бы netsh параллельно на одном адаптере.
        if not self.app._try_begin_operation():
            app_logger.info(
                "Автовосстановление отложено: выполняется другая операция. "
                "Попытка вернётся на следующем тике."
            )
            # Возвращаем «потраченную» в _on_dns_failure попытку, чтобы
            # отложенный цикл не съедал лимит автовосстановлений впустую.
            with self._lock:
                if self.recovery_attempts > 0:
                    self.recovery_attempts -= 1
            return

        self.app.after(0, lambda: self.app._set_buttons_state(False))

        try:
            self._execute_recovery(recovery_mode, attempt)
        finally:
            self.app._end_operation()
            self.app.after(0, lambda: self.app._set_buttons_state(True))

    def _execute_recovery(self, recovery_mode, attempt):
        prefix = f"Восстановление ({attempt}/{MAX_RECOVERY_ATTEMPTS})"

        # Шаг 1: Сброс DNS на DHCP
        self.app.after(0, lambda: self.app._set_operation_step(
            f"{prefix}: сброс к стандартному DNS..."
        ))

        # Помечаем, что сброс DNS выполняется самим приложением (не внешний источник)
        self.app._self_reset_pending = True

        result = self.app._apply_dns_reset()
        if not result["success"]:
            app_logger.error(f"Ошибка сброса DNS: {result['error']}")
            self.app.after(0, lambda: self.app._set_operation_step(
                f"Ошибка сброса DNS: {result['error']}", is_error=True
            ))
            return

        app_logger.info("DNS сброшен на DHCP для восстановления")
        flush_dns_cache()

        # Шаг 2: Ожидание интернета
        self.app.after(0, lambda: self.app._set_operation_step(
            f"{prefix}: ожидание интернета..."
        ))

        internet_ok = False
        elapsed = 0
        while elapsed < INTERNET_WAIT_TIMEOUT and not self._stop_event.is_set():
            self._stop_event.wait(INTERNET_WAIT_INTERVAL)
            if self._stop_event.is_set():
                return
            elapsed += INTERNET_WAIT_INTERVAL
            check = verify_dns_working()
            if check["working"]:
                internet_ok = True
                break

        if not internet_ok:
            app_logger.error(f"Интернет не появился за {INTERNET_WAIT_TIMEOUT} сек")
            self.app.after(0, lambda: self.app._set_operation_step(
                "Интернет не появился. Ожидание действий пользователя.", is_error=True
            ))
            self.app.after(0, self.app._refresh_state_safe)
            return

        app_logger.info("Интернет восстановлен")

        # Режим "только сброс"
        if recovery_mode == "reset_only":
            app_logger.info("Режим 'только сброс': DNS сброшен, ожидание действий пользователя")
            self.app.after(0, lambda: self.app._set_desired_mode("standard"))
            self.app.after(0, lambda: self.app._set_operation_step(
                "DNS сброшен. Выбранный DNS отключён. Ожидание действий пользователя."
            ))
            self.app.after(0, self.app._refresh_state_safe)
            self._running = False
            self._stop_event.set()
            self.app.after(100, self.app._update_monitor_label)
            return

        # Режим "сброс и восстановление"
        # Если выбран standard — после шага сброса целевой режим уже восстановлен.
        if self.app.desired_mode == "standard":
            self.app._self_reset_pending = False
            self.app.after(0, lambda: self.app._set_operation_step(
                f"{prefix}: выбранный DNS (Стандартный DNS) восстановлен",
                is_success=True
            ))
            self.app.after(0, self.app._clear_operation_delayed(5))
            self.app.after(0, self.app._refresh_state_safe)
            return

        target_profile = self.app._get_desired_profile()
        if target_profile is None:
            app_logger.warn("Целевой выбранный DNS-профиль не задан. Восстановление после сброса остановлено")
            self.app.after(0, lambda: self.app._set_operation_step(
                "Выбранный DNS не задан. DNS сброшен, ожидание действий пользователя.",
                is_error=True
            ))
            self.app.after(0, self.app._refresh_state_safe)
            self._running = False
            self._stop_event.set()
            self.app.after(100, self.app._update_monitor_label)
            return

        profile_name = target_profile["name"]
        target_type = target_profile.get("type")
        primary = target_profile.get("primary")
        secondary = target_profile.get("secondary")

        if target_type == "geohide":
            # Шаг 3: Резолв GeoHide
            self.app.after(0, lambda: self.app._set_operation_step(
                f"{prefix}: получение IP для {GEOHIDE_DOMAIN}..."
            ))
            ips, used_fallback = resolve_geohide()
            if not used_fallback:
                self.app.geohide_known_ips = list(ips)
                self.app.settings["geohide_resolved_ips"] = self.app.geohide_known_ips
                save_settings(self.app.settings)
            primary = ips[0] if ips else GEOHIDE_FALLBACK_IPS[0]
            secondary = ips[1] if len(ips) > 1 else (GEOHIDE_FALLBACK_IPS[1] if len(GEOHIDE_FALLBACK_IPS) > 1 else None)

        # Шаг 4: Применение выбранного DNS
        self.app.after(0, lambda: self.app._set_operation_step(
            f"{prefix}: применение Выбранного DNS ({profile_name})..."
        ))

        result = self.app._apply_dns_set(primary, secondary)
        if not result["success"]:
            app_logger.error(f"Ошибка применения {profile_name} при восстановлении: {result['error']}")
            self.app.after(0, lambda: self.app._set_operation_step(
                f"Ошибка применения Выбранного DNS ({profile_name}): {result['error']}",
                is_error=True
            ))
            self.app.after(0, self.app._refresh_state_safe)
            return

        # Выбранный DNS применён — сброс больше не является «собственным временным»
        self.app._self_reset_pending = False
        flush_dns_cache()

        time.sleep(1)

        # Шаг 5: Контрольная проверка
        self.app.after(0, lambda: self.app._set_operation_step(
            f"{prefix}: контрольная проверка DNS..."
        ))

        verify = verify_dns_working()
        if verify["working"]:
            app_logger.info(f"Выбранный DNS ({profile_name}) восстановлен успешно (попытка {attempt})")
            self.app.after(0, lambda: self.app._set_operation_step(
                f"Выбранный DNS ({profile_name}) восстановлен (попытка {attempt}/{MAX_RECOVERY_ATTEMPTS})",
                is_success=True
            ))
            self.app.after(0, lambda: self.app._clear_operation_delayed(5))
        else:
            app_logger.warn(f"Выбранный DNS ({profile_name}) применён, но DNS-проверка не пройдена: {verify.get('error')}")
            self.app.after(0, lambda: self.app._set_operation_step(
                f"Выбранный DNS ({profile_name}) применён, но DNS пока не отвечает"
            ))

        self.app.after(0, self.app._refresh_state_safe)
