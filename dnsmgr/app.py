"""Главный класс GUI-приложения DNSManagerApp.

Это самая толстая часть пакета (~2700 строк) — она и должна быть толстой,
потому что описывает всю интерактивную часть: окно, трей-меню, модальные
диалоги настройки профилей и реакции на внешнее изменение DNS, оркестрация
действий пользователя над сетью.

Зависит от всех нижних модулей пакета: constants, logger, config, process,
network, geohide, monitor, autostart.
"""

import os
import sys
import threading
import time
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import messagebox, ttk

import pystray
from PIL import Image, ImageDraw, ImageFont

from dnsmgr.autostart import (
    create_admin_scheduled_task,
    delete_admin_scheduled_task,
    get_admin_task_exists,
    get_autostart_enabled,
    set_autostart,
)
from dnsmgr.config import (
    DEFAULT_SETTINGS,
    _get_default_dns_profiles,
    get_desired_mode_label,
    get_profile_by_id,
    load_settings,
    save_settings,
)
from dnsmgr.constants import (
    APP_NAME,
    DEFAULT_DNS_BUTTONS_PER_ROW,
    DNS_PROFILE_TEST_DOMAIN,
    DNS_APPLY_SETTLE_DELAY,
    GEOHIDE_DOMAIN,
    GEOHIDE_FALLBACK_IPS,
    GEOHIDE_LEGACY_FALLBACK_IPS,
    HEALTH_CHECK_INTERVAL_MIN,
    INTERNET_WAIT_INTERVAL,
    INTERNET_WAIT_TIMEOUT,
    LOG_PATH,
    MAX_GUI_LOG_LINES,
    MAX_RECOVERY_ATTEMPTS,
    NETWORK_NO_CONNECTION,
    NETWORK_READY,
    NETWORK_UNSTABLE,
)
from dnsmgr.geohide import fetch_dns_from_link, resolve_geohide
from dnsmgr.logger import app_logger
from dnsmgr.monitor import HealthMonitor, NetworkChangeWatcher
from dnsmgr.network import (
    check_network_ready,
    check_resource_via_dns,
    detect_dns_mode,
    filter_suitable_adapters,
    flush_dns_cache,
    get_active_internet_adapter,
    get_current_dns,
    get_dhcp_offered_dns,
    get_network_adapters,
    reset_dns,
    select_best_adapter,
    set_dns,
    verify_dns_working,
)
from dnsmgr.process import is_admin, restart_as_admin


# ═══════════════════════════════════════════════════════════════════════════════
# ГЕНЕРАЦИЯ ИКОНКИ
# ═══════════════════════════════════════════════════════════════════════════════

def create_tray_icon_image(size=64):
    """Создаёт иконку для трея программно."""
    img = Image.new("RGBA", (size, size), (52, 120, 246, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", size=int(size * 0.6))
    except Exception:
        font = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), "D", font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    x = (size - tw) // 2
    y = (size - th) // 2 - bbox[1]
    draw.text((x, y), "D", fill="white", font=font)
    return img


# ═══════════════════════════════════════════════════════════════════════════════
# ПРИЛОЖЕНИЕ
# ═══════════════════════════════════════════════════════════════════════════════

class DNSManagerApp(tk.Tk):

    @staticmethod
    def _enable_entry_clipboard_shortcuts(widget):
        """Явные Ctrl/Ctrl+Shift shortcut'ы для Entry при любой раскладке."""
        def _has_selection(w):
            try:
                w.index("sel.first")
                w.index("sel.last")
                return True
            except tk.TclError:
                return False

        def _is_editable(w):
            try:
                state = str(w.cget("state"))
            except tk.TclError:
                return True
            return state not in ("disabled", "readonly")

        def _copy(event):
            try:
                selected = event.widget.selection_get()
                event.widget.clipboard_clear()
                event.widget.clipboard_append(selected)
            except tk.TclError:
                pass
            return "break"

        def _paste(event):
            if not _is_editable(event.widget):
                return "break"
            try:
                text = event.widget.clipboard_get()
            except tk.TclError:
                return "break"
            try:
                if _has_selection(event.widget):
                    event.widget.delete("sel.first", "sel.last")
                event.widget.insert("insert", text)
            except tk.TclError:
                pass
            return "break"

        def _cut(event):
            if not _is_editable(event.widget):
                return "break"
            _copy(event)
            try:
                if _has_selection(event.widget):
                    event.widget.delete("sel.first", "sel.last")
            except tk.TclError:
                pass
            return "break"

        def _select_all(event):
            try:
                event.widget.selection_range(0, "end")
                event.widget.icursor("end")
            except tk.TclError:
                pass
            return "break"

        def _on_key(event):
            ctrl = bool(event.state & 0x4)
            shift = bool(event.state & 0x1)
            keysym = (event.keysym or "").lower()
            keycode = event.keycode
            if ctrl and (keysym in ("v", "м") or keycode == 86):
                return _paste(event)
            if shift and keysym == "insert":
                return _paste(event)
            if ctrl and (keysym in ("c", "с") or keycode == 67):
                return _copy(event)
            if ctrl and (keysym in ("x", "ч") or keycode == 88):
                return _cut(event)
            if ctrl and (keysym in ("a", "ф") or keycode == 65):
                return _select_all(event)
            return None

        widget.bind("<KeyPress>", _on_key)
        return widget

    def __init__(self, start_hidden=False):
        super().__init__()

        self.settings = load_settings()
        self.geohide_known_ips = []
        for ip in GEOHIDE_FALLBACK_IPS + self.settings.get("geohide_resolved_ips", []):
            if ip and ip not in self.geohide_known_ips:
                self.geohide_known_ips.append(ip)
        self._dns_profiles = self.settings.get("dns_profiles", _get_default_dns_profiles())
        self.adapters = []
        self.current_adapter = None
        self.operation_in_progress = False
        self.tray_icon = None
        self.tray_thread = None
        self._exiting = False
        self._external_change_pending = False
        self._self_reset_pending = False  # Флаг: DNS сброшен самим приложением (recovery)
        self._operation_clear_id = None
        self._action_stop_event = threading.Event()  # Прерывание длительных операций
        # Лок «входа в операцию». Сериализует установку operation_in_progress
        # между главным потоком (пользовательские действия через _run_action) и
        # потоком мониторинга (автовосстановление через HealthMonitor._do_recovery),
        # чтобы две DNS-операции не запускали netsh параллельно на одном адаптере.
        # Держится максимально коротко — только на проверку+установку флага,
        # сама операция выполняется без удержания лока.
        self._op_state_lock = threading.Lock()

        # Желаемый режим DNS
        self.desired_mode = self.settings.get("desired_mode", None)
        # Если desired_mode из настроек указывает на профиль, которого больше нет
        # (например, settings.json правили вручную), очищаем его, иначе UI будет
        # показывать «целевой режим» без соответствующей кнопки.
        if self.desired_mode and self.desired_mode != "standard":
            if not get_profile_by_id(self._dns_profiles, self.desired_mode):
                self.desired_mode = None
                self.settings["desired_mode"] = None
                save_settings(self.settings)
        self._current_actual_mode = "—"
        self._current_actual_profile_id = None

        # Визуальная индикация: кнопка, по которой сейчас идёт операция
        self._active_action_buttons = []  # список кнопок с индикацией «в процессе»
        self._pulse_after_id = None
        self._pulse_phase = 0

        # Мониторинг здоровья DNS
        self.health_monitor = HealthMonitor(self)

        # Событийная подписка на смену сети (Win32 NotifyAddrChange).
        # Срабатывает при каждом изменении IP-таблицы (подключение/отключение
        # адаптера, смена IP/маршрута). С дебаунсом вызывает _handle_network_change.
        self._net_change_after_id = None
        self.network_watcher = NetworkChangeWatcher(self._on_network_change)

        # Отложенная видимость
        self._start_hidden_requested = start_hidden
        # Флаг: приложение запущено через автозапуск Windows
        self._is_autostart = "--minimized" in sys.argv

        self._setup_window()
        self._build_ui()
        self._setup_tray()

        app_logger.set_gui_callback(self._add_log_entry_safe)
        app_logger.info("Запуск приложения")

        if is_admin():
            app_logger.info("Права администратора: да")
        else:
            app_logger.info("Права администратора: нет")

        if not app_logger.file_ok:
            app_logger.warn(f"Лог-файл недоступен для записи: {LOG_PATH}")

        self.after(100, self._initial_refresh)

    # ─── Окно ─────────────────────────────────────────────────────────────

    def _setup_window(self):
        self.title(APP_NAME)
        self.geometry("580x750")
        self.minsize(520, 600)
        self.configure(bg="#f5f5f5")
        self.resizable(True, True)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        try:
            icon_img = create_tray_icon_image(32)
            self._tk_icon = tk.PhotoImage(data=self._pil_to_png_bytes(icon_img))
            self.iconphoto(False, self._tk_icon)
        except Exception:
            pass

    @staticmethod
    def _pil_to_png_bytes(pil_img):
        import io
        buf = io.BytesIO()
        pil_img.save(buf, format="PNG")
        return buf.getvalue()

    # ─── UI ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background="#f5f5f5", font=("Segoe UI", 10))
        style.configure("TLabelframe", background="#f5f5f5")
        style.configure("TLabelframe.Label", background="#f5f5f5", font=("Segoe UI", 10, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("Big.TButton", font=("Segoe UI", 12, "bold"), padding=10)
        style.configure("TCheckbutton", background="#f5f5f5", font=("Segoe UI", 10))
        style.configure("TRadiobutton", background="#f5f5f5", font=("Segoe UI", 10))
        style.configure("TLabel", background="#f5f5f5", font=("Segoe UI", 10))
        style.configure("Header.TLabel", background="#f5f5f5", font=("Segoe UI", 11, "bold"))
        style.configure("Status.TLabel", background="#f5f5f5", font=("Segoe UI", 10))

        # Scrollable container для всего содержимого
        self._canvas = tk.Canvas(self, bg="#f5f5f5", highlightthickness=0)
        self._v_scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._v_scrollbar.set)

        self._v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        main_frame = ttk.Frame(self._canvas, padding=10)
        self._canvas_window = self._canvas.create_window((0, 0), window=main_frame, anchor="nw")

        def _on_frame_configure(event):
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))

        def _on_canvas_configure(event):
            self._canvas.itemconfig(self._canvas_window, width=event.width)

        main_frame.bind("<Configure>", _on_frame_configure)
        self._canvas.bind("<Configure>", _on_canvas_configure)

        # ── Заголовок ──
        header = ttk.Frame(main_frame)
        header.pack(fill=tk.X, pady=(0, 3))
        ttk.Label(header, text=APP_NAME, font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT)
        self.lbl_admin = ttk.Label(header, text="", font=("Segoe UI", 9))
        self.lbl_admin.pack(side=tk.RIGHT)
        if not is_admin():
            self.btn_elevate = ttk.Button(
                header, text="Перезапустить с правами",
                command=self._on_elevate
            )
            self.btn_elevate.pack(side=tk.RIGHT, padx=(0, 5))
        self._update_admin_label()

        # ── Текущее состояние ──
        state_frame = ttk.LabelFrame(main_frame, text="Текущее состояние", padding=6)
        state_frame.pack(fill=tk.X, pady=3)

        self.lbl_adapter = ttk.Label(state_frame, text="Адаптер: —", style="Status.TLabel")
        self.lbl_adapter.pack(anchor=tk.W)
        self.lbl_dns = ttk.Label(state_frame, text="DNS: —", style="Status.TLabel")
        self.lbl_dns.pack(anchor=tk.W)
        # Фактический и целевой режим — две отдельные строки
        self.lbl_mode_actual = ttk.Label(state_frame, text="Фактический режим: —", style="Status.TLabel")
        self.lbl_mode_actual.pack(anchor=tk.W)
        self.lbl_mode_desired = ttk.Label(state_frame, text="Целевой режим: —", style="Status.TLabel")
        self.lbl_mode_desired.pack(anchor=tk.W)
        self.lbl_check = ttk.Label(state_frame, text="Проверка: —", style="Status.TLabel")
        self.lbl_check.pack(anchor=tk.W)
        self.lbl_time = ttk.Label(state_frame, text="Обновлено: —", style="Status.TLabel")
        self.lbl_time.pack(anchor=tk.W)
        self.lbl_monitor = ttk.Label(state_frame, text="Мониторинг: —", style="Status.TLabel")
        self.lbl_monitor.pack(anchor=tk.W)

        # ── Текущая операция ──
        op_frame = ttk.LabelFrame(main_frame, text="Текущая операция", padding=6)
        op_frame.pack(fill=tk.X, pady=3)

        self.lbl_operation = ttk.Label(
            op_frame, text="Нет активной операции",
            font=("Segoe UI", 10), foreground="#888",
            background="#f5f5f5"
        )
        self.lbl_operation.pack(anchor=tk.W)

        # ── Быстрые кнопки ──
        quick_frame = ttk.LabelFrame(main_frame, text="Быстрое управление", padding=6)
        quick_frame.pack(fill=tk.X, pady=3)

        btn_row = ttk.Frame(quick_frame)
        btn_row.pack(fill=tk.X)

        # Две колонки: приоритетная кнопка + обновить состояние
        btn_row.columnconfigure(0, weight=1, uniform="qbtn")
        btn_row.columnconfigure(1, weight=1, uniform="qbtn")
        btn_row.rowconfigure(0, weight=1)

        # Приоритетная кнопка — определяется первым DNS-профилем в списке
        priority = self._dns_profiles[0] if self._dns_profiles else None
        priority_text = f"Включить {priority['name']}" if priority else "—"
        self.btn_quick_priority = tk.Button(
            btn_row, text=priority_text,
            font=("Segoe UI", 11, "bold"), bg="SystemButtonFace", fg="#333",
            relief=tk.RAISED, bd=1, padx=10, pady=10,
            activebackground="#e0e0e0", activeforeground="#000",
            command=lambda: self._action_apply_priority("quick_priority")
        )
        self.btn_quick_priority.grid(row=0, column=0, sticky="nsew", padx=(0, 3))

        self.btn_quick_refresh = tk.Button(
            btn_row, text="Обновить состояние",
            font=("Segoe UI", 11, "bold"), bg="SystemButtonFace", fg="#333",
            relief=tk.RAISED, bd=1, padx=10, pady=10,
            activebackground="#e0e0e0", activeforeground="#000",
            command=lambda: self._run_action(self._action_refresh, "quick_refresh")
        )
        self.btn_quick_refresh.grid(row=0, column=1, sticky="nsew", padx=(3, 0))

        # Динамический wraplength
        def _sync_wraplength(event=None):
            for btn in (self.btn_quick_priority, self.btn_quick_refresh):
                w = btn.winfo_width()
                if w > 1:
                    btn.configure(wraplength=max(60, w - 24))
        btn_row.bind("<Configure>", _sync_wraplength)

        # ── Адаптер + Действия ──
        adapter_frame = ttk.LabelFrame(main_frame, text="Адаптер и DNS", padding=6)
        adapter_frame.pack(fill=tk.X, pady=3)

        adapter_row = ttk.Frame(adapter_frame)
        adapter_row.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(adapter_row, text="Адаптер:").pack(side=tk.LEFT)
        self.combo_adapter = ttk.Combobox(adapter_row, state="readonly", width=40)
        self.combo_adapter.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.combo_adapter.bind("<<ComboboxSelected>>", self._on_adapter_change)
        self.combo_adapter.bind("<MouseWheel>", self._on_adapter_combobox_mousewheel)
        self.combo_adapter.bind("<Button-4>", self._on_adapter_combobox_mousewheel)
        self.combo_adapter.bind("<Button-5>", self._on_adapter_combobox_mousewheel)

        # Контейнер для динамической сетки пользовательских DNS-кнопок
        self._dns_grid_frame = ttk.Frame(adapter_frame)
        self._dns_grid_frame.pack(fill=tk.X)
        self._dns_profile_buttons = []  # Список кнопок для пользовательских DNS-профилей
        self._build_dns_profile_buttons()

        # Отдельная большая кнопка «Стандартный DNS» (системные DNS компьютера)
        self.btn_standard = tk.Button(
            adapter_frame,
            text="Стандартный DNS",
            font=("Segoe UI", 10, "bold"), bg="SystemButtonFace", fg="#333",
            relief=tk.RAISED, bd=1, padx=6, pady=8,
            activebackground="#e0e0e0", activeforeground="#000",
            command=lambda: self._run_action(self._action_standard, "standard")
        )
        self.btn_standard.pack(fill=tk.X, padx=2, pady=(6, 0))

        # ── Настройки (сворачиваемый блок) ──
        settings_container = ttk.Frame(main_frame, relief="groove", borderwidth=1)
        settings_container.pack(fill=tk.X, pady=3)

        settings_header = ttk.Frame(settings_container)
        settings_header.pack(fill=tk.X)

        self._settings_collapsed = True
        self._settings_toggle_lbl = ttk.Label(
            settings_header, text="▶  Настройки",
            style="TLabelframe.Label", cursor="hand2"
        )
        self._settings_toggle_lbl.pack(side=tk.LEFT, padx=6, pady=4)

        settings_frame = ttk.Frame(settings_container, padding=(6, 3))
        # По умолчанию свёрнут — НЕ пакуем

        def _toggle_settings(event=None):
            if self._settings_collapsed:
                settings_frame.pack(fill=tk.X)
                self._settings_toggle_lbl.configure(text="▼  Настройки")
                self._settings_collapsed = False
            else:
                settings_frame.pack_forget()
                self._settings_toggle_lbl.configure(text="▶  Настройки")
                self._settings_collapsed = True

        settings_header.bind("<Button-1>", _toggle_settings)
        self._settings_toggle_lbl.bind("<Button-1>", _toggle_settings)

        # Всегда запускать с правами администратора (общая настройка)
        self.var_require_admin = tk.BooleanVar(value=self.settings.get("require_admin", False))
        self.chk_require_admin = ttk.Checkbutton(
            settings_frame, text="Всегда запускать приложение с правами администратора",
            variable=self.var_require_admin, command=self._on_require_admin_toggle
        )
        self.chk_require_admin.pack(anchor=tk.W)

        ttk.Separator(settings_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=3)

        # Автозапуск (обычный)
        self.var_autostart = tk.BooleanVar(value=self.settings.get("autostart", False))
        self.chk_autostart = ttk.Checkbutton(
            settings_frame, text="Запускать вместе с Windows",
            variable=self.var_autostart, command=self._on_autostart_toggle
        )
        self.chk_autostart.pack(anchor=tk.W)

        # Автозапуск с правами администратора
        self.var_autostart_admin = tk.BooleanVar(value=self.settings.get("autostart_admin", False))
        self.chk_autostart_admin = ttk.Checkbutton(
            settings_frame, text="Запускать вместе с Windows с правами администратора",
            variable=self.var_autostart_admin, command=self._on_autostart_admin_toggle
        )
        self.chk_autostart_admin.pack(anchor=tk.W, padx=(15, 0))

        # Показ окна при отсутствии прав
        self.var_admin_prompt = tk.BooleanVar(value=self.settings.get("autostart_show_admin_prompt", False))
        self.chk_admin_prompt = ttk.Checkbutton(
            settings_frame, text="Если нет прав администратора — показать окно для перезапуска",
            variable=self.var_admin_prompt, command=self._on_admin_prompt_toggle
        )
        self.chk_admin_prompt.pack(anchor=tk.W, padx=(15, 0))

        # В трей при автозапуске (зависит от autostart)
        self.var_start_minimized = tk.BooleanVar(value=self.settings.get("start_minimized", False))
        self.chk_minimized = ttk.Checkbutton(
            settings_frame, text="При автозапуске с Windows запускать сразу в трей",
            variable=self.var_start_minimized, command=self._on_minimized_toggle
        )
        self.chk_minimized.pack(anchor=tk.W, padx=(15, 0))

        ttk.Separator(settings_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=3)

        # При закрытии окна — скрывать в трей
        self.var_close_to_tray = tk.BooleanVar(value=self.settings.get("close_to_tray", True))
        self.chk_close_to_tray = ttk.Checkbutton(
            settings_frame, text="При закрытии окна скрывать приложение в трей",
            variable=self.var_close_to_tray, command=self._on_close_to_tray_toggle
        )
        self.chk_close_to_tray.pack(anchor=tk.W)

        # Применять выбранный DNS ко всем найденным адаптерам
        self.var_apply_to_all_adapters = tk.BooleanVar(
            value=self.settings.get("apply_to_all_adapters", False)
        )
        self.chk_apply_to_all_adapters = ttk.Checkbutton(
            settings_frame,
            text="Применять выбранный DNS ко всем найденным адаптерам",
            variable=self.var_apply_to_all_adapters,
            command=self._on_apply_to_all_adapters_toggle,
        )
        self.chk_apply_to_all_adapters.pack(anchor=tk.W)

        ttk.Separator(settings_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=3)

        # Режим восстановления выбранного DNS
        recovery_frame = ttk.Frame(settings_frame)
        recovery_frame.pack(anchor=tk.W, pady=(4, 0))

        ttk.Label(recovery_frame, text="При недоступности Выбранного DNS:").pack(anchor=tk.W)

        self.var_recovery_mode = tk.StringVar(
            value=self.settings.get("selected_dns_recovery_mode", "reset_and_restore")
        )

        ttk.Radiobutton(
            recovery_frame, text="Сбросить DNS и восстановить Выбранный DNS",
            variable=self.var_recovery_mode, value="reset_and_restore",
            command=self._on_recovery_mode_change
        ).pack(anchor=tk.W, padx=(15, 0))

        ttk.Radiobutton(
            recovery_frame, text="Только сбросить DNS (ждать пользователя)",
            variable=self.var_recovery_mode, value="reset_only",
            command=self._on_recovery_mode_change
        ).pack(anchor=tk.W, padx=(15, 0))

        # Параметры мониторинга
        self.var_failure_threshold = tk.StringVar(
            value=str(self.settings.get("failure_threshold", 3))
        )
        self.var_health_check_interval = tk.StringVar(
            value=str(self.settings.get("health_check_interval", 15))
        )

        mon_frame = ttk.Frame(recovery_frame)
        mon_frame.pack(anchor=tk.W, padx=(15, 0), pady=(4, 0))

        ttk.Label(mon_frame, text="Количество повторных проверок:").grid(
            row=0, column=0, sticky=tk.W, pady=1
        )
        ent_threshold = ttk.Entry(mon_frame, textvariable=self.var_failure_threshold, width=6)
        self._enable_entry_clipboard_shortcuts(ent_threshold)
        ent_threshold.grid(row=0, column=1, sticky=tk.W, padx=(6, 0))
        ent_threshold.bind("<FocusOut>", self._on_failure_threshold_change)
        ent_threshold.bind("<Return>", self._on_failure_threshold_change)

        ttk.Label(mon_frame, text="Интервал между проверками, сек:").grid(
            row=1, column=0, sticky=tk.W, pady=1
        )
        ent_interval = ttk.Entry(mon_frame, textvariable=self.var_health_check_interval, width=6)
        self._enable_entry_clipboard_shortcuts(ent_interval)
        ent_interval.grid(row=1, column=1, sticky=tk.W, padx=(6, 0))
        ent_interval.bind("<FocusOut>", self._on_health_check_interval_change)
        ent_interval.bind("<Return>", self._on_health_check_interval_change)

        ttk.Separator(settings_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=3)

        # Поведение при изменении DNS другим приложением
        ext_dns_frame = ttk.Frame(settings_frame)
        ext_dns_frame.pack(anchor=tk.W, pady=(4, 0))

        ttk.Label(ext_dns_frame, text="При изменении DNS другим приложением:").pack(anchor=tk.W)

        self.var_external_dns_change_mode = tk.StringVar(
            value=self.settings.get("external_dns_change_mode", "notify")
        )

        ttk.Radiobutton(
            ext_dns_frame, text="Уведомлять пользователя и спрашивать действие",
            variable=self.var_external_dns_change_mode, value="notify",
            command=self._on_external_dns_change_mode_change
        ).pack(anchor=tk.W, padx=(15, 0))

        ttk.Radiobutton(
            ext_dns_frame, text="Автоматически возвращать Выбранный DNS",
            variable=self.var_external_dns_change_mode, value="auto_restore",
            command=self._on_external_dns_change_mode_change
        ).pack(anchor=tk.W, padx=(15, 0))

        log_path_frame = ttk.Frame(settings_frame)
        log_path_frame.pack(anchor=tk.W, pady=(3, 0))
        ttk.Label(log_path_frame, text=f"Лог-файл: {LOG_PATH}",
                  font=("Segoe UI", 8), foreground="#888").pack(side=tk.LEFT)
        ttk.Button(log_path_frame, text="\U0001f4c2", width=3,
                   command=self._open_log_folder).pack(side=tk.LEFT, padx=(4, 0))

        ttk.Separator(settings_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=3)

        # ── Кнопка настройки DNS-кнопок ──
        ttk.Button(
            settings_frame, text="Настройка DNS-кнопок",
            command=self._open_dns_profiles_settings
        ).pack(anchor=tk.W, pady=(2, 0))

        # ── Кнопка сброса настроек (внизу справа блока настроек) ──
        reset_btn_frame = ttk.Frame(settings_frame)
        reset_btn_frame.pack(fill=tk.X, pady=(6, 2))
        ttk.Button(
            reset_btn_frame, text="Сбросить к настройкам по умолчанию",
            command=self._reset_to_defaults
        ).pack(side=tk.RIGHT)

        # ── Журнал ──
        log_frame = ttk.LabelFrame(main_frame, text="Журнал", padding=5)
        log_frame.pack(fill=tk.X, pady=3)
        log_frame.configure(height=150)
        log_frame.pack_propagate(False)

        self.log_listbox = tk.Listbox(
            log_frame, font=("Consolas", 9), bg="white", fg="#333",
            selectbackground="#d0d0d0", activestyle="none",
            borderwidth=1, relief="solid", height=6
        )
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_listbox.yview)
        self.log_listbox.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_listbox.pack(fill=tk.BOTH, expand=True)

        # Динамические маппинги кнопок
        self._rebuild_button_mappings()

        # Начальное состояние зависимых чекбоксов
        self._update_checkbox_states()

        # Привязка прокрутки колёсиком мыши
        self._bind_mousewheel()

    def _bind_mousewheel(self):
        """Колёсико мыши: canvas глобально, Listbox журнала при наведении."""
        def _on_mousewheel_canvas(event):
            if self._is_adapter_dropdown_open():
                return "break"
            self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _on_mousewheel_listbox(event):
            self.log_listbox.yview_scroll(int(-1 * (event.delta / 120)), "units")
            return "break"

        self._canvas.bind_all("<MouseWheel>", _on_mousewheel_canvas)
        self.log_listbox.bind("<MouseWheel>", _on_mousewheel_listbox)
        self.log_listbox.bind("<Enter>", lambda e: self._canvas.bind_all("<MouseWheel>", _on_mousewheel_listbox))
        self.log_listbox.bind("<Leave>", lambda e: self._canvas.bind_all("<MouseWheel>", _on_mousewheel_canvas))

    def _is_adapter_dropdown_open(self):
        try:
            popdown = self.tk.call("ttk::combobox::PopdownWindow", str(self.combo_adapter))
            return bool(int(self.tk.call("winfo", "ismapped", popdown)))
        except Exception:
            return False

    def _on_adapter_combobox_mousewheel(self, event):
        """Запрещает смену адаптера колесом, оставляя прокрутку страницы."""
        # Если выпадающий список Combobox открыт, не скроллим фон —
        # это предотвращает визуальное "залипание" popdown-окна.
        if self._is_adapter_dropdown_open():
            return "break"

        delta = getattr(event, "delta", 0)
        if delta:
            self._canvas.yview_scroll(int(-1 * (delta / 120)), "units")
        elif getattr(event, "num", None) == 4:
            self._canvas.yview_scroll(-1, "units")
        elif getattr(event, "num", None) == 5:
            self._canvas.yview_scroll(1, "units")
        return "break"

    def _update_admin_label(self):
        if is_admin():
            self.lbl_admin.configure(text="Администратор: Да", foreground="#2a7d2a")
        else:
            self.lbl_admin.configure(text="Администратор: Нет", foreground="#c0392b")

    # ─── DNS-профили: вспомогательные методы ─────────────────────────────

    def _get_desired_profile(self):
        """Возвращает выбранный DNS-профиль (целевой режим) или None."""
        if not self.desired_mode or self.desired_mode == "standard":
            return None
        return get_profile_by_id(self._dns_profiles, self.desired_mode)

    def _has_selected_dns_mode(self):
        """Проверяет, что выбран целевой DNS-режим (профиль или standard)."""
        return self.desired_mode is not None

    def _find_geohide_profile(self):
        """Возвращает первый профиль типа geohide в текущем списке (или None).

        Используется как безопасный fallback в местах, где geohide-действие
        вызывается без явного указания профиля (мониторинг здоровья, диалог
        внешнего изменения DNS, меню трея). Сам id «geohide» больше не
        зашит в логику установки desired_mode — он берётся из реального
        профиля в списке.
        """
        for p in self._dns_profiles:
            if p.get("type") == "geohide":
                return p
        return None

    def _action_restore_selected_dns(self):
        """Восстанавливает выбранный DNS-профиль из desired_mode."""
        if self.desired_mode == "standard":
            self._action_standard()
            return
        profile = self._get_desired_profile()
        if profile is None:
            app_logger.warn("Автовосстановление пропущено: выбранный DNS-профиль не задан")
            self._set_operation_step(
                "Автовосстановление пропущено: выбранный DNS-профиль не задан",
                is_error=True
            )
            return
        if profile.get("type") == "geohide":
            self._action_geohide(profile)
        else:
            self._action_apply_profile(profile)

    def _build_dns_profile_buttons(self):
        """Создаёт кнопки пользовательских DNS-профилей в сетке."""
        # Очистка старых кнопок
        for w in self._dns_grid_frame.winfo_children():
            w.destroy()
        self._dns_profile_buttons = []

        per_row = self.settings.get("dns_buttons_per_row", DEFAULT_DNS_BUTTONS_PER_ROW)
        # Сброс старых настроек колонок (до 5 максимум)
        for col in range(5):
            self._dns_grid_frame.columnconfigure(col, weight=0, uniform="")
        for col in range(per_row):
            self._dns_grid_frame.columnconfigure(col, weight=1, uniform="dnsbtn")

        for idx, profile in enumerate(self._dns_profiles):
            row = idx // per_row
            col = idx % per_row
            pid = profile["id"]
            btn = tk.Button(
                self._dns_grid_frame, text=profile["name"],
                font=("Segoe UI", 10), bg="SystemButtonFace", fg="#333",
                relief=tk.RAISED, bd=1, padx=6, pady=6,
                activebackground="#e0e0e0", activeforeground="#000",
                command=lambda p=profile: self._action_apply_by_profile(p)
            )
            btn.grid(row=row, column=col, sticky="nsew", padx=2, pady=2)
            btn._profile_id = pid
            self._dns_profile_buttons.append(btn)

    def _action_apply_by_profile(self, profile):
        """Запускает применение DNS-профиля (выбор между geohide и static)."""
        if profile["type"] == "geohide":
            self._run_action(lambda p=profile: self._action_geohide(p), profile["id"])
        else:
            self._run_action(lambda p=profile: self._action_apply_profile(p), profile["id"])

    def _action_apply_priority(self, action_key="quick_priority"):
        """Запускает применение приоритетного DNS-профиля (верхняя кнопка).

        Приоритетным считается ПЕРВЫЙ профиль в пользовательском списке,
        вне зависимости от его имени или типа. GeoHide здесь не выделен
        особо: он попадает сюда только если пользователь сам поставил его
        первым (или оставил по умолчанию).
        """
        priority = self._dns_profiles[0] if self._dns_profiles else None
        if not priority:
            return
        if priority["type"] == "geohide":
            # Спецлогика geohide-типа сохраняется: если этот профиль уже
            # активен — запускаем полный цикл обновления, иначе — обычное
            # включение. Конкретный профиль передаём явно, чтобы не
            # завязываться на литерал id="geohide".
            if self._current_actual_profile_id == priority["id"]:
                self._run_action(lambda p=priority: self._action_update_geohide(p), action_key)
            else:
                self._run_action(lambda p=priority: self._action_geohide(p), action_key)
        else:
            self._run_action(lambda p=priority: self._action_apply_profile(p), action_key)

    def _rebuild_button_mappings(self):
        """Перестраивает маппинги кнопок для индикации (пульсации «в процессе»).

        Подсветка активного режима НЕ строится через эти маппинги. Она
        пересчитывается централизованно в `_update_active_mode_buttons`
        напрямую от фактического `_current_actual_profile_id` и текущего
        списка кнопок — это единственный источник истины для зелёного
        активного состояния.
        """
        # Все кнопки для блокировки при операции
        self.action_buttons = [self.btn_quick_priority, self.btn_quick_refresh, self.btn_standard]
        self.action_buttons.extend(self._dns_profile_buttons)

        # action_key -> кнопки для пульсации «в процессе»
        self._action_key_to_buttons = {
            "standard": [self.btn_standard],
            "quick_priority": [self.btn_quick_priority],
            "quick_refresh": [self.btn_quick_refresh],
            "initial": [],
        }
        for btn in self._dns_profile_buttons:
            self._action_key_to_buttons[btn._profile_id] = [btn]

    def _rebuild_dns_ui(self):
        """Полная перестройка DNS-кнопок и связанных маппингов."""
        self._build_dns_profile_buttons()
        self._rebuild_button_mappings()
        self._update_quick_priority_button()
        self._rebuild_tray_menu()
        # Обновить подсветку
        self._update_active_mode_buttons()

    def _update_quick_priority_button(self):
        """Обновляет текст и команду верхней приоритетной кнопки."""
        priority = self._dns_profiles[0] if self._dns_profiles else None
        if not priority:
            self.btn_quick_priority.configure(text="—", command=lambda: None)
            return
        pid = priority["id"]
        pname = priority["name"]
        if priority["type"] == "geohide" and self._current_actual_profile_id == pid:
            self.btn_quick_priority.configure(
                text=f"Обновить {pname}",
                command=lambda: self._action_apply_priority("quick_priority")
            )
        else:
            self.btn_quick_priority.configure(
                text=f"Включить {pname}",
                command=lambda: self._action_apply_priority("quick_priority")
            )

    def _update_monitor_label(self):
        """Обновляет постоянную строку статуса мониторинга в блоке «Текущее состояние»."""
        selected_dns_mode = self._has_selected_dns_mode()
        if self.health_monitor.is_running():
            if not self.current_adapter:
                self.lbl_monitor.configure(text="Мониторинг: поиск адаптера...", foreground="#e65100")
            elif self.health_monitor._network_waiting:
                self.lbl_monitor.configure(text="Мониторинг: ожидание сети", foreground="#e65100")
            else:
                self.lbl_monitor.configure(text="Мониторинг: работает", foreground="#2a7d2a")
        elif selected_dns_mode and not self.current_adapter:
            self.lbl_monitor.configure(
                text="Мониторинг: не запущен (нет активного адаптера)", foreground="#c0392b"
            )
        elif selected_dns_mode and not is_admin():
            self.lbl_monitor.configure(
                text="Мониторинг: не запущен (нет прав администратора)", foreground="#c0392b"
            )
        elif selected_dns_mode and self.health_monitor.recovery_attempts >= MAX_RECOVERY_ATTEMPTS:
            self.lbl_monitor.configure(
                text="Мониторинг: остановлен (лимит попыток исчерпан)", foreground="#c0392b"
            )
        elif selected_dns_mode:
            self.lbl_monitor.configure(text="Мониторинг: остановлен", foreground="#e65100")
        else:
            self.lbl_monitor.configure(text="Мониторинг: не требуется", foreground="#888")

    # ─── Зависимости чекбоксов ────────────────────────────────────────────

    def _update_checkbox_states(self):
        """Обновляет доступность зависимых чекбоксов и сбрасывает отключённые."""
        autostart = self.var_autostart.get()
        autostart_admin = self.var_autostart_admin.get()
        admin_prompt = self.var_admin_prompt.get()

        # autostart_admin: зависит от autostart
        if autostart:
            self.chk_autostart_admin.configure(state=tk.NORMAL)
        else:
            self.chk_autostart_admin.configure(state=tk.DISABLED)
            if autostart_admin:
                self.var_autostart_admin.set(False)
                self.settings["autostart_admin"] = False
                save_settings(self.settings)
                autostart_admin = False

        # admin_prompt: зависит от autostart AND autostart_admin
        if autostart and autostart_admin:
            self.chk_admin_prompt.configure(state=tk.NORMAL)
        else:
            self.chk_admin_prompt.configure(state=tk.DISABLED)
            if admin_prompt:
                self.var_admin_prompt.set(False)
                self.settings["autostart_show_admin_prompt"] = False
                save_settings(self.settings)
                admin_prompt = False

        # minimized: зависит от autostart AND autostart_admin AND admin_prompt
        if autostart and autostart_admin and admin_prompt:
            self.chk_minimized.configure(state=tk.NORMAL)
        else:
            self.chk_minimized.configure(state=tk.DISABLED)
            if self.var_start_minimized.get():
                self.var_start_minimized.set(False)
                self.settings["start_minimized"] = False
                save_settings(self.settings)

    # ─── Блок «Текущая операция» ─────────────────────────────────────────

    def _set_operation_step(self, text, is_error=False, is_success=False):
        """Потокобезопасное обновление блока «Текущая операция»."""
        if is_error:
            color = "#c0392b"
        elif is_success:
            color = "#2a7d2a"
        else:
            color = "#2962ff"
        try:
            self.after(0, lambda t=text, c=color: self._do_set_operation(t, c))
        except Exception:
            pass

    def _do_set_operation(self, text, color):
        self.lbl_operation.configure(text=text, foreground=color, font=("Segoe UI", 10, "bold"))

    def _clear_operation(self):
        try:
            self.after(0, lambda: self.lbl_operation.configure(
                text="Нет активной операции", foreground="#888", font=("Segoe UI", 10)
            ))
        except Exception:
            pass

    def _clear_operation_delayed(self, seconds=3):
        try:
            if self._operation_clear_id is not None:
                self.after_cancel(self._operation_clear_id)
            self._operation_clear_id = self.after(int(seconds * 1000), self._do_clear_operation)
        except Exception:
            pass

    def _do_clear_operation(self):
        self._operation_clear_id = None
        if not self.operation_in_progress:
            self.lbl_operation.configure(
                text="Нет активной операции", foreground="#888", font=("Segoe UI", 10)
            )

    # ─── Желаемый режим ───────────────────────────────────────────────────

    def _set_desired_mode(self, mode):
        self.desired_mode = mode
        self.settings["desired_mode"] = mode
        save_settings(self.settings)

    # ─── Трей ─────────────────────────────────────────────────────────────

    def _build_tray_menu(self):
        """Строит меню трея из текущих DNS-профилей."""
        items = [pystray.MenuItem("Открыть окно", self._tray_show, default=True),
                 pystray.Menu.SEPARATOR]

        def make_apply_action(pr):
            return lambda icon, item: self.after(0, lambda: self._action_apply_by_profile(pr))

        def make_update_geohide_action(pr):
            # Захватываем конкретный профиль, чтобы _action_update_geohide
            # работал именно с ним, а не с неявным id="geohide".
            return lambda icon, item: self.after(
                0,
                lambda: self._run_action(lambda p=pr: self._action_update_geohide(p))
            )

        for profile in self._dns_profiles:
            p = profile
            items.append(pystray.MenuItem(
                f"Включить {p['name']}",
                make_apply_action(p)
            ))
            # Для geohide-профилей добавляем «Обновить»
            if p["type"] == "geohide":
                items.append(pystray.MenuItem(
                    f"Обновить {p['name']}",
                    make_update_geohide_action(p)
                ))
        items.append(pystray.MenuItem(
            "Стандартный DNS (системные настройки)",
            lambda icon, item: self.after(0, lambda: self._run_action(self._action_standard))
        ))
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem(
            "Обновить состояние",
            lambda icon, item: self.after(0, lambda: self._run_action(self._action_refresh))
        ))
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Выход", self._tray_quit))
        return pystray.Menu(*items)

    def _setup_tray(self):
        icon_image = create_tray_icon_image(64)
        self.tray_icon = pystray.Icon(
            "dns_manager",
            icon=icon_image,
            title=APP_NAME,
            menu=self._build_tray_menu()
        )
        self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        self.tray_thread.start()

    def _rebuild_tray_menu(self):
        """Перестраивает меню трея после изменения профилей."""
        try:
            if self.tray_icon:
                self.tray_icon.menu = self._build_tray_menu()
                self.tray_icon.update_menu()
        except Exception:
            pass

    def _tray_show(self, icon=None, item=None):
        self.after(0, self._show_window)

    def _tray_quit(self, icon=None, item=None):
        self.after(0, self._do_quit)

    # ─── Окно: скрытие / показ / закрытие ─────────────────────────────────

    def _on_close(self):
        if self.settings.get("close_to_tray", True):
            app_logger.info("Скрытие в трей")
            self.withdraw()
        else:
            self._do_quit()

    def _show_window(self):
        self.deiconify()
        self.lift()
        self.focus_force()
        self.state("normal")

    def _do_quit(self):
        if self._exiting:
            return
        self._exiting = True
        app_logger.info("Завершение приложения")
        try:
            self._action_stop_event.set()
        except Exception:
            pass
        try:
            self.health_monitor.stop()
        except Exception:
            pass
        try:
            self.network_watcher.stop()
        except Exception:
            pass
        try:
            if self.tray_icon:
                self.tray_icon.stop()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass

    def _on_elevate(self):
        app_logger.info("Запрос повышения прав (UAC)")
        if not restart_as_admin():
            app_logger.error("Не удалось перезапустить с правами администратора")
            messagebox.showerror(APP_NAME, "Не удалось получить права администратора.\nПопробуйте запустить приложение вручную от имени администратора.")

    # ─── Окно запроса прав администратора ─────────────────────────────────

    def _show_admin_prompt_window(self):
        """Показывает окно с предложением перезапуска с правами администратора."""
        self._show_window()
        answer = messagebox.askyesno(
            APP_NAME,
            "Приложение запущено без прав администратора.\n\n"
            "Для автоматической DNS-логики (мониторинг, восстановление Выбранного DNS, "
            "сброс DNS) требуются права администратора.\n\n"
            "Перезапустить с правами администратора?",
            icon="warning"
        )
        if answer:
            self._on_elevate()

    # ─── Настройка: всегда требовать права администратора ─────────────────

    def _on_require_admin_toggle(self):
        val = self.var_require_admin.get()
        self.settings["require_admin"] = val
        save_settings(self.settings)
        if val:
            app_logger.info("Настройка: всегда запускать с правами администратора — включено")
            if not is_admin():
                self.after(100, self._show_require_admin_window)
        else:
            app_logger.info("Настройка: всегда запускать с правами администратора — выключено")

    def _show_require_admin_window(self):
        """Показывает окно с предложением перезапуска с правами администратора.
        При отказе — приложение остаётся открытым без прав (read-only режим)."""
        self._show_window()
        answer = messagebox.askyesno(
            APP_NAME,
            "Приложение настроено на работу только с правами администратора.\n\n"
            "Без прав администратора не работают мониторинг, восстановление Выбранного DNS "
            "и автоматическая логика DNS.\n\n"
            "Перезапустить с правами администратора?",
            icon="warning"
        )
        if answer:
            self._on_elevate()
        else:
            app_logger.warn("Пользователь отказался от перезапуска — приложение работает без прав администратора")

    # ─── Настройки: переключатели ─────────────────────────────────────────

    def _on_autostart_toggle(self):
        val = self.var_autostart.get()
        self.settings["autostart"] = val
        save_settings(self.settings)

        if val:
            if self.settings.get("autostart_admin", False):
                create_admin_scheduled_task(self.settings.get("start_minimized", False))
            else:
                set_autostart(True, self.settings.get("start_minimized", False))
        else:
            # Выключаем оба механизма
            set_autostart(False)
            delete_admin_scheduled_task()

        self._update_checkbox_states()

    def _on_autostart_admin_toggle(self):
        val = self.var_autostart_admin.get()
        self.settings["autostart_admin"] = val
        save_settings(self.settings)

        minimized = self.settings.get("start_minimized", False)

        if val:
            # Включаем Планировщик, убираем реестр
            set_autostart(False)
            create_admin_scheduled_task(minimized)
        else:
            # Убираем Планировщик, включаем реестр
            delete_admin_scheduled_task()
            if self.settings.get("autostart", False):
                set_autostart(True, minimized)

        self._update_checkbox_states()

    def _on_admin_prompt_toggle(self):
        val = self.var_admin_prompt.get()
        self.settings["autostart_show_admin_prompt"] = val
        save_settings(self.settings)
        self._update_checkbox_states()

    def _on_minimized_toggle(self):
        val = self.var_start_minimized.get()
        self.settings["start_minimized"] = val
        save_settings(self.settings)
        if val:
            app_logger.info("При автозапуске — в трей: включено")
        else:
            app_logger.info("При автозапуске — в трей: выключено")
        # Обновить запись автозапуска
        if self.settings.get("autostart", False):
            if self.settings.get("autostart_admin", False):
                create_admin_scheduled_task(val)
            else:
                set_autostart(True, val)

    def _on_close_to_tray_toggle(self):
        val = self.var_close_to_tray.get()
        self.settings["close_to_tray"] = val
        save_settings(self.settings)
        if val:
            app_logger.info("При закрытии окна — скрывать в трей: включено")
        else:
            app_logger.info("При закрытии окна — скрывать в трей: выключено")

    def _on_apply_to_all_adapters_toggle(self):
        val = self.var_apply_to_all_adapters.get()
        self.settings["apply_to_all_adapters"] = val
        save_settings(self.settings)
        if val:
            app_logger.info("Применение выбранного DNS ко всем найденным адаптерам: включено")
            # Если есть активный выбранный DNS — синхронизируем все подходящие адаптеры
            if self._has_selected_dns_mode() and self.current_adapter and is_admin():
                self._run_action(self._action_sync_all_adapters)
        else:
            app_logger.info("Применение выбранного DNS ко всем найденным адаптерам: выключено")

    def _on_recovery_mode_change(self):
        val = self.var_recovery_mode.get()
        self.settings["selected_dns_recovery_mode"] = val
        save_settings(self.settings)
        label = "сброс и восстановление" if val == "reset_and_restore" else "только сброс"
        app_logger.info(f"Режим восстановления выбранного DNS: {label}")

    def _on_external_dns_change_mode_change(self):
        val = self.var_external_dns_change_mode.get()
        self.settings["external_dns_change_mode"] = val
        save_settings(self.settings)
        label = "уведомление пользователя" if val == "notify" else "автоматический возврат выбранного DNS"
        app_logger.info(f"Режим реакции на внешнее изменение DNS: {label}")

    def _on_failure_threshold_change(self, event=None):
        try:
            val = int(self.var_failure_threshold.get())
            if val < 1:
                raise ValueError
        except (ValueError, tk.TclError):
            self.var_failure_threshold.set(str(self.settings.get("failure_threshold", 3)))
            return
        self.settings["failure_threshold"] = val
        save_settings(self.settings)
        app_logger.info(f"Количество повторных проверок для выбранного DNS: {val}")

    def _on_health_check_interval_change(self, event=None):
        try:
            val = int(self.var_health_check_interval.get())
            if val < HEALTH_CHECK_INTERVAL_MIN:
                val = HEALTH_CHECK_INTERVAL_MIN
                self.var_health_check_interval.set(str(val))
        except (ValueError, tk.TclError):
            self.var_health_check_interval.set(str(self.settings.get("health_check_interval", 15)))
            return
        self.settings["health_check_interval"] = val
        save_settings(self.settings)
        app_logger.info(f"Интервал между проверками для выбранного DNS: {val} сек")

    def _open_log_folder(self):
        """Открывает папку, содержащую лог-файл."""
        try:
            folder = os.path.dirname(LOG_PATH)
            if os.path.isdir(folder):
                os.startfile(folder)
            else:
                messagebox.showerror(APP_NAME, f"Папка не найдена:\n{folder}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Не удалось открыть папку:\n{e}")

    def _reset_to_defaults(self):
        """Сбрасывает настройки к значениям по умолчанию."""
        answer = messagebox.askyesno(
            "Подтверждение",
            "Сбросить все настройки по умолчанию?"
        )
        if not answer:
            return

        # Сохраняем значения, которые не нужно сбрасывать
        keep_keys = ("selected_adapter", "geohide_resolved_ips", "desired_mode")
        preserved = {k: self.settings.get(k) for k in keep_keys}

        # Применяем дефолты
        self.settings.update(DEFAULT_SETTINGS)
        self.settings.update(preserved)
        # DNS-профили тоже сбрасываются к дефолту при полном сбросе
        self.settings["dns_profiles"] = _get_default_dns_profiles()
        self.settings["dns_buttons_per_row"] = DEFAULT_DNS_BUTTONS_PER_ROW

        # Если сохранённый desired_mode не указывает на существующий профиль
        # (после сброса к дефолтным профилям), очищаем его, чтобы не появлялось
        # «фантомное» желаемое состояние без реальной кнопки.
        valid_ids = {p["id"] for p in self.settings["dns_profiles"]}
        valid_ids.add("standard")
        if self.settings.get("desired_mode") not in valid_ids:
            self.settings["desired_mode"] = None

        save_settings(self.settings)

        # Обновляем все UI-переменные
        self.var_require_admin.set(self.settings["require_admin"])
        self.var_autostart.set(self.settings["autostart"])
        self.var_autostart_admin.set(self.settings["autostart_admin"])
        self.var_admin_prompt.set(self.settings["autostart_show_admin_prompt"])
        self.var_start_minimized.set(self.settings["start_minimized"])
        self.var_close_to_tray.set(self.settings["close_to_tray"])
        self.var_apply_to_all_adapters.set(self.settings["apply_to_all_adapters"])
        self.var_recovery_mode.set(self.settings["selected_dns_recovery_mode"])
        self.var_failure_threshold.set(str(self.settings["failure_threshold"]))
        self.var_health_check_interval.set(str(self.settings["health_check_interval"]))
        self.var_external_dns_change_mode.set(self.settings["external_dns_change_mode"])

        # Пересчитать зависимости чекбоксов
        self._update_checkbox_states()

        # Восстановить DNS-профили и перестроить UI
        self._dns_profiles = self.settings["dns_profiles"]
        self._rebuild_dns_ui()

        # Применить автозапуск
        minimized = self.settings["start_minimized"]
        if self.settings["autostart_admin"]:
            set_autostart(False)
            create_admin_scheduled_task(minimized)
        elif self.settings["autostart"]:
            delete_admin_scheduled_task()
            set_autostart(True, minimized)

        app_logger.info("Настройки сброшены по умолчанию")

    # ─── Адаптер ──────────────────────────────────────────────────────────

    def _on_adapter_change(self, event=None):
        sel = self.combo_adapter.get()
        if sel:
            name = sel.split(" — ")[0].strip()
            self.current_adapter = name
            self.settings["selected_adapter"] = name
            # Запоминаем явный выбор пользователя отдельно от operационного
            # selected_adapter. Авто-перепривязка может временно переключить
            # current_adapter/selected_adapter на другой работающий адаптер,
            # но manual_adapter сохраняется — и когда выбранный пользователем
            # адаптер снова станет здоров, монитор вернётся к нему.
            self.settings["manual_adapter"] = name
            save_settings(self.settings)
            app_logger.info(f"Выбран адаптер: {name} (manual)")
            self._run_action(self._action_refresh)

    # ─── Журнал ───────────────────────────────────────────────────────────

    def _add_log_entry_safe(self, entry):
        """Потокобезопасное добавление записи в GUI-лог."""
        try:
            self.after(0, lambda e=entry: self._add_log_entry(e))
        except Exception:
            pass

    def _add_log_entry(self, entry):
        try:
            self.log_listbox.insert(tk.END, entry)
            while self.log_listbox.size() > MAX_GUI_LOG_LINES:
                self.log_listbox.delete(0)
            self.log_listbox.see(tk.END)
        except Exception:
            pass

    # ─── Выполнение действий (threading) ──────────────────────────────────

    def _try_begin_operation(self):
        """Атомарно «захватывает» право на DNS-операцию.

        Возвращает True, если операция начата (operation_in_progress был False
        и стал True под локом), иначе False. Используется и пользовательскими
        действиями, и автовосстановлением — это единственная точка перехода
        operation_in_progress в True, что устраняет гонку «проверил → начал».
        """
        with self._op_state_lock:
            if self.operation_in_progress:
                return False
            self.operation_in_progress = True
            return True

    def _end_operation(self):
        """Снимает флаг операции под локом (парный к _try_begin_operation)."""
        with self._op_state_lock:
            self.operation_in_progress = False

    def _run_action(self, action_func, action_key=None):
        # Атомарный захват: если операция уже идёт (в т.ч. автовосстановление
        # в потоке мониторинга) — выходим, не запуская вторую.
        if not self._try_begin_operation():
            return
        # Любое ручное действие пользователя отменяет ожидание внешнего изменения DNS.
        # Предотвращает «мёртвый» мониторинг при действии из трея
        # во время открытого диалога внешнего изменения.
        if self._external_change_pending:
            self._external_change_pending = False
            app_logger.info("Ожидание внешнего изменения DNS сброшено (пользователь запустил действие)")
        if self._operation_clear_id is not None:
            self.after_cancel(self._operation_clear_id)
            self._operation_clear_id = None
        self._action_stop_event.clear()
        self._self_reset_pending = False
        self._set_buttons_state(False)
        # Визуальная индикация «операция выполняется» на кнопке
        self._start_action_indication(action_key)
        threading.Thread(target=self._action_wrapper, args=(action_func,), daemon=True).start()

    def _action_wrapper(self, action_func):
        try:
            action_func()
        except Exception as e:
            app_logger.error(f"Непредвиденная ошибка: {e}")
            self._set_operation_step(f"Ошибка: {e}", is_error=True)
        finally:
            self.after(0, self._action_done)

    def _action_done(self):
        self._end_operation()
        self._stop_action_indication()
        self._set_buttons_state(True)
        self._update_active_mode_buttons()

    def _set_buttons_state(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        for btn in self.action_buttons:
            try:
                btn.configure(state=state)
            except Exception:
                pass

    # ─── Визуальная индикация активного режима и выполняемой операции ──

    # Цвета для состояния «активный режим»
    _MODE_ACTIVE_BG = "#d4edda"       # светло-зелёный фон
    _MODE_ACTIVE_BORDER = "#28a745"   # зелёная рамка

    # Цвета для состояния «операция выполняется» (пульсация)
    _ACTION_PULSE_COLORS = ["#fff3cd", "#ffe082"]  # жёлто-оранжевые фазы
    _ACTION_PULSE_BORDER = "#ff8f00"
    _PULSE_INTERVAL_MS = 500

    def _update_active_mode_buttons(self):
        """Единый источник истины для зелёной подсветки активной кнопки.

        Строгая модель:
          1. В любой момент времени активной (зелёной) может быть только одна
             логическая кнопка — та, что соответствует фактически активному
             текущему DNS (`_current_actual_profile_id`).
          2. Кнопка пользовательского DNS-профиля зелёная только если её
             `_profile_id` совпадает с фактически активным DNS.
          3. Верхняя кнопка быстрого доступа (`btn_quick_priority`) зелёная
             только если приоритетный профиль (первый в списке) ДЕЙСТВИТЕЛЬНО
             является фактически активным DNS. Просто быть приоритетным —
             недостаточно.
          4. Большая кнопка стандартного DNS зелёная только если фактически
             активен стандартный DNS (DHCP).
          5. При активном стандартном DNS ни одна пользовательская кнопка не
             может быть зелёной; при активном пользовательском DNS не может
             быть зелёной кнопка стандартного DNS.
          6. Кнопка «Обновить состояние» (`btn_quick_refresh`) никогда не
             зелёная — она не привязана к режиму.
          7. Если кнопка сейчас участвует в индикации операции (пульсирует),
             её стиль не трогаем — пульсация имеет приоритет, а после её
             завершения функция будет вызвана повторно из `_action_done`.

        Подсветка пересчитывается ИСКЛЮЧИТЕЛЬНО от `_current_actual_profile_id`,
        а не от приоритетного профиля, не от позиции кнопки в интерфейсе и не
        от desired_mode. Все вызовы (refresh, применение DNS, сброс, загрузка,
        восстановление, изменение списка профилей) идут через эту функцию.
        """
        actual_pid = self._current_actual_profile_id

        # 1. Кнопки пользовательских DNS-профилей
        for btn in self._dns_profile_buttons:
            if btn in self._active_action_buttons:
                continue
            if actual_pid is not None and getattr(btn, "_profile_id", None) == actual_pid:
                self._set_btn_active_mode(btn)
            else:
                self._reset_btn_style(btn)

        # 2. Верхняя кнопка быстрого доступа.
        # Зелёная — только если приоритетный профиль == фактически активный DNS.
        if self.btn_quick_priority not in self._active_action_buttons:
            priority = self._dns_profiles[0] if self._dns_profiles else None
            priority_is_actually_active = (
                priority is not None
                and actual_pid is not None
                and priority["id"] == actual_pid
            )
            if priority_is_actually_active:
                self._set_btn_active_mode(self.btn_quick_priority)
            else:
                self._reset_btn_style(self.btn_quick_priority)

        # 3. Большая кнопка стандартного DNS.
        # Зелёная — только при actual_pid == "standard".
        if self.btn_standard not in self._active_action_buttons:
            if actual_pid == "standard":
                self._set_btn_active_mode(self.btn_standard)
            else:
                self._reset_btn_style(self.btn_standard)

        # 4. Кнопка обновления состояния — не привязана к режиму, всегда нейтральна.
        if self.btn_quick_refresh not in self._active_action_buttons:
            self._reset_btn_style(self.btn_quick_refresh)

    def _set_btn_active_mode(self, btn):
        """Применяет стиль «активный режим» к tk.Button."""
        try:
            btn.configure(
                bg=self._MODE_ACTIVE_BG,
                highlightbackground=self._MODE_ACTIVE_BORDER,
                highlightthickness=2,
                relief=tk.GROOVE,
            )
        except Exception:
            pass

    def _reset_btn_style(self, btn):
        """Сбрасывает стиль кнопки к нейтральному (не активному) состоянию.

        Сброс идёт к фиксированной системной палитре, а НЕ к запомненному ранее
        фону. Запоминание `cget('bg')` приводило к загрязнению «дефолта»: если
        в момент пересохранения маппингов кнопка была подсвечена зелёным, эта
        зелёная подсветка попадала в кэш как «исходный» цвет, и последующий
        reset фактически не сбрасывал зелёный. Теперь reset всегда возвращает
        кнопку именно к нейтральному виду, что и требуется единым правилом
        подсветки.
        """
        try:
            btn.configure(
                bg="SystemButtonFace",
                highlightbackground="SystemButtonFace",
                highlightthickness=0,
                relief=tk.RAISED,
            )
        except Exception:
            pass

    def _start_action_indication(self, action_key):
        """Начинает пульсирующую индикацию на кнопках, связанных с action_key."""
        self._stop_action_indication()
        if action_key is None:
            return
        buttons = self._action_key_to_buttons.get(action_key, [])
        if not buttons:
            return
        self._active_action_buttons = list(buttons)
        self._pulse_phase = 0
        self._do_pulse()

    def _do_pulse(self):
        """Один такт пульсации: переключает фон между фазами."""
        if not self._active_action_buttons:
            return
        color = self._ACTION_PULSE_COLORS[self._pulse_phase % len(self._ACTION_PULSE_COLORS)]
        for btn in self._active_action_buttons:
            try:
                btn.configure(
                    bg=color,
                    highlightbackground=self._ACTION_PULSE_BORDER,
                    highlightthickness=2,
                    relief=tk.SUNKEN,
                )
            except Exception:
                pass
        self._pulse_phase += 1
        try:
            self._pulse_after_id = self.after(self._PULSE_INTERVAL_MS, self._do_pulse)
        except Exception:
            pass

    def _stop_action_indication(self):
        """Останавливает пульсацию и сбрасывает стиль кнопок."""
        if self._pulse_after_id is not None:
            try:
                self.after_cancel(self._pulse_after_id)
            except Exception:
                pass
            self._pulse_after_id = None
        for btn in self._active_action_buttons:
            self._reset_btn_style(btn)
        self._active_action_buttons = []

    # ─── Применение DNS к одному или ко всем подходящим адаптерам ─────────

    def _get_dns_target_adapters(self):
        """Возвращает список имён адаптеров, к которым нужно применить DNS.

        Учитывает настройку «Применять выбранный DNS ко всем найденным
        адаптерам». Текущий выбранный адаптер всегда первый в списке —
        результат операции на нём считается основным результатом.
        """
        primary = self.current_adapter
        if not self.settings.get("apply_to_all_adapters", False):
            return [primary] if primary else []

        suitable = filter_suitable_adapters(self.adapters or [])
        names = [a["name"] for a in suitable]

        ordered = []
        if primary and primary in names:
            ordered.append(primary)
            ordered.extend(n for n in names if n != primary)
        elif primary:
            # Текущий выбран, но не прошёл фильтр (например, пользователь
            # выбрал его руками). Всё равно ставим его первым — это основной
            # адаптер, на котором отслеживаем результат.
            ordered.append(primary)
            ordered.extend(names)
        else:
            ordered.extend(names)

        # Дедупликация с сохранением порядка
        seen = set()
        result = []
        for n in ordered:
            if n and n not in seen:
                seen.add(n)
                result.append(n)
        return result

    def _ensure_adapter_binding(self):
        """Перед операцией с DNS проверяет актуальность current_adapter.

        Перепривязывается, если:
          - адаптер не задан или исчез из списка Up;
          - адаптер на месте, но не имеет рабочей сети, при этом интернет
            в системе доступен через другой адаптер с активным default-маршрутом.

        Явный выбор пользователя сохраняется, пока выбранный адаптер реально
        работает. Это страхует от ситуации, когда после серии переключений
        приложение пытается применить DNS к мёртвому адаптеру и получает
        ошибку netsh.
        """
        try:
            adapters = get_network_adapters()
        except Exception:
            return
        if not adapters:
            return
        self.adapters = adapters
        adapter_names = [a["name"] for a in adapters]

        new_adapter = None
        if not self.current_adapter or self.current_adapter not in adapter_names:
            new_adapter = select_best_adapter(adapters)
        else:
            active = get_active_internet_adapter(adapters)
            if active and active != self.current_adapter:
                # Default-маршрут идёт через другой адаптер. Переключаемся
                # ТОЛЬКО если текущий не обслуживает сеть — иначе уважаем
                # явный выбор пользователя.
                net = check_network_ready(self.current_adapter)
                if net["state"] != NETWORK_READY:
                    new_adapter = active

        if new_adapter and new_adapter != self.current_adapter:
            old = self.current_adapter
            self.current_adapter = new_adapter
            self.settings["selected_adapter"] = new_adapter
            save_settings(self.settings)
            if self.health_monitor.is_running():
                self.health_monitor.reset_attempts()
            app_logger.warn(
                f"Перепривязка перед операцией: '{old}' → '{new_adapter}'"
            )
            try:
                self.after(0, self._populate_adapters)
            except Exception:
                pass

    def _apply_dns_set(self, primary, secondary):
        """Применяет статический DNS к выбранному адаптеру (и опционально
        ко всем подходящим). Возвращает результат для основного адаптера —
        чтобы существующая логика, проверяющая result["success"], не менялась.
        """
        self._ensure_adapter_binding()
        targets = self._get_dns_target_adapters()
        if not targets:
            return {"success": False, "error": "Нет адаптера для применения DNS"}

        primary_result = set_dns(targets[0], primary, secondary)

        if self.settings.get("apply_to_all_adapters", False) and len(targets) > 1:
            for name in targets[1:]:
                r = set_dns(name, primary, secondary)
                if r.get("success"):
                    app_logger.info(f"DNS применён также на адаптер '{name}': {primary}" + (f", {secondary}" if secondary else ""))
                else:
                    app_logger.warn(f"Не удалось применить DNS на адаптер '{name}': {r.get('error')}")
        return primary_result

    def _apply_dns_reset(self):
        """Сбрасывает DNS на DHCP для выбранного адаптера (и опционально для
        всех подходящих). Возвращает результат основного адаптера."""
        self._ensure_adapter_binding()
        targets = self._get_dns_target_adapters()
        if not targets:
            return {"success": False, "error": "Нет адаптера для сброса DNS"}

        primary_result = reset_dns(targets[0])

        if self.settings.get("apply_to_all_adapters", False) and len(targets) > 1:
            for name in targets[1:]:
                r = reset_dns(name)
                if r.get("success"):
                    app_logger.info(f"DNS сброшен также на адаптер '{name}'")
                else:
                    app_logger.warn(f"Не удалось сбросить DNS на адаптер '{name}': {r.get('error')}")
        return primary_result

    def _action_sync_all_adapters(self):
        """Синхронизация: применить текущий выбранный DNS-режим ко всем
        подходящим адаптерам. Используется при включении настройки и при
        появлении нового подходящего адаптера во время активного режима.
        """
        if not self.settings.get("apply_to_all_adapters", False):
            return
        if not self._has_selected_dns_mode():
            return
        if not self.current_adapter:
            return

        suitable = filter_suitable_adapters(self.adapters or [])
        extra = [a["name"] for a in suitable if a["name"] != self.current_adapter]
        if not extra:
            return

        if self.desired_mode == "standard":
            for name in extra:
                r = reset_dns(name)
                if r.get("success"):
                    app_logger.info(f"Синхронизация: DNS сброшен на адаптер '{name}'")
                else:
                    app_logger.warn(f"Синхронизация: не удалось сбросить DNS на '{name}': {r.get('error')}")
            return

        target_profile = self._get_desired_profile()
        if target_profile is None:
            return

        primary = target_profile.get("primary")
        secondary = target_profile.get("secondary")
        if target_profile.get("type") == "geohide":
            ips = list(self.geohide_known_ips) if self.geohide_known_ips else list(GEOHIDE_FALLBACK_IPS)
            primary = ips[0] if ips else primary
            secondary = ips[1] if len(ips) > 1 else secondary

        if not primary:
            return

        for name in extra:
            r = set_dns(name, primary, secondary)
            if r.get("success"):
                app_logger.info(f"Синхронизация: DNS применён на адаптер '{name}': {primary}" + (f", {secondary}" if secondary else ""))
            else:
                app_logger.warn(f"Синхронизация: не удалось применить DNS на '{name}': {r.get('error')}")

    # ─── Начальное обновление ─────────────────────────────────────────────

    def _initial_refresh(self):
        self._run_action(self._action_initial, "initial")

    def _action_initial(self):
        # Флаг: требуются права, но их нет — продолжаем в read-only
        require_admin_no_rights = self.settings.get("require_admin", False) and not is_admin()
        if require_admin_no_rights:
            app_logger.warn("Приложение требует права администратора, но запущено без них")

        self._set_operation_step("Определение адаптера...")

        # После загрузки Windows адаптер может быть ещё не готов.
        # Пробуем несколько раз с нарастающей задержкой (до ~30 сек суммарно).
        STARTUP_RETRY_DELAYS = [0, 2, 3, 5, 5, 5, 5, 5]  # секунды между попытками
        saved_adapter = self.settings.get("selected_adapter")

        for attempt_i, delay in enumerate(STARTUP_RETRY_DELAYS):
            if delay > 0:
                self._set_operation_step(
                    f"Ожидание сетевого адаптера... (попытка {attempt_i + 1})"
                )
                time.sleep(delay)

            self.adapters = get_network_adapters()
            adapter_names = [a["name"] for a in self.adapters]

            if saved_adapter and saved_adapter in adapter_names:
                self.current_adapter = saved_adapter
                if attempt_i > 0:
                    app_logger.info(f"Адаптер найден после ожидания ({attempt_i + 1} попытка): {saved_adapter}")
                else:
                    app_logger.info(f"Восстановлен сохранённый адаптер: {saved_adapter}")
                break
            elif adapter_names:
                # Сохранённый адаптер не найден, но есть другие
                if saved_adapter:
                    # Подождём ещё — возможно нужный адаптер ещё не инициализировался
                    if attempt_i < len(STARTUP_RETRY_DELAYS) - 1:
                        continue
                    app_logger.warn(f"Сохранённый адаптер '{saved_adapter}' не найден, выбран автоматически")
                self.current_adapter = select_best_adapter(self.adapters)
                if saved_adapter and saved_adapter not in adapter_names:
                    self.settings["selected_adapter"] = self.current_adapter
                    save_settings(self.settings)
                break
            # Адаптеров нет — продолжаем ожидание
        else:
            # Все попытки исчерпаны
            self.current_adapter = select_best_adapter(self.adapters)
            if not self.current_adapter and saved_adapter:
                self.settings["selected_adapter"] = None
                save_settings(self.settings)

        self.after(0, self._populate_adapters)

        if self.current_adapter:
            app_logger.info(f"Активный адаптер: {self.current_adapter}")
        else:
            app_logger.warn("Не найден ни один активный адаптер")

        self._set_operation_step("Чтение текущего состояния DNS...")
        self._do_refresh_state()

        # Синхронизация чекбокса автозапуска с реальным состоянием
        actual_autostart = get_autostart_enabled() or get_admin_task_exists()
        if actual_autostart != self.settings.get("autostart", False):
            self.settings["autostart"] = actual_autostart
            save_settings(self.settings)
            self.after(0, lambda: self.var_autostart.set(actual_autostart))

        # Синхронизация чекбокса автозапуска с правами
        actual_admin_task = get_admin_task_exists()
        if actual_admin_task != self.settings.get("autostart_admin", False):
            self.settings["autostart_admin"] = actual_admin_task
            save_settings(self.settings)
            self.after(0, lambda: self.var_autostart_admin.set(actual_admin_task))

        # ── Логика отложенной видимости ──
        should_hide = self._start_hidden_requested

        # Сценарий 0: require_admin без прав — окно ВСЕГДА видно
        if require_admin_no_rights:
            should_hide = False

        # Сценарий 1: автозапуск, нет прав, выбран DNS-режим — целевой режим
        need_admin_prompt = False
        if self._is_autostart and not is_admin():
            if self._has_selected_dns_mode():
                should_hide = False
                app_logger.warn("Автозапуск без прав администратора при активном выбранном DNS")
                if self.settings.get("autostart_show_admin_prompt", False):
                    need_admin_prompt = True

        # Сценарий 2: ручной запуск — окно ВСЕГДА видно
        if not self._is_autostart:
            should_hide = False

        if should_hide:
            self.after(0, self.withdraw)
            app_logger.info("Запуск в свёрнутом режиме (трей)")
        else:
            self.after(0, self.deiconify)

        # Показ окна запроса прав: require_admin или autostart admin prompt
        if require_admin_no_rights:
            self.after(500, self._show_require_admin_window)
        elif need_admin_prompt:
            self.after(500, self._show_admin_prompt_window)

        # Запуск мониторинга, если выбран DNS-режим — целевой режим
        if self._has_selected_dns_mode() and not self._external_change_pending:
            if not self.current_adapter:
                # Адаптер ещё не найден — запускаем мониторинг, он попробует обнаружить адаптер сам
                app_logger.info("Адаптер не найден, мониторинг запущен в режиме ожидания адаптера")
                if is_admin():
                    self.health_monitor.start()
                else:
                    app_logger.warn("Мониторинг DNS не запущен: нет прав администратора")
                    self._set_operation_step(
                        "Мониторинг DNS недоступен без прав администратора", is_error=True
                    )
                    return
            elif is_admin():
                self.health_monitor.start()
            else:
                app_logger.warn("Мониторинг DNS не запущен: нет прав администратора")
                self._set_operation_step(
                    "Мониторинг DNS недоступен без прав администратора", is_error=True
                )
                return  # Не очищаем статус операции — ошибка должна быть видна

        # Событийная подписка на смену сети — мгновенная реакция без ожидания
        # следующего тика мониторинга. Запускается всегда, независимо от
        # выбранного DNS-режима и прав, так как сама по себе только читает.
        try:
            self.network_watcher.start()
        except Exception as e:
            app_logger.warn(f"Не удалось запустить подписку на изменения сети: {e}")

        self._clear_operation_delayed(2)

    def _populate_adapters(self):
        items = []
        sel_index = 0
        for i, a in enumerate(self.adapters):
            label = f"{a['name']} — {a['description']}"
            items.append(label)
            if a["name"] == self.current_adapter:
                sel_index = i
        self.combo_adapter["values"] = items
        if items:
            self.combo_adapter.current(sel_index)

    # ─── Действие: обновить ───────────────────────────────────────────────

    def _action_refresh(self):
        self._set_operation_step("Обновление состояния...")
        app_logger.info("Обновление состояния")
        self.adapters = get_network_adapters()
        self.after(0, self._populate_adapters)

        adapter_names = [a["name"] for a in self.adapters]
        if self.current_adapter and self.current_adapter not in adapter_names:
            old = self.current_adapter
            self.current_adapter = select_best_adapter(self.adapters)
            self.settings["selected_adapter"] = self.current_adapter
            save_settings(self.settings)
            app_logger.warn(f"Адаптер '{old}' недоступен, переключён на '{self.current_adapter}'")

        # Ручной refresh — это явный сигнал «начни мониторинг с чистого листа».
        # Сбрасываем залипшие счётчики (_consecutive_net_failures, _network_waiting,
        # recovery_attempts), чтобы после серии переключений сетей и зависания
        # в «нет сети» одна кнопка «Обновить состояние» приводила приложение
        # в рабочее состояние без перезапуска.
        self.health_monitor.reset_attempts()

        self._do_refresh_state()

        # Запуск мониторинга при появлении адаптера (если выбран DNS-режим активен)
        if self._has_selected_dns_mode() and self.current_adapter and is_admin():
            if not self.health_monitor.is_running() and not self._external_change_pending:
                self.health_monitor.start()

        # Если включён режим «применять ко всем адаптерам» и активен выбранный
        # DNS — синхронизируем состояние со всеми подходящими адаптерами
        # (важно при появлении нового адаптера во время работы приложения).
        if (self.settings.get("apply_to_all_adapters", False)
                and self._has_selected_dns_mode()
                and self.current_adapter
                and is_admin()):
            self._action_sync_all_adapters()

        self._clear_operation_delayed(2)

    def _refresh_state_safe(self):
        """Безопасный вызов обновления состояния из любого потока."""
        self._run_action(self._action_refresh)

    def _on_network_change(self):
        """Колбэк из потока NetworkChangeWatcher (Win32 NotifyAddrChange).

        Дебаунсит вызовы: при пакете изменений (DHCP renew → IP сменился →
        gateway сменился — три подряд события за миллисекунды) запланирует
        ровно один обработчик через 800 мс.
        """
        try:
            if self._net_change_after_id is not None:
                try:
                    self.after_cancel(self._net_change_after_id)
                except Exception:
                    pass
            self._net_change_after_id = self.after(800, self._handle_network_change)
        except Exception:
            pass

    def _handle_network_change(self):
        """Реакция на смену сети — выполняется в Tk-потоке после дебаунса."""
        self._net_change_after_id = None
        if self._exiting:
            return
        app_logger.info("Изменение сети обнаружено (NotifyAddrChange)")
        # Сбрасываем залипшие счётчики мониторинга — старые накопленные
        # неудачи относились к прошлой сетевой среде.
        try:
            self.health_monitor.reset_attempts()
        except Exception:
            pass
        # Полный пересчёт состояния: список адаптеров, привязка, DNS, проверка.
        # _action_refresh внутри уже умеет рекомендовать новый адаптер через
        # обновлённый select_best_adapter (default route + active internet).
        try:
            self._refresh_state_safe()
        except Exception:
            pass

    def _do_refresh_state(self):
        if not self.current_adapter:
            self.after(0, lambda: self._update_status(
                adapter="Не найден",
                dns="—",
                actual_mode_display="Не определён",
                actual_profile_id=None,
                desired_mode_text="—",
                check="—",
            ))
            return

        # Всегда читаем фактическое состояние из системы
        dns_info = get_current_dns(self.current_adapter)
        dns_servers = dns_info["servers"]

        # DNS, выданные DHCP-сервером (даже если сейчас стоит статический override).
        # Используется для подписи на кнопке «Стандартный DNS», чтобы пользователь
        # видел, к каким адресам он вернётся при клике.
        dhcp_offered = get_dhcp_offered_dns(self.current_adapter)

        if dns_info["is_dhcp"]:
            dns_text = "Стандартный DNS (DHCP)" if not dns_servers else f"DHCP ({', '.join(dns_servers)})"
        elif dns_servers:
            dns_text = ", ".join(dns_servers)
        else:
            dns_text = "Нет данных"

        actual_profile_id, actual_mode_display = detect_dns_mode(
            dns_servers, self.geohide_known_ips, dns_info.get("is_dhcp", False),
            dns_profiles=self._dns_profiles
        )

        net = check_network_ready(self.current_adapter)
        if net["state"] == NETWORK_NO_CONNECTION:
            reason = net.get("reason", "")
            if reason == "no_ip":
                check_text = "Сеть не подключена (нет IP-адреса)"
            elif reason == "no_gateway":
                check_text = "Сеть не подключена (нет шлюза)"
            else:
                check_text = "Сеть не подключена"
        elif net["state"] == NETWORK_UNSTABLE:
            check_text = f"Сеть нестабильна (шлюз {net.get('gateway', '?')} недоступен)"
        else:
            verify = verify_dns_working()
            if verify["working"]:
                check_text = f"DNS работает ({verify['resolved_ip']})"
            else:
                check_text = "Сеть подключена, DNS не отвечает"

        now = datetime.now().strftime("%H:%M:%S")

        # Целевой режим
        desired_mode_text = get_desired_mode_label(self.desired_mode, self._dns_profiles)

        # Логирование расхождений
        if self.desired_mode:
            mode_matches = (actual_profile_id == self.desired_mode)
            if not mode_matches:
                app_logger.warn(f"Расхождение: целевой={desired_mode_text}, фактический={actual_mode_display}")

        self.after(0, lambda: self._update_status(
            adapter=self.current_adapter,
            dns=dns_text,
            actual_mode_display=actual_mode_display,
            actual_profile_id=actual_profile_id,
            desired_mode_text=desired_mode_text,
            check=check_text,
            time=now,
            dhcp_offered=dhcp_offered,
        ))

    def _update_status(self, adapter="—", dns="—", actual_mode_display="—",
                       actual_profile_id=None, desired_mode_text="—",
                       check="—", time=None, dhcp_offered=None):
        self.lbl_adapter.configure(text=f"Адаптер: {adapter}")
        self.lbl_dns.configure(text=f"DNS: {dns}")

        # Два поля: фактический и целевой режим
        self.lbl_mode_actual.configure(text=f"Фактический режим: {actual_mode_display}")
        self.lbl_mode_desired.configure(text=f"Целевой режим: {desired_mode_text}")

        # Подсветка расхождения и случая «DNS системы не соответствует ни одной кнопке».
        # Второй случай важен для первого запуска: если у пользователя в системе стоит
        # DNS, который не попадает ни в один профиль кнопок, желаемый режим ещё не
        # задан, и без явной индикации это выглядело бы как обычное «Не задан».
        no_button_match = (
            actual_profile_id is None
            and actual_mode_display not in ("—", "Не определён")
        )
        if desired_mode_text != "Не задан" and actual_mode_display != "—":
            matches = (actual_profile_id == self.desired_mode)
            if not matches:
                self.lbl_mode_desired.configure(foreground="#e65100")
                self.lbl_mode_actual.configure(foreground="#e65100")
            else:
                self.lbl_mode_desired.configure(foreground="#333")
                self.lbl_mode_actual.configure(foreground="#333")
        elif no_button_match:
            # Желаемый режим ещё не выбран, но текущий системный DNS не подходит
            # ни к одной кнопке — подсвечиваем оранжевым, чтобы было заметно.
            self.lbl_mode_desired.configure(foreground="#888")
            self.lbl_mode_actual.configure(foreground="#e65100")
        else:
            self.lbl_mode_desired.configure(foreground="#888")
            self.lbl_mode_actual.configure(foreground="#333")

        self.lbl_check.configure(text=f"Проверка: {check}")
        if time:
            self.lbl_time.configure(text=f"Обновлено: {time}")

        if "работает" in check:
            self.lbl_check.configure(foreground="#2a7d2a")
        elif "не подключена" in check or "нестабильна" in check:
            self.lbl_check.configure(foreground="#e65100")
        elif "не отвечает" in check or "Проблема" in check:
            self.lbl_check.configure(foreground="#c0392b")
        else:
            self.lbl_check.configure(foreground="#333")

        # Обновление строки мониторинга
        self._update_monitor_label()

        # Сохранение текущего фактического режима
        self._current_actual_mode = actual_mode_display
        self._current_actual_profile_id = actual_profile_id

        # Динамическая верхняя приоритетная кнопка
        self._update_quick_priority_button()

        # Обновление визуальной индикации активного DNS-режима
        self._update_active_mode_buttons()

        # Подпись на кнопке «Стандартный DNS»: показываем DHCP-выданные адреса
        self._update_standard_button_text(dhcp_offered)

    def _update_standard_button_text(self, dhcp_offered):
        """Обновляет подпись кнопки «Стандартный DNS»: добавляет DHCP-выданные DNS."""
        if dhcp_offered:
            ips_text = ", ".join(dhcp_offered)
            text = f"Стандартный DNS ({ips_text})"
        else:
            text = "Стандартный DNS"
        try:
            self.btn_standard.configure(text=text)
        except Exception:
            pass

    # ─── Действие: применение geohide-профиля (динамический резолв) ──────

    def _action_geohide(self, profile=None):
        if not self.current_adapter:
            app_logger.error("Нет выбранного адаптера")
            return

        # Профиль может быть передан явно (из приоритетной кнопки или
        # обычной кнопки сетки), либо найден по типу как fallback —
        # для вызовов без контекста (мониторинг, диалог внешнего изменения).
        if profile is None:
            profile = self._find_geohide_profile()
        if profile is None:
            app_logger.error("В списке нет ни одного DNS-профиля типа geohide")
            self._set_operation_step(
                "Завершено с ошибкой: нет geohide-профиля в списке", is_error=True
            )
            return
        target_profile_id = profile["id"]
        profile_name = profile["name"]

        app_logger.info(f"Включение {profile_name} DNS")

        self._set_operation_step("Проверка прав администратора...")
        # Не блокируем, но предупреждаем

        self._set_operation_step("Получение IP для dns.geohide.ru...")
        ips, used_fallback = resolve_geohide()
        if used_fallback:
            app_logger.warn("Использованы резервные IP GeoHide")
        else:
            self.geohide_known_ips = list(ips)
            self.settings["geohide_resolved_ips"] = self.geohide_known_ips
            save_settings(self.settings)

        primary = ips[0] if ips else GEOHIDE_FALLBACK_IPS[0]
        secondary = ips[1] if len(ips) > 1 else (GEOHIDE_FALLBACK_IPS[1] if len(GEOHIDE_FALLBACK_IPS) > 1 else None)

        self._set_operation_step(f"Применение {profile_name} DNS...")
        result = self._apply_dns_set(primary, secondary)

        if not result["success"]:
            if result.get("access_denied"):
                app_logger.error(result["error"])
                self._set_operation_step("Завершено с ошибкой: нет прав администратора", is_error=True)
                self.after(0, lambda: self._show_access_error(result["error"]))
            else:
                app_logger.error(f"Ошибка применения {profile_name}: {result['error']}")
                self._set_operation_step(f"Завершено с ошибкой: {result['error']}", is_error=True)
            self._do_refresh_state()
            return

        app_logger.info(f"{profile_name} DNS применён: {primary}" + (f", {secondary}" if secondary else ""))
        flush_dns_cache()

        self._set_operation_step("Контрольная проверка DNS...")
        # Пауза «осесть» — Windows иногда возвращает старое состояние, если
        # читать DNS сразу после netsh-set. См. DNS_APPLY_SETTLE_DELAY.
        time.sleep(DNS_APPLY_SETTLE_DELAY)

        self._set_desired_mode(target_profile_id)

        self._set_operation_step("Обновление состояния интерфейса...")
        self._do_refresh_state()

        dns_info = get_current_dns(self.current_adapter)
        actual_set = set(dns_info["servers"])
        expected_set = set(ips[:2])

        if actual_set != expected_set and actual_set:
            app_logger.warn(f"DNS применены частично. Ожидалось: {expected_set}, фактически: {actual_set}")
            self._set_operation_step("Завершено: DNS применены частично", is_error=True)
        elif not dns_info["servers"]:
            app_logger.error("DNS не были применены — адаптер показывает пустые DNS")
            self._set_operation_step("Завершено с ошибкой: DNS не применены", is_error=True)
        else:
            app_logger.info(f"{profile_name}: DNS успешно подтверждены")
            self._set_operation_step("Завершено успешно", is_success=True)

        self._clear_operation_delayed(3)

        # Запуск мониторинга и сброс счётчика
        self.health_monitor.reset_attempts()
        if is_admin():
            self.health_monitor.start()
        else:
            app_logger.warn("Мониторинг DNS не запущен: нет прав администратора")

    # ─── Действие: применение статического DNS-профиля ────────────────────

    def _action_apply_profile(self, profile):
        """Универсальное применение статического DNS-профиля."""
        if not self.current_adapter:
            app_logger.error("Нет выбранного адаптера")
            return

        self.health_monitor.stop()

        name = profile["name"]
        primary = profile["primary"]
        secondary = profile.get("secondary")

        app_logger.info(f"Включение {name} DNS")
        self._set_operation_step(f"Применение {name} DNS...")

        result = self._apply_dns_set(primary, secondary)

        if not result["success"]:
            if result.get("access_denied"):
                app_logger.error(result["error"])
                self._set_operation_step("Завершено с ошибкой: нет прав администратора", is_error=True)
                self.after(0, lambda: self._show_access_error(result["error"]))
            else:
                app_logger.error(f"Ошибка: {result['error']}")
                self._set_operation_step(f"Завершено с ошибкой: {result['error']}", is_error=True)
            self._do_refresh_state()
            return

        self._set_desired_mode(profile["id"])
        dns_str = primary + (f", {secondary}" if secondary else "")
        app_logger.info(f"{name} DNS применён: {dns_str}")
        flush_dns_cache()

        self._set_operation_step("Контрольная проверка DNS...")
        time.sleep(DNS_APPLY_SETTLE_DELAY)  # см. DNS_APPLY_SETTLE_DELAY
        self._do_refresh_state()
        self._set_operation_step("Завершено успешно", is_success=True)
        self._clear_operation_delayed(3)

        # Запуск мониторинга и сброс счётчика для выбранного DNS-профиля
        self.health_monitor.reset_attempts()
        if is_admin():
            self.health_monitor.start()
        else:
            app_logger.warn("Мониторинг DNS не запущен: нет прав администратора")

    # ─── Действие: Стандартный DNS (системные настройки) ───────────────────

    def _action_standard(self):
        if not self.current_adapter:
            app_logger.error("Нет выбранного адаптера")
            return

        self.health_monitor.stop()

        app_logger.info("Сброс к стандартному DNS")
        self._set_operation_step("Стандартный DNS: системные настройки (DHCP)...")

        result = self._apply_dns_reset()

        if not result["success"]:
            if result.get("access_denied"):
                app_logger.error(result["error"])
                self._set_operation_step("Завершено с ошибкой: нет прав администратора", is_error=True)
                self.after(0, lambda: self._show_access_error(result["error"]))
            else:
                app_logger.error(f"Ошибка: {result['error']}")
                self._set_operation_step(f"Завершено с ошибкой: {result['error']}", is_error=True)
            self._do_refresh_state()
            return

        self._set_desired_mode("standard")
        app_logger.info("DNS сброшен на стандартный (DHCP)")
        flush_dns_cache()

        self._set_operation_step("Контрольная проверка DNS...")
        time.sleep(DNS_APPLY_SETTLE_DELAY)  # см. DNS_APPLY_SETTLE_DELAY
        self._do_refresh_state()
        self._set_operation_step("Завершено успешно", is_success=True)
        self._clear_operation_delayed(3)

        # Запуск мониторинга и сброс счётчика для выбранного DNS-режима
        self.health_monitor.reset_attempts()
        if is_admin():
            self.health_monitor.start()
        else:
            app_logger.warn("Мониторинг DNS не запущен: нет прав администратора")

    # ─── Действие: полное обновление geohide-профиля ─────────────────────

    def _action_update_geohide(self, profile=None):
        if not self.current_adapter:
            app_logger.error("Нет выбранного адаптера")
            return

        # Аналогично _action_geohide: либо профиль передан явно, либо
        # ищется как первый профиль типа geohide. id больше не зашит.
        if profile is None:
            profile = self._find_geohide_profile()
        if profile is None:
            app_logger.error("В списке нет ни одного DNS-профиля типа geohide")
            self._set_operation_step(
                "Завершено с ошибкой: нет geohide-профиля в списке", is_error=True
            )
            return
        target_profile_id = profile["id"]
        profile_name = profile["name"]

        app_logger.info(f"Обновление {profile_name}: полный цикл")

        # Шаг 1: Сброс DNS
        self._set_operation_step(f"Обновление {profile_name}: сброс к стандартному DNS...")
        result = self._apply_dns_reset()
        if not result["success"]:
            if result.get("access_denied"):
                app_logger.error(result["error"])
                self._set_operation_step("Завершено с ошибкой: нет прав администратора", is_error=True)
                self.after(0, lambda: self._show_access_error(result["error"]))
            else:
                app_logger.error(f"Ошибка сброса DNS: {result['error']}")
                self._set_operation_step(f"Завершено с ошибкой: {result['error']}", is_error=True)
            self._do_refresh_state()
            return

        app_logger.info(f"DNS сброшен для обновления {profile_name}")
        flush_dns_cache()

        # Шаг 2: Ожидание интернета (прерываемое)
        self._set_operation_step(f"Обновление {profile_name}: ожидание появления интернета...")
        internet_ok = False
        elapsed = 0
        while elapsed < INTERNET_WAIT_TIMEOUT:
            self._action_stop_event.wait(INTERNET_WAIT_INTERVAL)
            if self._action_stop_event.is_set():
                app_logger.info(f"Обновление {profile_name} прервано (завершение приложения)")
                return
            elapsed += INTERNET_WAIT_INTERVAL
            check = verify_dns_working()
            if check["working"]:
                internet_ok = True
                break
            self._set_operation_step(
                f"Обновление {profile_name}: ожидание появления интернета ({elapsed} сек)..."
            )

        if not internet_ok:
            app_logger.error(f"Интернет не появился за {INTERNET_WAIT_TIMEOUT} сек")
            self._set_operation_step(
                f"Завершено с ошибкой: интернет не появился за {INTERNET_WAIT_TIMEOUT} сек",
                is_error=True
            )
            self._do_refresh_state()
            return

        app_logger.info(f"Интернет восстановлен, продолжаем обновление {profile_name}")

        # Шаг 3: Получение IP
        self._set_operation_step(f"Обновление {profile_name}: получение IP для {GEOHIDE_DOMAIN}...")
        ips, used_fallback = resolve_geohide()
        if not used_fallback:
            self.geohide_known_ips = list(ips)
            self.settings["geohide_resolved_ips"] = self.geohide_known_ips
            save_settings(self.settings)

        primary = ips[0] if ips else GEOHIDE_FALLBACK_IPS[0]
        secondary = ips[1] if len(ips) > 1 else (GEOHIDE_FALLBACK_IPS[1] if len(GEOHIDE_FALLBACK_IPS) > 1 else None)

        # Шаг 4: Применение
        self._set_operation_step(f"Обновление {profile_name}: применение DNS...")
        result = self._apply_dns_set(primary, secondary)
        if not result["success"]:
            if result.get("access_denied"):
                app_logger.error(result["error"])
                self._set_operation_step("Завершено с ошибкой: нет прав администратора", is_error=True)
                self.after(0, lambda: self._show_access_error(result["error"]))
            else:
                app_logger.error(f"Ошибка применения {profile_name}: {result['error']}")
                self._set_operation_step(f"Завершено с ошибкой: {result['error']}", is_error=True)
            self._do_refresh_state()
            return

        app_logger.info(f"{profile_name} DNS обновлён: {primary}" + (f", {secondary}" if secondary else ""))
        flush_dns_cache()

        # Шаг 5: Контрольная проверка
        self._set_operation_step(f"Обновление {profile_name}: контрольная проверка DNS...")
        time.sleep(DNS_APPLY_SETTLE_DELAY)  # см. DNS_APPLY_SETTLE_DELAY

        self._set_desired_mode(target_profile_id)

        verify = verify_dns_working()
        if verify["working"]:
            app_logger.info(f"{profile_name} обновлён и работает")
            self._set_operation_step("Завершено успешно", is_success=True)
        else:
            app_logger.warn(f"{profile_name} обновлён, но DNS пока не отвечает: {verify.get('error')}")
            self._set_operation_step(f"{profile_name} обновлён, но DNS пока не отвечает", is_error=True)

        # Шаг 6: Обновление состояния интерфейса
        self._do_refresh_state()
        self._clear_operation_delayed(5)

        # Перезапуск мониторинга
        self.health_monitor.reset_attempts()
        if is_admin():
            self.health_monitor.start()

    # ─── Внешнее изменение DNS ───────────────────────────────────────────

    def _show_external_dns_change_dialog(self):
        """Показывает диалог при обнаружении внешнего изменения DNS."""
        profile_name = get_desired_mode_label(self.desired_mode, self._dns_profiles)
        if profile_name in ("Не задан", None):
            profile_name = "Выбранный DNS"
        self._show_window()
        dialog = tk.Toplevel(self)
        dialog.title(APP_NAME)
        dialog.geometry("520x220")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg="#f5f5f5")

        ttk.Label(
            dialog,
            text="DNS был изменён не через DNS Manager.\n\n"
                 f"Фоновый контроль {profile_name} остановлен.\n"
                 "Выберите дальнейшее действие:",
            font=("Segoe UI", 10), justify=tk.LEFT, wraplength=480, background="#f5f5f5"
        ).pack(padx=20, pady=(20, 15), anchor=tk.W)

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=20, pady=(0, 15))

        def _restore_selected_dns():
            self._external_change_pending = False
            dialog.destroy()
            self._run_action(self._action_restore_selected_dns)

        def _accept_change():
            self._external_change_pending = False
            dialog.destroy()
            self._set_desired_mode(None)
            self._refresh_state_safe()
            app_logger.info("Внешнее изменение DNS принято пользователем")

        def _quit_app():
            self._external_change_pending = False
            dialog.destroy()
            self._do_quit()

        def _always_auto_restore():
            self._external_change_pending = False
            self.settings["external_dns_change_mode"] = "auto_restore"
            save_settings(self.settings)
            self.var_external_dns_change_mode.set("auto_restore")
            app_logger.info(f"Режим реакции на внешнее изменение DNS: автоматический возврат {profile_name} (выбрано из диалога)")
            dialog.destroy()
            self._run_action(self._action_restore_selected_dns)

        dialog.protocol("WM_DELETE_WINDOW", _accept_change)

        ttk.Button(btn_frame, text=f"Вернуть {profile_name}", command=_restore_selected_dns).pack(
            side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True
        )
        ttk.Button(btn_frame, text="Принять изменение", command=_accept_change).pack(
            side=tk.LEFT, padx=5, fill=tk.X, expand=True
        )
        ttk.Button(btn_frame, text="Закрыть приложение", command=_quit_app).pack(
            side=tk.LEFT, padx=(5, 0), fill=tk.X, expand=True
        )

        btn_frame2 = ttk.Frame(dialog)
        btn_frame2.pack(fill=tk.X, padx=20, pady=(0, 15))
        ttk.Button(btn_frame2, text=f"Всегда автоматически возвращать {profile_name}", command=_always_auto_restore).pack(
            fill=tk.X, expand=True
        )

        dialog.lift()
        dialog.focus_force()

    # ─── Настройка DNS-кнопок (модальное окно) ─────────────────────────

    def _open_dns_profiles_settings(self):
        """Открывает модальное окно настройки DNS-профилей."""
        dialog = tk.Toplevel(self)
        dialog.title("Настройка DNS-кнопок")
        dialog.geometry("940x580")
        dialog.minsize(900, 500)
        dialog.resizable(True, True)
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg="#f5f5f5")

        # Рабочая копия профилей
        work_profiles = [dict(p) for p in self._dns_profiles]
        work_bpr = tk.IntVar(value=self.settings.get("dns_buttons_per_row", DEFAULT_DNS_BUTTONS_PER_ROW))

        # Состояние «лаборатории тестирования DNS» (время отклика + доступность
        # домена). Результаты привязаны к id профиля, а не к индексу — чтобы
        # перестановка/редактирование строк не путали показания.
        test_results = {}        # profile_id -> (text, color)
        result_labels = {}       # profile_id -> ttk.Label (живёт между перестроениями)
        test_state = {"busy": False}
        var_test_domain = tk.StringVar(value=DNS_PROFILE_TEST_DOMAIN)

        # ── Кнопок в ряду ──
        bpr_frame = ttk.Frame(dialog)
        bpr_frame.pack(fill=tk.X, padx=15, pady=(12, 6))
        ttk.Label(bpr_frame, text="Кнопок в ряду:").pack(side=tk.LEFT)
        bpr_spin = ttk.Spinbox(bpr_frame, from_=1, to=5, width=4, textvariable=work_bpr)
        self._enable_entry_clipboard_shortcuts(bpr_spin)
        bpr_spin.pack(side=tk.LEFT, padx=(6, 0))

        # ── Панель проверки DNS: время отклика + откроется ли домен ──
        test_frame = ttk.Frame(dialog)
        test_frame.pack(fill=tk.X, padx=15, pady=(0, 4))
        ttk.Label(test_frame, text="Проверить домен:").pack(side=tk.LEFT)
        ent_test_domain = ttk.Entry(test_frame, textvariable=var_test_domain, width=22)
        self._enable_entry_clipboard_shortcuts(ent_test_domain)
        ent_test_domain.pack(side=tk.LEFT, padx=(6, 6))
        btn_test = ttk.Button(test_frame, text="Проверить")
        btn_test.pack(side=tk.LEFT)
        lbl_test_status = ttk.Label(test_frame, text="", foreground="#555", font=("Segoe UI", 9))
        lbl_test_status.pack(side=tk.LEFT, padx=(8, 0))

        # ── Список профилей ──
        list_outer = ttk.Frame(dialog)
        list_outer.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 6))

        canvas = tk.Canvas(list_outer, bg="white", highlightthickness=1, highlightbackground="#ccc")
        scrollbar = ttk.Scrollbar(list_outer, orient=tk.VERTICAL, command=canvas.yview)
        list_frame = ttk.Frame(canvas)

        list_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=list_frame, anchor="nw", tags="frame")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig("frame", width=e.width))

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tooltip_ref = {"win": None}

        def _hide_tooltip(_event=None):
            tw = tooltip_ref.get("win")
            if tw is not None:
                try:
                    tw.destroy()
                except tk.TclError:
                    pass
                tooltip_ref["win"] = None

        def _show_tooltip(event, text):
            _hide_tooltip()
            tw = tk.Toplevel(dialog)
            tw.wm_overrideredirect(True)
            tw.attributes("-topmost", True)
            tw.geometry(f"+{event.x_root + 14}+{event.y_root + 10}")
            ttk.Label(
                tw,
                text=text,
                background="#fffbdc",
                relief=tk.SOLID,
                borderwidth=1,
                padding=(6, 3),
                justify=tk.LEFT,
            ).pack()
            tooltip_ref["win"] = tw

        def _rebuild_list():
            for w in list_frame.winfo_children():
                w.destroy()
            result_labels.clear()  # старые виджеты уничтожены — ссылки больше не валидны
            bold = ("Segoe UI", 9, "bold")
            reg = ("Segoe UI", 9)

            # Единая grid-сетка для заголовка и строк — гарантирует ровные
            # колонки (раньше pack со side=LEFT/RIGHT «разъезжался», когда
            # блок кнопок менял ширину от строки к строке). Признак служебного
            # geohide-профиля — пометка ★, приоритетной (быстрой) кнопки — ⚡,
            # обе у названия, чтобы не ломать выравнивание блока кнопок.
            list_frame.columnconfigure(0, minsize=30)    # #
            list_frame.columnconfigure(1, minsize=170)   # Название
            list_frame.columnconfigure(2, minsize=135)   # Основной DNS
            list_frame.columnconfigure(3, minsize=135)   # Резервный DNS
            list_frame.columnconfigure(4, minsize=270, weight=1)  # Результат
            list_frame.columnconfigure(5, minsize=120)   # Кнопки

            # ── Заголовок ──
            ttk.Label(list_frame, text="#", font=bold).grid(row=0, column=0, sticky="w", padx=4, pady=(4, 2))
            ttk.Label(list_frame, text="Название", font=bold).grid(row=0, column=1, sticky="w", padx=4, pady=(4, 2))
            ttk.Label(list_frame, text="Основной DNS", font=bold).grid(row=0, column=2, sticky="w", padx=4, pady=(4, 2))
            ttk.Label(list_frame, text="Резервный DNS", font=bold).grid(row=0, column=3, sticky="w", padx=4, pady=(4, 2))
            ttk.Label(list_frame, text="Результат", font=bold).grid(row=0, column=4, sticky="w", padx=4, pady=(4, 2))

            for idx, profile in enumerate(work_profiles):
                r = idx + 1
                ttk.Label(list_frame, text=str(idx + 1), font=reg).grid(row=r, column=0, sticky="w", padx=4, pady=1)

                name_text = profile["name"]
                if profile.get("type") == "geohide":
                    name_text = "★ " + name_text
                if idx == 0:
                    name_text += "  ⚡"   # вынесен на быструю кнопку главного окна
                name_lbl = ttk.Label(list_frame, text=name_text, font=reg)
                name_lbl.grid(row=r, column=1, sticky="w", padx=4, pady=1)
                if profile.get("type") == "geohide":
                    name_lbl.bind(
                        "<Enter>",
                        lambda e: _show_tooltip(
                            e,
                            "Служебный профиль GeoHide: IP обновляется автоматически по dns.geohide.ru",
                        ),
                    )
                    name_lbl.bind("<Leave>", _hide_tooltip)
                elif idx == 0:
                    name_lbl.bind(
                        "<Enter>",
                        lambda e: _show_tooltip(e, "Профиль вынесен на быструю кнопку главного окна"),
                    )
                    name_lbl.bind("<Leave>", _hide_tooltip)

                ttk.Label(list_frame, text=profile.get("primary", ""), font=reg).grid(row=r, column=2, sticky="w", padx=4, pady=1)
                ttk.Label(list_frame, text=profile.get("secondary", ""), font=reg).grid(row=r, column=3, sticky="w", padx=4, pady=1)

                # Колонка результата теста (время отклика / доступность домена).
                pid = profile["id"]
                rtext, rcolor = test_results.get(pid, ("", "#555"))
                res_lbl = ttk.Label(list_frame, text=rtext, foreground=rcolor, font=reg)
                res_lbl.grid(row=r, column=4, sticky="w", padx=4, pady=1)
                result_labels[pid] = res_lbl

                # Блок кнопок: ровно 4 слота (▲ ▼ ✎ ✖); ненужные слоты —
                # пустые заглушки той же ширины, чтобы кнопки строк выровнялись.
                btn_box = ttk.Frame(list_frame)
                btn_box.grid(row=r, column=5, sticky="e", padx=4, pady=1)
                if idx > 0:
                    ttk.Button(btn_box, text="▲", width=2,
                               command=lambda i=idx: (_swap(i, i - 1), _rebuild_list())).grid(row=0, column=0, padx=1)
                else:
                    ttk.Label(btn_box, text="", width=2).grid(row=0, column=0, padx=1)
                if idx < len(work_profiles) - 1:
                    ttk.Button(btn_box, text="▼", width=2,
                               command=lambda i=idx: (_swap(i, i + 1), _rebuild_list())).grid(row=0, column=1, padx=1)
                else:
                    ttk.Label(btn_box, text="", width=2).grid(row=0, column=1, padx=1)
                ttk.Button(btn_box, text="✎", width=2,
                           command=lambda i=idx: _edit_profile(i)).grid(row=0, column=2, padx=1)
                if len(work_profiles) > 1:
                    ttk.Button(btn_box, text="✖", width=2,
                               command=lambda i=idx: (_delete(i), _rebuild_list())).grid(row=0, column=3, padx=1)
                else:
                    ttk.Label(btn_box, text="", width=2).grid(row=0, column=3, padx=1)

        def _swap(i, j):
            work_profiles[i], work_profiles[j] = work_profiles[j], work_profiles[i]

        def _delete(i):
            if len(work_profiles) > 1:
                work_profiles.pop(i)

        def _add_profile():
            _open_profile_editor(None)

        def _edit_profile(idx):
            _open_profile_editor(idx)

        def _open_profile_editor(idx):
            """Открывает редактор одного профиля (добавление или редактирование).

            Поддерживает два сценария ввода:
              1) Полностью ручной — пользователь сам вводит название, primary
                 и secondary DNS.
              2) Полуавтоматический — пользователь вводит ссылку или домен,
                 нажимает «Получить DNS по ссылке»; если попытка успешна, поля
                 primary/secondary заполняются автоматически. Их можно вручную
                 поправить перед сохранением. Профиль сохраняется только после
                 явного нажатия «Сохранить».
            """
            is_new = idx is None
            if is_new:
                p = {"id": "", "name": "", "type": "static", "primary": "", "secondary": ""}
            else:
                p = dict(work_profiles[idx])

            ed = tk.Toplevel(dialog)
            ed.title("Добавить профиль" if is_new else "Редактировать профиль")
            ed.geometry("640x520")
            ed.minsize(600, 500)
            ed.resizable(True, False)
            ed.transient(dialog)
            ed.grab_set()
            ed.configure(bg="#f5f5f5")

            def _default_source_url(profile):
                return _default_profile_field(profile, "source_url")

            def _default_fetch_url(profile):
                return _default_profile_field(profile, "fetch_url")

            def _default_profile_field(profile, field):
                pid = profile.get("id")
                if not pid:
                    return ""
                for default_profile in _get_default_dns_profiles():
                    if default_profile.get("id") == pid:
                        return default_profile.get(field, "")
                return ""

            var_name = tk.StringVar(value=p["name"])
            # Тип скрыт от пользователя как явное поле: «geohide» — служебный
            # (жёстко привязан к dns.geohide.ru и динамическому обновлению),
            # «static» — обычный. Новые профили всегда static. При
            # редактировании существующего geohide-профиля тип сохраняется
            # неизменным и показывается только как информационная пометка.
            existing_type = p.get("type", "static") or "static"
            var_source_url = tk.StringVar(value=p.get("source_url") or _default_source_url(p))
            var_link = tk.StringVar(value=p.get("fetch_url") or _default_fetch_url(p))
            var_primary = tk.StringVar(value=p.get("primary", ""))
            var_secondary = tk.StringVar(value=p.get("secondary", ""))

            fr = ttk.Frame(ed, padding=15)
            fr.pack(fill=tk.BOTH, expand=True)
            fr.columnconfigure(1, weight=1)

            grid_row = 0

            # ── Название ──
            ttk.Label(fr, text="Название:").grid(row=grid_row, column=0, sticky=tk.W, pady=4)
            ent_name = ttk.Entry(fr, textvariable=var_name, width=36)
            self._enable_entry_clipboard_shortcuts(ent_name)
            ent_name.grid(row=grid_row, column=1, sticky=tk.EW, pady=4)
            grid_row += 1

            # ── Официальная страница с актуальными DNS ──
            ttk.Label(fr, text="Где смотреть DNS:").grid(row=grid_row, column=0, sticky=tk.W, pady=4)
            source_row = ttk.Frame(fr)
            source_row.grid(row=grid_row, column=1, sticky=tk.EW, pady=4)
            source_row.columnconfigure(0, weight=1)
            ent_source = ttk.Entry(source_row, textvariable=var_source_url, width=34)
            self._enable_entry_clipboard_shortcuts(ent_source)
            ent_source.grid(row=0, column=0, sticky=tk.EW, padx=(0, 8))
            btn_copy_source = ttk.Button(source_row, text="Копировать")
            btn_copy_source.grid(row=0, column=1, sticky=tk.E, padx=(0, 6))
            btn_open_source = ttk.Button(source_row, text="Открыть")
            btn_open_source.grid(row=0, column=2, sticky=tk.E)
            grid_row += 1

            source_actions_fr = ttk.Frame(fr)
            source_actions_fr.grid(row=grid_row, column=0, columnspan=2, sticky=tk.W, pady=(0, 2))
            lbl_source_status = ttk.Label(
                source_actions_fr, text="", foreground="#555", font=("Segoe UI", 9)
            )
            lbl_source_status.pack(side=tk.LEFT)
            grid_row += 1

            def _normalized_source_url():
                url = var_source_url.get().strip()
                if url and not url.lower().startswith(("http://", "https://")):
                    url = "https://" + url
                return url

            def _copy_source_url():
                url = _normalized_source_url()
                if not url:
                    lbl_source_status.configure(text="Ссылка не указана", foreground="#c0392b")
                    return
                try:
                    ed.clipboard_clear()
                    ed.clipboard_append(url)
                    lbl_source_status.configure(text="Ссылка скопирована", foreground="#2a7d2a")
                except tk.TclError:
                    lbl_source_status.configure(text="Не удалось скопировать", foreground="#c0392b")

            def _open_source_url():
                url = _normalized_source_url()
                if not url:
                    lbl_source_status.configure(text="Ссылка не указана", foreground="#c0392b")
                    return
                try:
                    webbrowser.open(url)
                    lbl_source_status.configure(text="Открыто в браузере", foreground="#2a7d2a")
                except Exception as e:
                    lbl_source_status.configure(text=f"Не удалось открыть: {e}", foreground="#c0392b")

            btn_copy_source.configure(command=_copy_source_url)
            btn_open_source.configure(command=_open_source_url)

            # ── Информационная пометка для служебного geohide-профиля ──
            # Это не выбор типа, а просто подсказка, что профиль обновляется
            # автоматически по dns.geohide.ru. Поля Primary/Secondary в этом
            # профиле — резервные значения на случай отказа резолва.
            if not is_new and existing_type == "geohide":
                ttk.Label(
                    fr,
                    text="★ Служебный профиль: IP обновляется автоматически\n"
                         "    по dns.geohide.ru. Поля ниже — резервные.",
                    font=("Segoe UI", 9), foreground="#666", justify=tk.LEFT
                ).grid(row=grid_row, column=0, columnspan=2, sticky=tk.W, pady=(2, 6))
                grid_row += 1

            # ── Блок «получить DNS по ссылке» ──
            ttk.Separator(fr, orient=tk.HORIZONTAL).grid(
                row=grid_row, column=0, columnspan=2, sticky=tk.EW, pady=(10, 6))
            grid_row += 1

            ttk.Label(fr, text="Ссылка или домен:").grid(
                row=grid_row, column=0, sticky=tk.W, pady=4)
            link_row = ttk.Frame(fr)
            link_row.grid(row=grid_row, column=1, sticky=tk.EW, pady=4)
            link_row.columnconfigure(0, weight=1)
            ent_link = ttk.Entry(link_row, textvariable=var_link, width=26)
            self._enable_entry_clipboard_shortcuts(ent_link)
            ent_link.grid(row=0, column=0, sticky=tk.EW, padx=(0, 8))
            btn_fetch = ttk.Button(link_row, text="Получить DNS по ссылке")
            btn_fetch.grid(row=0, column=1, sticky=tk.E)
            grid_row += 1

            link_actions_fr = ttk.Frame(fr)
            link_actions_fr.grid(row=grid_row, column=0, columnspan=2, sticky=tk.W, pady=(0, 2))
            lbl_fetch_status = ttk.Label(
                link_actions_fr, text="", foreground="#555", font=("Segoe UI", 9)
            )
            lbl_fetch_status.pack(side=tk.LEFT)
            grid_row += 1

            ttk.Separator(fr, orient=tk.HORIZONTAL).grid(
                row=grid_row, column=0, columnspan=2, sticky=tk.EW, pady=(4, 6))
            grid_row += 1

            # ── DNS-поля (всегда доступны для ручного ввода/правки) ──
            ttk.Label(fr, text="Основной DNS:").grid(row=grid_row, column=0, sticky=tk.W, pady=4)
            ent_primary = ttk.Entry(fr, textvariable=var_primary, width=36)
            self._enable_entry_clipboard_shortcuts(ent_primary)
            ent_primary.grid(row=grid_row, column=1, sticky=tk.EW, pady=4)
            grid_row += 1

            ttk.Label(fr, text="Резервный DNS:").grid(row=grid_row, column=0, sticky=tk.W, pady=4)
            ent_secondary = ttk.Entry(fr, textvariable=var_secondary, width=36)
            self._enable_entry_clipboard_shortcuts(ent_secondary)
            ent_secondary.grid(row=grid_row, column=1, sticky=tk.EW, pady=4)
            grid_row += 1

            lbl_err = ttk.Label(fr, text="", foreground="#c0392b", font=("Segoe UI", 9))
            lbl_err.grid(row=grid_row, column=0, columnspan=2, sticky=tk.W, pady=(6, 0))
            grid_row += 1

            # ── Логика «Получить DNS по ссылке» (асинхронно, чтобы не блокировать UI) ──
            fetch_state = {"busy": False}

            def _set_fetch_busy(busy):
                fetch_state["busy"] = busy
                try:
                    btn_fetch.configure(state=(tk.DISABLED if busy else tk.NORMAL))
                except tk.TclError:
                    pass
                if busy:
                    try:
                        lbl_fetch_status.configure(text="Получение...", foreground="#555")
                    except tk.TclError:
                        pass

            def _on_fetch_done(result):
                if not ed.winfo_exists():
                    return
                _set_fetch_busy(False)
                if result.get("ok"):
                    var_primary.set(result.get("primary") or "")
                    var_secondary.set(result.get("secondary") or "")
                    src = result.get("source") or ""
                    msg = "Готово" + (f" ({src})" if src else "")
                    lbl_fetch_status.configure(text=msg, foreground="#2a7d2a")
                    lbl_err.configure(text="")
                else:
                    err = result.get("error") or "Не удалось определить DNS"
                    lbl_fetch_status.configure(
                        text=f"{err}. Введите DNS вручную.",
                        foreground="#c0392b"
                    )

            def _do_fetch():
                if fetch_state["busy"]:
                    return
                text = var_link.get().strip()
                if not text:
                    lbl_fetch_status.configure(
                        text="Введите ссылку или домен",
                        foreground="#c0392b"
                    )
                    return
                _set_fetch_busy(True)
                app_logger.info(f"Запрошено получение DNS по ссылке: {text}")

                def _worker():
                    try:
                        result = fetch_dns_from_link(text)
                    except Exception as e:
                        result = {"ok": False, "primary": None, "secondary": None,
                                  "source": "", "error": f"Ошибка: {e}"}
                    if not result.get("ok"):
                        app_logger.warn(
                            f"DNS по ссылке не распознаны ({text}): "
                            f"{result.get('error') or 'нет данных'}"
                        )
                    try:
                        ed.after(0, lambda r=result: _on_fetch_done(r))
                    except (tk.TclError, RuntimeError):
                        pass

                threading.Thread(target=_worker, daemon=True).start()

            btn_fetch.configure(command=_do_fetch)
            ent_link.bind("<Return>", lambda _e: _do_fetch())

            def _validate_ip(s):
                if not s:
                    return True
                parts = s.strip().split(".")
                if len(parts) != 4:
                    return False
                return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

            def _save_ed():
                name = var_name.get().strip()
                # Тип не редактируется через интерфейс. Существующий profile
                # сохраняет свой тип, новые профили всегда static.
                ptype = existing_type if not is_new else "static"
                primary = var_primary.get().strip()
                secondary = var_secondary.get().strip()

                # Строгая валидация — те же правила, что и раньше; не ослабляем
                # их даже если поля заполнены автоматически по ссылке.
                if not name:
                    lbl_err.configure(text="Название не может быть пустым")
                    return
                if not primary or not _validate_ip(primary):
                    lbl_err.configure(text="Некорректный адрес основного DNS")
                    return
                if secondary and not _validate_ip(secondary):
                    lbl_err.configure(text="Некорректный адрес резервного DNS")
                    return

                # Уникальный id профиля. Для существующего сохраняем родной id
                # (он привязан к desired_mode). Для нового — генерируем по имени
                # и при коллизии добавляем числовой суффикс, чтобы не плодить
                # двойников и не ломать сохранение desired_mode.
                if is_new:
                    base_id = (name.lower()
                               .replace(" ", "_")
                               .replace(".", "_")
                               .replace("/", "_")) or "profile"
                    existing_ids = {ex["id"] for ex in work_profiles}
                    new_id = base_id
                    suffix = 2
                    while new_id in existing_ids:
                        new_id = f"{base_id}_{suffix}"
                        suffix += 1
                else:
                    new_id = p.get("id") or name.lower().replace(" ", "_").replace(".", "_")

                new_p = {
                    "id": new_id,
                    "name": name,
                    "type": ptype,
                    "primary": primary,
                    "secondary": secondary,
                    "source_url": var_source_url.get().strip(),
                    "fetch_url": var_link.get().strip(),
                }

                if is_new:
                    for existing in work_profiles:
                        if existing["primary"] == primary and existing.get("secondary", "") == secondary:
                            lbl_err.configure(text="Профиль с такими же DNS-адресами уже существует")
                            return
                    work_profiles.append(new_p)
                else:
                    for i2, existing in enumerate(work_profiles):
                        if i2 != idx and existing["primary"] == primary and existing.get("secondary", "") == secondary:
                            lbl_err.configure(text="Профиль с такими же DNS-адресами уже существует")
                            return
                    work_profiles[idx] = new_p

                ed.destroy()
                _rebuild_list()

            btn_fr = ttk.Frame(fr)
            btn_fr.grid(row=grid_row, column=0, columnspan=2, pady=(10, 0))
            ttk.Button(btn_fr, text="Сохранить", command=_save_ed).pack(side=tk.LEFT, padx=(0, 6))
            ttk.Button(btn_fr, text="Отменить", command=ed.destroy).pack(side=tk.LEFT)

        # ── Логика проверки (время отклика + доступность домена) ──
        def _format_test_result(r):
            """Превращает результат check_resource_via_dns в (текст, цвет)."""
            lat = r.get("latency_ms")
            lat_txt = f"{lat:.0f} мс" if isinstance(lat, (int, float)) else "?"
            verdict = r.get("verdict")
            if verdict == "open":
                text = f"{lat_txt}  ✓ открывается"
                if r.get("tls_unverified"):
                    return (text + " (TLS без пров.)", "#e65100")
                return (text, "#2a7d2a")
            if verdict == "geoblock":
                status = r.get("http_status")
                suffix = f" ({status})" if status is not None else ""
                return (f"{lat_txt}  ⛔ геоблок{suffix}", "#c0392b")
            if verdict == "unreachable":
                return ("✗ нет ответа", "#c0392b")
            if verdict == "no_resolve":
                return ("✗ не резолвит домен", "#c0392b")
            return ("✗ не резолвит домен", "#c0392b")

        def _update_test_label(pid, text, color):
            test_results[pid] = (text, color)
            lbl = result_labels.get(pid)
            if lbl is not None:
                try:
                    lbl.configure(text=text, foreground=color)
                except tk.TclError:
                    pass

        def _test_ip_for_profile(profile):
            """IP, по которому проверять профиль.

            Для geohide сначала берём явно сохранённый не-резервный primary
            из таблицы, чтобы пользователь видел и проверял один и тот же IP.
            Если в таблице только дефолтный резерв, используем актуальный
            резолв dns.geohide.ru.
            """
            if profile.get("type") == "geohide":
                primary = profile.get("primary", "")
                fallback_ips = set(GEOHIDE_FALLBACK_IPS) | set(GEOHIDE_LEGACY_FALLBACK_IPS)
                if primary and primary not in fallback_ips:
                    return primary
                if self.geohide_known_ips:
                    return self.geohide_known_ips[0]
                return primary
            return profile.get("primary", "")

        def _run_test():
            if test_state["busy"]:
                return
            domain = var_test_domain.get().strip() or DNS_PROFILE_TEST_DOMAIN
            snapshot = [(p["id"], _test_ip_for_profile(p)) for p in work_profiles]
            snapshot = [(pid, ip) for pid, ip in snapshot if ip]
            if not snapshot:
                lbl_test_status.configure(text="Нет профилей для проверки", foreground="#c0392b")
                return
            test_state["busy"] = True
            try:
                btn_test.configure(state=tk.DISABLED)
            except tk.TclError:
                pass
            lbl_test_status.configure(text=f"Проверка «{domain}»…", foreground="#555")
            for pid, _ip in snapshot:
                _update_test_label(pid, "…", "#888")
            app_logger.info(f"Проверка DNS-серверов по домену: {domain}")

            total = len(snapshot)
            done_state = {"n": 0}
            done_lock = threading.Lock()

            def _probe(pid, ip):
                # Каждый сервер проверяется в своём потоке — все параллельно,
                # иначе при таймаутах последовательный прогон занял бы десятки
                # секунд. Обновление UI — строго через dialog.after.
                try:
                    r = check_resource_via_dns(ip, domain, timeout=2.5)
                except Exception as e:
                    r = {"resolved": False, "latency_ms": None, "ips": [],
                         "http_status": None, "verdict": "unreachable",
                         "tls_unverified": False, "error": str(e)}
                text, color = _format_test_result(r)
                with done_lock:
                    done_state["n"] += 1
                    d = done_state["n"]
                try:
                    dialog.after(0, lambda p=pid, t=text, c=color: _update_test_label(p, t, c))
                    dialog.after(0, lambda dd=d: lbl_test_status.configure(
                        text=f"Проверка «{domain}»… {dd}/{total}", foreground="#555"))
                    if d >= total:
                        dialog.after(0, _finish)
                except (tk.TclError, RuntimeError):
                    pass

            def _finish():
                test_state["busy"] = False
                try:
                    btn_test.configure(state=tk.NORMAL)
                    lbl_test_status.configure(text="Готово", foreground="#2a7d2a")
                except tk.TclError:
                    pass

            for pid, ip in snapshot:
                threading.Thread(target=_probe, args=(pid, ip), daemon=True).start()

        btn_test.configure(command=_run_test)
        ent_test_domain.bind("<Return>", lambda _e: _run_test())

        _rebuild_list()

        # ── Кнопки под списком ──
        actions_frame = ttk.Frame(dialog)
        actions_frame.pack(fill=tk.X, padx=15, pady=(0, 6))
        ttk.Button(actions_frame, text="Добавить профиль", command=_add_profile).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            actions_frame, text="Сбросить DNS-кнопки к стандартному набору",
            command=lambda: (_reset_dns_profiles(), _rebuild_list())
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            actions_frame, text="Удалить все кнопки",
            command=lambda: _delete_all_profiles()
        ).pack(side=tk.LEFT)

        def _reset_dns_profiles():
            work_profiles.clear()
            work_profiles.extend(_get_default_dns_profiles())
            work_bpr.set(DEFAULT_DNS_BUTTONS_PER_ROW)

        def _delete_all_profiles():
            """Полная очистка пользовательских DNS-кнопок (рабочая копия).

            Это НЕ сброс к дефолтному набору: после подтверждения список
            становится пустым, и пользователь сможет собрать свой набор
            с нуля. Стандартная системная кнопка DNS в окне настройки не
            участвует — она не пользовательский профиль.
            Окончательное сохранение происходит только по кнопке
            «Сохранить» внизу диалога.
            """
            if not work_profiles:
                messagebox.showinfo(
                    "Удаление DNS-кнопок",
                    "Пользовательских DNS-кнопок нет — удалять нечего.",
                    parent=dialog,
                )
                return
            answer = messagebox.askyesno(
                "Удалить все DNS-кнопки?",
                "Будут удалены ВСЕ пользовательские DNS-кнопки.\n\n"
                "Стандартный DNS останется без изменений.\n"
                "Дефолтный набор автоматически не восстанавливается — "
                "после сохранения вы сможете добавить свои кнопки с нуля.\n\n"
                "Продолжить?",
                icon="warning",
                parent=dialog,
            )
            if not answer:
                return
            work_profiles.clear()
            _rebuild_list()

        # ── Кнопки Сохранить / Отменить ──
        bottom_frame = ttk.Frame(dialog)
        bottom_frame.pack(fill=tk.X, padx=15, pady=(0, 12))

        def _save_all():
            try:
                bpr = int(work_bpr.get())
                bpr = max(1, min(5, bpr))
            except (ValueError, tk.TclError):
                bpr = DEFAULT_DNS_BUTTONS_PER_ROW

            # Пустой список пользовательских DNS-кнопок — допустимое состояние
            # (результат действия «Удалить все кнопки»). Дефолтный набор
            # автоматически не восстанавливается. Стандартная системная кнопка
            # DNS сюда не входит и остаётся на месте.
            self._dns_profiles = [dict(p) for p in work_profiles]
            self.settings["dns_profiles"] = self._dns_profiles
            self.settings["dns_buttons_per_row"] = bpr

            # Если после сохранения желаемый режим указывает на профиль,
            # которого больше нет в списке — очищаем его, чтобы не висел
            # «фантомный» desired_mode. Стандартный DNS и None не трогаем.
            desired = self.settings.get("desired_mode")
            if desired and desired != "standard":
                valid_ids = {p["id"] for p in self._dns_profiles}
                if desired not in valid_ids:
                    self.settings["desired_mode"] = None
                    self.desired_mode = None

            save_settings(self.settings)
            self._rebuild_dns_ui()
            if not self._dns_profiles:
                app_logger.info("DNS-профили обновлены: все пользовательские кнопки удалены")
            else:
                app_logger.info("DNS-профили обновлены")
            dialog.destroy()

        ttk.Button(bottom_frame, text="Сохранить", command=_save_all).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(bottom_frame, text="Отменить", command=dialog.destroy).pack(side=tk.RIGHT)

    # ─── Сообщение об ошибке доступа ──────────────────────────────────────

    def _show_access_error(self, msg):
        answer = messagebox.askyesno(
            APP_NAME,
            f"{msg}\n\nПерезапустить приложение с правами администратора?",
            icon="warning"
        )
        if answer:
            self._on_elevate()

    # ─── Главный цикл ────────────────────────────────────────────────────

    def run(self):
        self.mainloop()
