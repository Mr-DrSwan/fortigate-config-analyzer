import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.error import URLError

from address_utils import (
    address_sort_key,
    address_sort_mode_key,
    get_address_display_value,
    normalize_iprange_value,
    normalize_subnet_value,
    subnet_to_display,
)
from config_sections import replace_or_append_config_section
from fortigate_analyzer import FortigateConfigParser
from perf_metrics import PerfRecorder
from security_utils import ensure_under_root, sanitize_spreadsheet_text
from services.device_vault import (
    DeviceRecord,
    get_app_data_dir,
    load_devices_from_disk,
)
from services.updater import (
    download_update_asset,
    fetch_asset_checksum,
    fetch_latest_asset_urls,
    fetch_remote_version,
    get_display_version,
    get_platform_asset_name,
    is_newer_version,
    run_installer,
)


CHECK_COMMAND_TEXT = """config firewall address
    show
end

config firewall addrgrp
    show
end"""

FORTIGATE_COLOR_TABLE = [
    (0, "neutral-100"),
    (1, "neutral-100"),
    (2, "blue-500"),
    (3, "emerald-500"),
    (4, "red-300"),
    (5, "red-200"),
    (6, "tomato-500"),
    (7, "tomato-600"),
    (8, "orange-800"),
    (9, "yellow-900"),
    (10, "amber-400"),
    (11, "amber-600"),
    (12, "emerald-700"),
    (13, "green-600"),
    (14, "emerald-300"),
    (15, "emerald-600"),
    (16, "green-700"),
    (17, "sky-600"),
    (18, "sky-500"),
    (19, "blue-500"),
    (20, "indigo-300"),
    (21, "violet-200"),
    (22, "purple-200"),
    (23, "pink-200"),
    (24, "pink-300"),
    (25, "red-400"),
    (26, "gray-400"),
    (27, "gray-500"),
    (28, "orange-400"),
    (29, "lime-800"),
    (30, "indigo-200"),
    (31, "purple-100"),
    (32, "brown-300"),
]
FORTIGATE_COLOR_OPTIONS = ["(из конфига)"] + [f"{name:<12} | {code:>2}" for code, name in FORTIGATE_COLOR_TABLE]
FORTIGATE_COLOR_OPTION_BY_CODE = {code: f"{name:<12} | {code:>2}" for code, name in FORTIGATE_COLOR_TABLE}
GITHUB_OWNER = "Mr-DrSwan"
GITHUB_REPO = "fortigate-config-analyzer"
APP_ROOT = Path(__file__).resolve().parent
VERSION_FILE = APP_ROOT / "VERSION"


APP_DATA_DIR = get_app_data_dir() if getattr(sys, "frozen", False) else APP_ROOT
DEVICES_DIR = APP_DATA_DIR / "devices"
GITHUB_PROFILE_URL = f"https://github.com/{GITHUB_OWNER}"
COPYRIGHT_TEXT = f"© {GITHUB_OWNER} (GitHub)"
UI_STYLE_TOKENS = {
    "colors": {
        # --- Termius-inspired palette ---
        "bg": "#1C1E2B",
        "sidebar": "#181A27",
        "panel": "#242638",
        "panel_soft": "#1E2030",
        "panel_shadow": "#13141F",
        "line": "#2A2D42",
        "line_soft": "#33374F",
        "accent": "#5B6BDF",
        "accent_soft": "#4A5ACC",
        "accent_hover": "#6B7BEF",
        "text": "#E8EAF0",
        "muted": "#7C8099",
        "sidebar_item_hover": "#252840",
        "sidebar_item_active": "#2E3150",
        "sidebar_text_active": "#C8CCEF",
        # --- buttons ---
        "button_app_fg": "#E8EAF0",
        "button_app_bg": "#2E3150",
        "button_app_bg_active": "#363859",
        "button_app_bg_pressed": "#3E4163",
        "button_app_bg_disabled": "#242638",
        "button_app_fg_disabled": "#555872",
        "button_danger_fg": "#FFB3B8",
        "button_danger_bg": "#4A2830",
        "button_danger_bg_active": "#5C3038",
        "button_danger_bg_pressed": "#6E3842",
        "entry_light": "#1E2030",
        "chip_hover": "#2C2F4A",
        "button_primary_fill": "#353856",
        "button_primary_hover": "#3D4062",
        "button_primary_border": "#4A4E78",
        "button_primary_text": "#E8EAF0",
        "button_danger_fill": "#4A2830",
        "button_danger_hover": "#5C3038",
        "button_danger_border": "#6E4050",
        "button_danger_text": "#FFB3B8",
        "button_ghost_hover": "#282B44",
        # --- window controls (keep macOS-standard) ---
        "window_ctrl_close": "#FF5F57",
        "window_ctrl_minimize": "#FEBB2E",
        "window_ctrl_maximize": "#28C840",
        "window_ctrl_idle": "#383B56",
        "window_ctrl_idle_border": "#484B6A",
    },
    "fonts": {
        "label_xs": ("Helvetica", 9),
        "label_sm": ("Helvetica", 10),
        "label_sm_bold": ("Helvetica", 10, "bold"),
        "label_md": ("Helvetica", 11),
        "label_lg": ("Helvetica", 12),
        "label_lg_bold": ("Helvetica", 12, "bold"),
        "title_md_bold": ("Helvetica", 13, "bold"),
        "title_lg_bold": ("Helvetica", 15, "bold"),
        "title_xl_bold": ("Helvetica", 16, "bold"),
        "action_bold": ("Helvetica", 11, "bold"),
        "sidebar_item": ("Helvetica", 12),
        "sidebar_item_bold": ("Helvetica", 12, "bold"),
        "sidebar_logo": ("Helvetica", 13, "bold"),
        "sidebar_logo_sub": ("Helvetica", 10),
    },
    "spacing": {
        "outer": 0,
        "section": 14,
        "gap": 8,
        "tight": 4,
    },
    "metrics": {
        "radius_panel": 18,
        "radius_block": 16,
        "radius_card": 16,
        "radius_control": 14,
        "radius_chip": 14,
        "radius_device_card": 18,
        "width_sidebar": 190,
        "height_shell_panel": 360,
        "height_device_menu_bar": 44,
        "height_device_menu_item": 30,
        "height_chip": 28,
        "height_main_card": 320,
        "height_host_list": 170,
        "height_dropdown": 340,
        "height_device_card": 72,
        "height_tile": 70,
        "height_add_device_dialog": 220,
        "height_inventory_panel": 300,
        "height_transfer_panel": 280,
        "height_transfer_color_map": 170,
        "height_transfer_target": 240,
        "height_check_command": 130,
        "height_transfer_editor": 320,
        "height_duplicates_view": 170,
        "height_duplicates_editor": 260,
        "height_color_picker": 145,
        "height_header": 88,
        "height_titlebar": 34,
        "height_container_min": 110,
        "height_button_sm": 30,
        "height_button_md": 32,
        "height_button_lg": 34,
        "control_height": 36,
    },
    "button_styles": {
        "primary": {
            "fill": "button_primary_fill",
            "hover": "button_primary_hover",
            "border": "button_primary_border",
            "fg": "button_primary_text",
        },
        "danger": {
            "fill": "button_danger_fill",
            "hover": "button_danger_hover",
            "border": "button_danger_border",
            "fg": "button_danger_text",
        },
        "ghost": {
            "fill": "panel_soft",
            "hover": "button_ghost_hover",
            "border": "line",
            "fg": "text",
        },
    },
}
UI_COLORS = UI_STYLE_TOKENS["colors"]
UI_FONTS = UI_STYLE_TOKENS["fonts"]
UI_SPACING = UI_STYLE_TOKENS["spacing"]
UI_STYLE_KIT = UI_STYLE_TOKENS["metrics"]
UI_BUTTON_STYLES = UI_STYLE_TOKENS["button_styles"]


def analyze_config(input_path: Path, output_path: Path) -> FortigateConfigParser:
    parser = FortigateConfigParser(str(input_path))
    parser.parse_all()
    parser.save_to_excel(str(output_path))
    return parser


def parse_fortigate_color_code(value: str) -> Optional[int]:
    if not value or value == "(из конфига)":
        return None
    match = re.search(r"(\d+)\s*$", value.strip())
    if not match:
        return None
    return int(match.group(1))


def format_fortigate_color_option(code: int) -> str:
    return FORTIGATE_COLOR_OPTION_BY_CODE.get(code, str(code))


def quote_cli(value: str) -> str:
    escaped = value.replace('"', r'\"')
    return f'"{escaped}"'


def sanitize_device_name(raw_name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", raw_name.strip())
    cleaned = cleaned.strip("._-")
    return cleaned[:64]


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FortiGate Config Analyzer")
        self.root.geometry("1280x760")
        self.root.minsize(1120, 680)
        self.root.configure(bg=UI_COLORS["bg"])
        self._configure_window_chrome()
        self._set_window_icon()

        self.local_version = get_display_version(VERSION_FILE)
        self.status_var = tk.StringVar(value="Добавьте устройство, чтобы начать анализ.")
        self.devices: Dict[str, DeviceRecord] = {}
        self.selected_device_name: Optional[str] = None
        self.last_parser: Optional[FortigateConfigParser] = None
        self._parser_cache: Dict[Tuple[str, float, str], FortigateConfigParser] = {}
        self.details_vars: Dict[str, tk.StringVar] = {}
        self.hosts_canvas: Optional[tk.Canvas] = None
        self.hosts_frame: Optional[tk.Frame] = None
        self.device_page_scroll_canvas: Optional[tk.Canvas] = None
        self.cards_canvas: Optional[tk.Canvas] = None
        self.cards_frame: Optional[tk.Frame] = None
        self.cards_wrap_canvas: Optional[tk.Canvas] = None
        self.editor_canvas: Optional[tk.Canvas] = None
        self.editor_text: Optional[tk.Text] = None
        self.device_page_canvas: Optional[tk.Canvas] = None
        self.editor_title_var = tk.StringVar(value="Встроенный редактор")
        self.editor_file_var = tk.StringVar(value="-")
        self.device_page_title_var = tk.StringVar(value="Страница устройства")
        self.device_page_status_var = tk.StringVar(value="-")
        self.device_page_config_added_var = tk.StringVar(value="-")
        self.device_page_excel_var = tk.StringVar(value="-")
        self.device_page_csv_var = tk.StringVar(value="-")
        self.device_page_folder_var = tk.StringVar(value="-")
        self.host_search_var = tk.StringVar(value="")
        self.editor_target_path: Optional[Path] = None
        self.open_tabs_frame: Optional[tk.Frame] = None
        self.opened_devices: List[str] = []
        self.active_device_tab: Optional[str] = None
        self.active_editor_device: Optional[str] = None
        self.right_panel_canvas: Optional[tk.Canvas] = None
        self.right_panel_visible = False
        self.host_tile_canvases: Dict[str, tk.Canvas] = {}
        self.card_canvases: Dict[str, tk.Canvas] = {}
        self._scroll_widget_targets: Dict[str, tk.Canvas] = {}
        self._scroll_fallback_targets: Dict[str, tk.Canvas] = {}
        self._active_scroll_canvas: Optional[tk.Canvas] = None
        self._global_wheel_bound = False
        self.perf_recorder = PerfRecorder(APP_DATA_DIR / "perf_metrics.jsonl")
        self.ui_root: tk.Widget = self.root
        # Use native OS title bar to keep window controls reliable.
        self.show_custom_titlebar = False
        self.custom_chrome_enabled = False
        self._window_drag_offset: tuple[int, int] = (0, 0)
        self._window_last_geometry: Optional[str] = None
        self._window_maximized = False
        self._resize_state: Optional[dict] = None
        self._resize_grips: List[tk.Frame] = []

        self._ensure_devices_dir()
        self._configure_styles()
        self._build_ui()
        self._load_devices()

    def _set_window_icon(self) -> None:
        icon_path = Path(__file__).resolve().parent / "assets" / "forti-analyzer-icon.png"
        if not icon_path.exists():
            return
        try:
            icon = tk.PhotoImage(file=str(icon_path))
            self.root.iconphoto(True, icon)
            self._icon_ref = icon
            self._small_icon_ref = icon.subsample(8, 8)
            self._header_icon_ref = icon.subsample(5, 5)
        except tk.TclError:
            pass

    def _configure_window_chrome(self) -> None:
        # Force fully native window chrome on macOS to keep
        # minimize/restore/maximize controls stable.
        self.custom_chrome_enabled = False
        return

    def _enable_window_resizing(self) -> None:
        if not self.custom_chrome_enabled:
            return
        grip = 6

        grips_config = [
            ("left", {"x": 0, "y": grip, "relheight": 1, "height": -grip * 2, "width": grip}),
            ("right", {"relx": 1, "x": -grip, "y": grip, "relheight": 1, "height": -grip * 2, "width": grip}),
            ("top", {"x": grip, "y": 0, "relwidth": 1, "width": -grip * 2, "height": grip}),
            ("bottom", {"x": grip, "rely": 1, "y": -grip, "relwidth": 1, "width": -grip * 2, "height": grip}),
            ("top_left", {"x": 0, "y": 0, "width": grip, "height": grip}),
            ("top_right", {"relx": 1, "x": -grip, "y": 0, "width": grip, "height": grip}),
            ("bottom_left", {"x": 0, "rely": 1, "y": -grip, "width": grip, "height": grip}),
            ("bottom_right", {"relx": 1, "rely": 1, "x": -grip, "y": -grip, "width": grip, "height": grip}),
        ]
        for edge, place_cfg in grips_config:
            handle = tk.Frame(self.root, bg=UI_COLORS["bg"], highlightthickness=0, bd=0)
            handle.place(**place_cfg)
            handle.lift()
            handle.bind("<Button-1>", lambda event, e=edge: self._start_resize(event, e))
            handle.bind("<B1-Motion>", self._perform_resize)
            self._resize_grips.append(handle)

    def _start_resize(self, event: tk.Event, edge: str) -> None:
        self._resize_state = {
            "edge": edge,
            "start_x": event.x_root,
            "start_y": event.y_root,
            "x": self.root.winfo_x(),
            "y": self.root.winfo_y(),
            "w": self.root.winfo_width(),
            "h": self.root.winfo_height(),
        }

    def _perform_resize(self, event: tk.Event) -> None:
        if not self._resize_state or self._window_maximized:
            return
        min_w = max(860, self.root.winfo_reqwidth())
        min_h = max(560, self.root.winfo_reqheight())
        dx = event.x_root - self._resize_state["start_x"]
        dy = event.y_root - self._resize_state["start_y"]
        x = self._resize_state["x"]
        y = self._resize_state["y"]
        w = self._resize_state["w"]
        h = self._resize_state["h"]
        edge = self._resize_state["edge"]

        if "right" in edge:
            w = max(min_w, self._resize_state["w"] + dx)
        if "left" in edge:
            w = max(min_w, self._resize_state["w"] - dx)
            x = self._resize_state["x"] + (self._resize_state["w"] - w)
        if "bottom" in edge:
            h = max(min_h, self._resize_state["h"] + dy)
        if "top" in edge:
            h = max(min_h, self._resize_state["h"] - dy)
            y = self._resize_state["y"] + (self._resize_state["h"] - h)

        self.root.geometry(f"{int(w)}x{int(h)}+{int(x)}+{int(y)}")

    def _on_window_map(self, _event: tk.Event) -> None:
        if not self.custom_chrome_enabled:
            return
        if self.root.state() == "normal":
            self.root.after(20, lambda: self.root.overrideredirect(True))

    def _start_window_drag(self, event: tk.Event) -> None:
        if self._window_maximized:
            return
        self._window_drag_offset = (event.x_root - self.root.winfo_x(), event.y_root - self.root.winfo_y())

    def _drag_window(self, event: tk.Event) -> None:
        if self._window_maximized:
            return
        dx, dy = self._window_drag_offset
        x = event.x_root - dx
        y = max(0, event.y_root - dy)
        self.root.geometry(f"+{x}+{y}")

    def _close_window(self, _event: Optional[tk.Event] = None) -> None:
        self.root.destroy()

    def _minimize_window(self, _event: Optional[tk.Event] = None) -> None:
        if self.custom_chrome_enabled:
            self.root.overrideredirect(False)
            self.root.update_idletasks()
            self.root.after(20, self.root.iconify)
            return
        self.root.iconify()

    def _toggle_maximize_window(self, _event: Optional[tk.Event] = None) -> None:
        if self._window_maximized:
            if self._window_last_geometry:
                self.root.geometry(self._window_last_geometry)
            self._window_maximized = False
            return
        self._window_last_geometry = self.root.geometry()
        width = self.root.winfo_screenwidth()
        height = self.root.winfo_screenheight() - 36
        self.root.geometry(f"{width}x{height}+0+28")
        self._window_maximized = True

    def _ensure_devices_dir(self) -> None:
        DEVICES_DIR.mkdir(parents=True, exist_ok=True)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "App.TButton",
            font=UI_FONTS["action_bold"],
            padding=(12, 8),
            foreground=UI_COLORS["button_app_fg"],
            background=UI_COLORS["button_app_bg"],
            borderwidth=0,
            focusthickness=0,
        )
        style.map(
            "App.TButton",
            background=[("active", UI_COLORS["button_app_bg_active"]), ("pressed", UI_COLORS["button_app_bg_pressed"]), ("disabled", UI_COLORS["button_app_bg_disabled"])],
            foreground=[("disabled", UI_COLORS["button_app_fg_disabled"])],
        )
        style.configure(
            "Danger.TButton",
            font=UI_FONTS["action_bold"],
            padding=(12, 8),
            foreground=UI_COLORS["button_danger_fg"],
            background=UI_COLORS["button_danger_bg"],
            borderwidth=0,
            focusthickness=0,
        )
        style.map("Danger.TButton", background=[("active", UI_COLORS["button_danger_bg_active"]), ("pressed", UI_COLORS["button_danger_bg_pressed"])])
        style.configure("Rounded.TEntry", fieldbackground=UI_COLORS["entry_light"], borderwidth=0, relief="flat", padding=(8, 6))
        style.configure("Card.TFrame", background=UI_COLORS["panel"], borderwidth=0, relief="flat")
        style.configure("Ghost.TButton", font=UI_FONTS["label_sm_bold"], padding=(10, 5), foreground=UI_COLORS["muted"])
        style.configure(
            "Vault.TCombobox",
            fieldbackground=UI_COLORS["panel"],
            background=UI_COLORS["panel"],
            foreground=UI_COLORS["text"],
            arrowcolor=UI_COLORS["muted"],
            bordercolor=UI_COLORS["line"],
            lightcolor=UI_COLORS["line"],
            darkcolor=UI_COLORS["line"],
            relief="flat",
            padding=(8, 5),
        )
        style.map(
            "Ghost.TButton",
            background=[("active", UI_COLORS["panel_soft"]), ("pressed", UI_COLORS["panel_soft"])],
            foreground=[("active", UI_COLORS["text"]), ("pressed", UI_COLORS["text"])],
        )

    def _build_ui(self) -> None:
        if self.custom_chrome_enabled:
            window_shell = tk.Frame(self.root, bg=UI_COLORS["bg"])
            window_shell.pack(fill="both", expand=True, padx=2, pady=2)
            frame_canvas, frame = self._create_rounded_container(
                window_shell,
                outer_bg=UI_COLORS["bg"],
                fill_color=UI_COLORS["panel_shadow"],
                border_color=UI_COLORS["line_soft"],
                radius=28,
                border_width=1,
                min_height=UI_STYLE_KIT["height_shell_panel"],
            )
            frame_canvas.pack(fill="both", expand=True)
            self.ui_root = frame
            self._enable_window_resizing()
        else:
            self.ui_root = self.root

        self._build_custom_titlebar()
        self._build_header()

        # Main body: sidebar + content area (Termius-style flat layout)
        body = tk.Frame(self.ui_root, bg=UI_COLORS["bg"])
        body.pack(fill="both", expand=True)

        # Sidebar — fixed width, darker background
        sidebar = tk.Frame(body, bg=UI_COLORS["sidebar"], width=UI_STYLE_KIT["width_sidebar"])
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        self._build_left_panel(sidebar)

        # Thin vertical divider
        tk.Frame(body, bg=UI_COLORS["line"], width=1).pack(side="left", fill="y")

        # Content area: center + right
        content = tk.Frame(body, bg=UI_COLORS["bg"])
        content.pack(side="left", fill="both", expand=True)

        center = tk.Frame(content, bg=UI_COLORS["panel_soft"])
        center.pack(side="left", fill="both", expand=True)
        self._build_center_panel(center)

        # Thin vertical divider before right panel
        tk.Frame(content, bg=UI_COLORS["line"], width=1).pack(side="left", fill="y")

        right = tk.Frame(content, bg=UI_COLORS["panel"], width=340)
        right.pack(side="left", fill="y")
        right.pack_propagate(False)
        self.right_panel_canvas = None
        self._build_right_panel(right)

    def _build_custom_titlebar(self) -> None:
        if not self.show_custom_titlebar:
            return
        bar = tk.Frame(self.ui_root, bg=UI_COLORS["panel_shadow"], height=UI_STYLE_KIT["height_titlebar"])
        bar.pack(fill="x", side="top", padx=0, pady=0)
        bar.pack_propagate(False)

        left = tk.Frame(bar, bg=UI_COLORS["panel_shadow"])
        left.pack(side="left", padx=(10, 0), pady=(0, 1))
        center = tk.Frame(bar, bg=UI_COLORS["panel_shadow"])
        center.pack(side="left", fill="both", expand=True)
        right = tk.Frame(bar, bg=UI_COLORS["panel_shadow"])
        right.pack(side="right", padx=(0, 8))

        def _add_window_control(hover_color: str, handler) -> tk.Canvas:
            control = tk.Canvas(left, width=12, height=12, bg=UI_COLORS["panel_shadow"], highlightthickness=0, bd=0)
            oval = control.create_oval(
                1,
                1,
                11,
                11,
                fill=UI_COLORS["window_ctrl_idle"],
                outline=UI_COLORS["window_ctrl_idle_border"],
                width=1,
            )
            control.pack(side="left", padx=(0, 7), pady=(2, 0))

            def _on_enter(_event) -> None:
                control.itemconfigure(oval, fill=hover_color, outline=hover_color)

            def _on_leave(_event) -> None:
                control.itemconfigure(
                    oval,
                    fill=UI_COLORS["window_ctrl_idle"],
                    outline=UI_COLORS["window_ctrl_idle_border"],
                )

            def _on_click(event: tk.Event) -> str:
                handler(event)
                return "break"

            control.bind("<Enter>", _on_enter)
            control.bind("<Leave>", _on_leave)
            control.bind("<Button-1>", _on_click)
            return control

        _add_window_control(UI_COLORS["window_ctrl_close"], self._close_window)
        _add_window_control(UI_COLORS["window_ctrl_minimize"], self._minimize_window)
        _add_window_control(UI_COLORS["window_ctrl_maximize"], self._toggle_maximize_window)

        title = tk.Label(
            center,
            text="FortiGate Config Analyzer",
            bg=UI_COLORS["panel_shadow"],
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_sm_bold"],
        )
        title.pack(expand=True)
        tk.Label(right, text="", bg=UI_COLORS["panel_shadow"]).pack()

        separator = tk.Frame(self.ui_root, bg=UI_COLORS["line"], height=1)
        separator.pack(fill="x", side="top")

        draggable = (bar, center, title)
        for widget in draggable:
            widget.bind("<Button-1>", self._start_window_drag)
            widget.bind("<B1-Motion>", self._drag_window)
            widget.bind("<Double-Button-1>", self._toggle_maximize_window)

    def _build_device_menu_bar(self) -> None:
        bar_wrap = tk.Frame(self.root, bg=UI_COLORS["bg"])
        bar_wrap.pack(fill="x", padx=UI_SPACING["outer"], pady=(UI_SPACING["outer"], 0))
        bar_canvas, bar = self._create_rounded_container(
            bar_wrap,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel"],
            border_color=UI_COLORS["line_soft"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_device_menu_bar"],
        )
        bar_canvas.pack(fill="x")

        self.open_tabs_frame = tk.Frame(bar, bg=UI_COLORS["panel"])
        self.open_tabs_frame.pack(side="left", fill="x", expand=True, padx=(10, 0))
        self._refresh_open_tabs()

        right = tk.Frame(bar, bg=UI_COLORS["panel"])
        right.pack(side="right", padx=(0, 10))
        tk.Label(
            right,
            text="Opened devices",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_sm_bold"],
        ).pack(side="right")

    def _open_github_profile(self, _event: Optional[tk.Event] = None) -> None:
        webbrowser.open_new_tab(GITHUB_PROFILE_URL)

    def _refresh_open_tabs(self) -> None:
        if self.open_tabs_frame is None:
            return
        for child in self.open_tabs_frame.winfo_children():
            child.destroy()

        BG = UI_COLORS["bg"]

        def _make_tab(parent: tk.Frame, text: str, is_active: bool, on_click, on_close=None) -> None:
            tab_bg = UI_COLORS["sidebar_item_active"] if is_active else BG
            border_col = UI_COLORS["line_soft"] if is_active else UI_COLORS["line"]

            tab_canvas, tab_inner = self._create_rounded_container(
                parent,
                outer_bg=BG,
                fill_color=tab_bg,
                border_color=border_col,
                radius=UI_STYLE_KIT["radius_control"],
                border_width=1,
                min_height=UI_STYLE_KIT["height_device_menu_item"],
            )
            tab_canvas.pack(side="left", padx=(0, 6))

            row = tk.Frame(tab_inner, bg=tab_bg)
            row.pack(fill="both", expand=True, padx=8)

            lbl = tk.Label(
                row,
                text=text,
                bg=tab_bg,
                fg=UI_COLORS["text"] if is_active else UI_COLORS["muted"],
                font=UI_FONTS["label_sm_bold"],
            )
            lbl.pack(side="left")

            if on_close:
                close = tk.Label(
                    row,
                    text=" ×",
                    bg=tab_bg,
                    fg=UI_COLORS["muted"],
                    font=UI_FONTS["label_sm_bold"],
                )
                close.pack(side="left")
                close.bind("<Button-1>", lambda _e: on_close())

            for w in (tab_canvas, tab_inner, row, lbl):
                w.bind("<Button-1>", lambda _e, fn=on_click: fn())

        menu_active = self.active_device_tab is None
        _make_tab(self.open_tabs_frame, "Устройства", menu_active, self._activate_menu_tab)

        for device_name in self.opened_devices:
            is_active = device_name == self.active_device_tab
            _make_tab(
                self.open_tabs_frame,
                device_name,
                is_active,
                on_click=lambda n=device_name: self._activate_device_tab(n),
                on_close=lambda n=device_name: self._close_open_tab(n),
            )

    def _activate_menu_tab(self) -> None:
        self.active_device_tab = None
        self.active_editor_device = None
        self._show_cards_view()
        self._refresh_open_tabs()

    def _ensure_device_tab(self, device_name: str, *, activate: bool = True) -> None:
        if device_name not in self.devices:
            return
        if device_name not in self.opened_devices:
            self.opened_devices.append(device_name)
        if activate:
            self.active_device_tab = device_name
        self._refresh_open_tabs()

    def _activate_device_tab(self, device_name: str) -> None:
        if device_name not in self.devices:
            return
        self.active_device_tab = device_name
        self.active_editor_device = None
        self._open_device_page(device_name)
        self._refresh_open_tabs()

    def _close_open_tab(self, device_name: str) -> None:
        if device_name in self.opened_devices:
            self.opened_devices.remove(device_name)
        if self.active_device_tab == device_name:
            self.active_device_tab = self.opened_devices[-1] if self.opened_devices else None
        if self.active_editor_device == device_name:
            self.active_editor_device = None
        if self.active_editor_device:
            self._open_device_editor(self.active_editor_device)
        elif self.active_device_tab:
            self._activate_device_tab(self.active_device_tab)
        else:
            self._show_cards_view()
        self._refresh_open_tabs()

    def _show_cards_view(self) -> None:
        if self.device_page_canvas is not None and self.device_page_canvas.winfo_manager():
            self.device_page_canvas.pack_forget()
        if self.editor_canvas is not None and self.editor_canvas.winfo_manager():
            self.editor_canvas.pack_forget()
        if hasattr(self, "cards_outer_frame") and self.cards_outer_frame is not None:
            if not self.cards_outer_frame.winfo_manager():
                self.cards_outer_frame.pack(fill="both", expand=True)
        elif self.cards_wrap_canvas is not None and not self.cards_wrap_canvas.winfo_manager():
            self.cards_wrap_canvas.pack(fill="both", expand=True, padx=UI_SPACING["section"], pady=(0, UI_SPACING["section"]))
        self.editor_target_path = None
        self.editor_title_var.set("Встроенный редактор")
        self.editor_file_var.set("-")

    def _open_device_editor(self, device_name: str) -> None:
        record = self.devices.get(device_name)
        if record is None:
            return
        self.select_device(device_name)
        self._ensure_device_tab(device_name, activate=True)
        self.active_device_tab = device_name
        self.active_editor_device = device_name

        target = record.config_path or record.csv_path
        if target is None:
            target = record.folder / f"{record.name}_notes.txt"
            if not target.exists():
                target.write_text("", encoding="utf-8")

        if hasattr(self, "cards_outer_frame") and self.cards_outer_frame is not None and self.cards_outer_frame.winfo_manager():
            self.cards_outer_frame.pack_forget()
        elif self.cards_wrap_canvas is not None and self.cards_wrap_canvas.winfo_manager():
            self.cards_wrap_canvas.pack_forget()
        if self.device_page_canvas is not None and self.device_page_canvas.winfo_manager():
            self.device_page_canvas.pack_forget()
        if self.editor_canvas is not None and not self.editor_canvas.winfo_manager():
            self.editor_canvas.pack(fill="both", expand=True, padx=UI_SPACING["section"], pady=(0, UI_SPACING["section"]))

        self.editor_target_path = target
        self.editor_title_var.set(f"Редактор: {device_name}")
        self.editor_file_var.set(target.name)
        if self.editor_text is not None:
            try:
                content = target.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                content = target.read_text(encoding="utf-8-sig", errors="ignore")
            self.editor_text.delete("1.0", "end")
            self.editor_text.insert("1.0", content)

    @staticmethod
    def _format_path_timestamp(path: Optional[Path]) -> str:
        if path is None or not path.exists():
            return "-"
        return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")

    def _open_device_page(self, device_name: str) -> None:
        started_at = time.perf_counter()
        record = self.devices.get(device_name)
        if record is None:
            return
        self.select_device(device_name)
        self._ensure_device_tab(device_name, activate=True)
        self.active_editor_device = None
        self._show_right_panel()

        if hasattr(self, "cards_outer_frame") and self.cards_outer_frame is not None and self.cards_outer_frame.winfo_manager():
            self.cards_outer_frame.pack_forget()
        elif self.cards_wrap_canvas is not None and self.cards_wrap_canvas.winfo_manager():
            self.cards_wrap_canvas.pack_forget()
        if self.editor_canvas is not None and self.editor_canvas.winfo_manager():
            self.editor_canvas.pack_forget()
        if self.device_page_canvas is not None and not self.device_page_canvas.winfo_manager():
            self.device_page_canvas.pack(fill="both", expand=True, padx=UI_SPACING["section"], pady=(0, UI_SPACING["section"]))

        self.device_page_title_var.set(f"Устройство: {record.name}")
        self.device_page_status_var.set(record.name)
        config_name = record.config_path.name if record.config_path else "-"
        config_added = self._format_path_timestamp(record.config_path)
        self.device_page_config_added_var.set(f"{config_name}  (добавлен: {config_added})")
        self.device_page_excel_var.set(record.excel_path.name if record.excel_path else "-")
        self.device_page_csv_var.set(record.csv_path.name if record.csv_path else "-")
        self.device_page_folder_var.set(str(record.folder))
        self._record_perf("ui.open_device_page", started_at, device=device_name)

    def _open_selected_device_page(self) -> None:
        record = self._get_selected_device()
        if not record:
            return
        self._open_device_page(record.name)

    def _open_selected_device_editor(self) -> None:
        record = self._get_selected_device()
        if not record:
            return
        self._open_device_editor(record.name)

    def _show_addresses_for_selected_device(self) -> None:
        parser = self._load_parser_for_selected_device(profile="addresses")
        if parser is None:
            return
        self.last_parser = parser
        addresses = sorted(parser.address_objects.keys(), key=self._address_sort_key)
        groups = sorted(parser.address_group_objects.keys())

        dialog = tk.Toplevel(self.root)
        dialog.title("Адреса устройства")
        dialog.geometry("980x700")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        text_canvas, text_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_transfer_editor"],
        )
        text_canvas.pack(fill="both", expand=True, padx=10, pady=10)
        text = tk.Text(
            text_wrap,
            wrap="word",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            relief="flat",
            insertbackground=UI_COLORS["text"],
        )
        text.pack(fill="both", expand=True)
        lines: List[str] = [f"Адресов: {len(addresses)}", f"Групп: {len(groups)}", ""]
        lines.append("Адреса:")
        for name in addresses:
            lines.append(f"- {name}  |  {self._get_address_display_value(name)}")
        lines.append("")
        lines.append("Группы:")
        for group in groups:
            lines.append(f"- {group}")
        text.insert("1.0", "\n".join(lines))
        text.configure(state="disabled")

        actions = tk.Frame(dialog, bg=UI_COLORS["bg"])
        actions.pack(fill="x", padx=10, pady=(0, 10))
        self._create_round_button(actions, "Закрыть", dialog.destroy, style_kind="ghost").pack(side="right")

    def _open_group_sorting_for_selected_device(self) -> None:
        parser = self._load_parser_for_selected_device(profile="addresses")
        if parser is None:
            return
        self.last_parser = parser

        all_addresses = sorted(parser.address_objects.keys(), key=self._address_sort_key)
        group_names = sorted(parser.address_group_objects.keys())
        group_members: Dict[str, Set[str]] = {
            name: set(parser.address_group_members.get(name, []))
            for name in group_names
        }
        grouped_addresses: Set[str] = set()
        for members in group_members.values():
            grouped_addresses.update(members)
        ungrouped_addresses = [name for name in all_addresses if name not in grouped_addresses]

        dialog = tk.Toplevel(self.root)
        dialog.title("Сортировка по группам")
        dialog.geometry("1080x720")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        tk.Label(
            dialog,
            text=(
                "Выберите группу, задайте ее цвет и отметьте адреса вне групп.\n"
                "Будут сгенерированы команды: добавить адреса в группу и выставить адресам цвет группы."
            ),
            anchor="w",
            justify="left",
            bg=UI_COLORS["bg"],
            fg=UI_COLORS["text"],
        ).pack(fill="x", padx=10, pady=(10, 6))

        top_canvas, top_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_host_list"],
        )
        top_canvas.pack(fill="x", padx=10, pady=(0, 8))
        top_controls = tk.Frame(top_wrap, bg=UI_COLORS["panel_soft"])
        top_controls.pack(fill="x")

        group_var = tk.StringVar(value=group_names[0] if group_names else "")
        group_color_var = tk.StringVar(value="(из конфига)")
        new_group_var = tk.StringVar()
        group_values: List[str] = list(group_names)
        group_color_overrides: Dict[str, int] = {}

        tk.Label(top_controls, text="Группа:", bg=UI_COLORS["panel_soft"], fg=UI_COLORS["muted"]).pack(side="left")
        group_cb = ttk.Combobox(
            top_controls,
            textvariable=group_var,
            values=group_values,
            width=28,
            state="readonly",
            style="Vault.TCombobox",
        )
        group_cb.pack(side="left", padx=(8, 12))
        tk.Label(top_controls, text="Цвет группы:", bg=UI_COLORS["panel_soft"], fg=UI_COLORS["muted"]).pack(side="left")
        group_color_cb = ttk.Combobox(
            top_controls,
            textvariable=group_color_var,
            values=FORTIGATE_COLOR_OPTIONS,
            width=22,
            state="readonly",
            style="Vault.TCombobox",
        )
        group_color_cb.pack(side="left", padx=(8, 8))

        def _resolve_group_color_code(group_name: str) -> Optional[int]:
            if group_name in group_color_overrides:
                return group_color_overrides[group_name]
            obj = parser.address_group_objects.get(group_name, {})
            raw = str(obj.get("color", "")).strip()
            return int(raw) if raw.isdigit() else None

        def _refresh_group_color() -> None:
            selected_group = group_var.get().strip()
            if not selected_group:
                group_color_var.set("(из конфига)")
                return
            color_code = _resolve_group_color_code(selected_group)
            if color_code is None:
                group_color_var.set("(из конфига)")
            else:
                group_color_var.set(format_fortigate_color_option(color_code))

        def _apply_group_color() -> None:
            selected_group = group_var.get().strip()
            if not selected_group:
                messagebox.showwarning("Нет группы", "Сначала выберите группу.", parent=dialog)
                return
            code = parse_fortigate_color_code(group_color_var.get().strip())
            if code is None:
                group_color_overrides.pop(selected_group, None)
            else:
                group_color_overrides[selected_group] = code
            _refresh_group_color()

        self._create_round_button(top_controls, "Применить цвет", _apply_group_color, style_kind="ghost").pack(side="left")

        create_row = tk.Frame(top_wrap, bg=UI_COLORS["panel_soft"])
        create_row.pack(fill="x", pady=(8, 0))
        tk.Label(create_row, text="Новая группа:", bg=UI_COLORS["panel_soft"], fg=UI_COLORS["muted"]).pack(side="left")
        create_shell, _ = self._create_round_entry(create_row, new_group_var, min_height=UI_STYLE_KIT["height_device_menu_item"])
        create_shell.pack(side="left", fill="x", expand=True, padx=(8, 8))

        def _create_group() -> None:
            group_name = new_group_var.get().strip()
            if not group_name:
                messagebox.showwarning("Пустое имя", "Введите имя новой группы.", parent=dialog)
                return
            if group_name in group_members:
                messagebox.showwarning("Уже существует", f"Группа '{group_name}' уже есть.", parent=dialog)
                return
            group_members[group_name] = set()
            group_values.append(group_name)
            group_values.sort(key=str.lower)
            group_cb.configure(values=group_values)
            group_var.set(group_name)
            _apply_group_color()
            new_group_var.set("")

        self._create_round_button(create_row, "Создать группу", _create_group, style_kind="ghost").pack(side="left")

        list_canvas, list_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_transfer_panel"],
        )
        list_canvas.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        right_text_map = {name: self._get_address_display_value(name) for name in ungrouped_addresses}
        address_vars = self._create_scrollable_checklist(
            list_wrap,
            "Адреса вне групп",
            ungrouped_addresses,
            right_text_map=right_text_map,
        )

        _refresh_group_color()
        group_cb.bind("<<ComboboxSelected>>", lambda _event: _refresh_group_color())

        actions = tk.Frame(dialog, bg=UI_COLORS["bg"])
        actions.pack(fill="x", padx=10, pady=(0, 10))

        def _build_group_sort_commands() -> None:
            selected_group = group_var.get().strip()
            if not selected_group:
                messagebox.showwarning("Нет группы", "Выберите или создайте группу.", parent=dialog)
                return
            selected_addresses = sorted([name for name, var in address_vars.items() if var.get()], key=self._address_sort_key)
            if not selected_addresses:
                messagebox.showwarning("Нет адресов", "Выберите хотя бы один адрес вне групп.", parent=dialog)
                return

            color_code = _resolve_group_color_code(selected_group)
            existing_members = set(group_members.get(selected_group, set()))
            final_members = sorted(existing_members.union(selected_addresses), key=str.lower)
            quoted_members = " ".join(quote_cli(name) for name in final_members)

            command_lines: List[str] = []
            if color_code is not None:
                command_lines.append("config firewall address")
                for name in selected_addresses:
                    command_lines.append(f"    edit {quote_cli(name)}")
                    command_lines.append(f"        set color {color_code}")
                    command_lines.append("    next")
                command_lines.append("end")
                command_lines.append("")

            command_lines.append("config firewall addrgrp")
            command_lines.append(f"    edit {quote_cli(selected_group)}")
            command_lines.append(f"        set member {quoted_members}")
            if color_code is not None:
                command_lines.append(f"        set color {color_code}")
            command_lines.append("    next")
            command_lines.append("end")

            result = tk.Toplevel(dialog)
            result.title("Команды сортировки по группам")
            result.geometry("980x700")
            result.transient(dialog)
            result.grab_set()
            result.configure(bg=UI_COLORS["bg"])

            result_canvas, result_wrap = self._create_rounded_container(
                result,
                outer_bg=UI_COLORS["bg"],
                fill_color=UI_COLORS["panel_soft"],
                border_color=UI_COLORS["line"],
                radius=UI_STYLE_KIT["radius_card"],
                border_width=1,
                min_height=UI_STYLE_KIT["height_transfer_editor"],
            )
            result_canvas.pack(fill="both", expand=True, padx=10, pady=10)
            result_text = tk.Text(
                result_wrap,
                wrap="none",
                bg=UI_COLORS["panel_soft"],
                fg=UI_COLORS["text"],
                relief="flat",
                insertbackground=UI_COLORS["text"],
            )
            result_text.pack(fill="both", expand=True)
            payload = "\n".join(command_lines).strip()
            result_text.insert("1.0", payload)

            result_actions = tk.Frame(result, bg=UI_COLORS["bg"])
            result_actions.pack(fill="x", padx=10, pady=(0, 10))

            def _copy_payload() -> None:
                self.root.clipboard_clear()
                self.root.clipboard_append(payload)
                messagebox.showinfo("Скопировано", "Команды скопированы в буфер обмена.", parent=result)

            def _mark_applied() -> None:
                if not self._ask_commands_applied_dialog(
                    "Подтверждение применения",
                    "Вы применили команды на FortiGate?\nИзменения будут отражены в конфиге устройства в приложении.",
                    result,
                ):
                    return
                if self.last_parser is None:
                    result.destroy()
                    dialog.destroy()
                    return

                parser_obj = self.last_parser
                for address_name in selected_addresses:
                    if address_name not in parser_obj.address_objects:
                        continue
                    if color_code is not None:
                        parser_obj.address_objects[address_name]["color"] = str(color_code)

                if selected_group not in parser_obj.address_group_objects:
                    parser_obj.address_group_objects[selected_group] = {"_name": selected_group}
                parser_obj.address_group_members[selected_group] = list(final_members)
                parser_obj.address_group_objects[selected_group]["member"] = " ".join(final_members)
                if color_code is not None:
                    parser_obj.address_group_objects[selected_group]["color"] = str(color_code)

                self._persist_current_address_data_to_selected_config()
                result.destroy()
                dialog.destroy()

            self._create_round_button(result_actions, "Скопировать", _copy_payload).pack(side="right")
            self._create_round_button(result_actions, "Применил", _mark_applied).pack(side="right", padx=(0, 8))
            self._create_round_button(result_actions, "Нет", result.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

        self._create_round_button(actions, "Сгенерировать команды", _build_group_sort_commands).pack(side="right")
        self._create_round_button(actions, "Отмена", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

    def _show_address_duplicates_for_selected_device(self) -> None:
        parser = self._load_parser_for_selected_device(profile="addresses")
        if parser is None:
            return
        self.last_parser = parser
        report = parser.find_duplicate_addresses()

        same_value = report["same_value_different_names"]
        same_name = report["same_name_multiple_entries"]
        exact_dupes = report["exact_duplicate_entries"]
        total_entries = int(report["total_entries"])

        dialog = tk.Toplevel(self.root)
        dialog.title("Дубликаты адресов в конфиге")
        dialog.geometry("980x740")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        if not same_value and not same_name and not exact_dupes:
            messagebox.showinfo("Дубликаты", f"В конфиге не найдено дубликатов.\nПроверено записей: {total_entries}")
            return

        tk.Label(
            dialog,
            text=(
                "Выберите, какой адрес оставить в каждой группе одинаковых адресов.\n"
                "После выбора можно получить готовые команды удаления дублей."
            ),
            anchor="w",
            justify="left",
            bg=UI_COLORS["bg"],
            fg=UI_COLORS["text"],
        ).pack(fill="x", padx=10, pady=(10, 6))

        chooser_canvas, chooser_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_host_list"],
        )
        chooser_canvas.pack(fill="x", padx=10, pady=(0, 8))
        chooser_scroll_canvas = tk.Canvas(chooser_wrap, height=180, bg=UI_COLORS["panel_soft"], highlightthickness=0)
        chooser_scroll = self._create_scrollbar(chooser_wrap, chooser_scroll_canvas.yview)
        chooser_frame = tk.Frame(chooser_scroll_canvas, bg=UI_COLORS["panel_soft"])
        chooser_frame.bind("<Configure>", lambda event: chooser_scroll_canvas.configure(scrollregion=chooser_scroll_canvas.bbox("all")))
        chooser_scroll_canvas.create_window((0, 0), window=chooser_frame, anchor="nw")
        chooser_scroll_canvas.configure(yscrollcommand=chooser_scroll.set)
        chooser_scroll_canvas.pack(side="left", fill="both", expand=True)
        chooser_scroll.pack(side="right", fill="y")
        self._bind_vertical_mousewheel(chooser_scroll_canvas, chooser_scroll_canvas, chooser_frame, chooser_wrap)

        keep_vars: List[Tuple[List[str], tk.StringVar, tk.StringVar, str]] = []
        if same_value:
            tk.Label(
                chooser_frame,
                text="Группы одинаковых адресов (справа можно указать новое имя):",
                anchor="w",
                bg=UI_COLORS["panel_soft"],
                fg=UI_COLORS["muted"],
                font=UI_FONTS["label_sm_bold"],
            ).pack(fill="x", pady=(4, 6))
            for item in same_value:
                names = [str(name) for name in item["names"]]
                value_type = str(item["value_type"])
                value = str(item["value"])
                row = tk.Frame(chooser_frame, bg=UI_COLORS["panel_soft"])
                row.pack(fill="x", pady=2)
                tk.Label(
                    row,
                    text=f"[{value_type}] {value}",
                    anchor="w",
                    bg=UI_COLORS["panel_soft"],
                    fg=UI_COLORS["text"],
                ).pack(side="left", fill="x", expand=True, padx=(0, 8))
                keep_var = tk.StringVar(value=names[0])
                ttk.Combobox(
                    row,
                    textvariable=keep_var,
                    values=names,
                    width=22,
                    state="readonly",
                    style="Vault.TCombobox",
                ).pack(side="right", padx=(0, 8))
                rename_var = tk.StringVar(value="")
                rename_shell, _ = self._create_round_entry(row, rename_var, min_height=UI_STYLE_KIT["height_device_menu_item"])
                rename_shell.configure(width=220)
                rename_shell.pack(side="right")
                keep_vars.append((names, keep_var, rename_var, f"[{value_type}] {value}"))

        text_canvas, text_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_transfer_editor"],
        )
        text_canvas.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        text = tk.Text(
            text_wrap,
            wrap="word",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            relief="flat",
            insertbackground=UI_COLORS["text"],
        )
        text.pack(fill="both", expand=True)

        lines: List[str] = [f"Всего адресных записей: {total_entries}", ""]
        lines.append("1) Одинаковый адрес при разных именах (выберите что оставить выше):")
        if same_value:
            for item in same_value:
                lines.append(f"- [{item['value_type']}] {item['value']}")
                for name in item["names"]:
                    lines.append(f"    • {name}")
        else:
            lines.append("- Не найдено")

        lines.append("")
        lines.append("2) Одно имя встречается несколько раз:")
        if same_name:
            for item in same_name:
                lines.append(f"- {item['name']} (записей: {item['count']})")
                for value in item["values"]:
                    lines.append(f"    • {value}")
        else:
            lines.append("- Не найдено")

        lines.append("")
        lines.append("3) Полностью одинаковые записи (дубликаты 1 в 1):")
        if exact_dupes:
            for item in exact_dupes:
                lines.append(f"- {item['name']} (повторов: {item['count']})")
        else:
            lines.append("- Не найдено")

        text.insert("1.0", "\n".join(lines))
        text.configure(state="disabled")

        actions = tk.Frame(dialog, bg=UI_COLORS["bg"])
        actions.pack(fill="x", padx=10, pady=(0, 10))
        def on_build_cleanup_commands() -> None:
            delete_names: List[str] = []
            decision_lines: List[str] = []
            rename_ops: List[Tuple[str, str]] = []
            known_names = set(parser.address_objects.keys())

            for names, keep_var, rename_var, signature in keep_vars:
                original_keep_name = keep_var.get().strip()
                keep_name = original_keep_name
                if not keep_name:
                    continue
                requested_new_name = rename_var.get().strip()
                if requested_new_name and requested_new_name != original_keep_name:
                    if requested_new_name in names:
                        messagebox.showerror(
                            "Некорректное переименование",
                            (
                                f"Имя '{requested_new_name}' уже есть в этой группе дублей.\n"
                                "Выберите это имя в поле 'оставить', а не через переименование."
                            ),
                            parent=dialog,
                        )
                        return
                    if requested_new_name in known_names and requested_new_name not in names:
                        messagebox.showerror(
                            "Конфликт имени",
                            f"Имя '{requested_new_name}' уже существует. Укажите другое имя.",
                            parent=dialog,
                        )
                        return
                    rename_ops.append((original_keep_name, requested_new_name))
                    known_names.add(requested_new_name)
                    keep_name = requested_new_name

                remove_names = [name for name in names if name != original_keep_name]
                if not remove_names:
                    continue
                decision_lines.append(f"- {signature}")
                decision_lines.append(f"    оставить: {keep_name}")
                decision_lines.append(f"    удалить: {', '.join(remove_names)}")
                delete_names.extend(remove_names)

            delete_names = sorted(set(delete_names))
            result = tk.Toplevel(dialog)
            result.title("Команды удаления дублей")
            result.geometry("980x680")
            result.transient(dialog)
            result.grab_set()
            result.configure(bg=UI_COLORS["bg"])

            result_canvas, result_wrap = self._create_rounded_container(
                result,
                outer_bg=UI_COLORS["bg"],
                fill_color=UI_COLORS["panel_soft"],
                border_color=UI_COLORS["line"],
                radius=UI_STYLE_KIT["radius_card"],
                border_width=1,
                min_height=UI_STYLE_KIT["height_transfer_editor"],
            )
            result_canvas.pack(fill="both", expand=True, padx=10, pady=10)
            result_text = tk.Text(
                result_wrap,
                wrap="word",
                bg=UI_COLORS["panel_soft"],
                fg=UI_COLORS["text"],
                relief="flat",
                insertbackground=UI_COLORS["text"],
            )
            result_text.pack(fill="both", expand=True)

            result_lines: List[str] = []
            if decision_lines:
                result_lines.append("Выбранные решения:")
                result_lines.extend(decision_lines)
                result_lines.append("")
            if rename_ops:
                result_lines.append("Команды переименования:")
                result_lines.append("config firewall address")
                for old_name, new_name in rename_ops:
                    result_lines.append(f"    rename \"{old_name}\" to \"{new_name}\"")
                result_lines.append("end")
                result_lines.append("")
            if delete_names:
                result_lines.append("Команды удаления дублей:")
                result_lines.append("config firewall address")
                for name in delete_names:
                    result_lines.append(f"    delete \"{name}\"")
                result_lines.append("end")
            else:
                result_lines.append("Нет адресов для удаления по выбранным решениям.")

            if same_name or exact_dupes:
                result_lines.append("")
                result_lines.append("Примечание:")
                result_lines.append("- В конфиге есть дубли по одному и тому же имени. Для них авто-удаление не генерируется.")

            payload = "\n".join(result_lines).strip()
            result_text.insert("1.0", payload)

            result_actions = tk.Frame(result, bg=UI_COLORS["bg"])
            result_actions.pack(fill="x", padx=10, pady=(0, 10))

            def copy_payload() -> None:
                self.root.clipboard_clear()
                self.root.clipboard_append(payload)
                messagebox.showinfo("Скопировано", "Команды удаления скопированы в буфер обмена.", parent=result)

            def mark_applied() -> None:
                if not self._ask_commands_applied_dialog(
                    "Подтверждение применения",
                    "Вы применили команды на FortiGate?\nИзменения будут отражены в конфиге устройства в приложении.",
                    result,
                ):
                    return
                if self.last_parser is None:
                    result.destroy()
                    return

                parser_obj = self.last_parser
                for old_name, new_name in rename_ops:
                    if old_name not in parser_obj.address_objects:
                        continue
                    obj = dict(parser_obj.address_objects.pop(old_name))
                    obj["_name"] = new_name
                    parser_obj.address_objects[new_name] = obj

                    for group_name, members in list(parser_obj.address_group_members.items()):
                        updated_members = self._replace_name_in_members(list(members), old_name, new_name)
                        parser_obj.address_group_members[group_name] = updated_members
                        if group_name in parser_obj.address_group_objects:
                            parser_obj.address_group_objects[group_name]["member"] = " ".join(updated_members)

                for delete_name in delete_names:
                    parser_obj.address_objects.pop(delete_name, None)
                    for group_name, members in list(parser_obj.address_group_members.items()):
                        updated_members = [member for member in members if member != delete_name]
                        parser_obj.address_group_members[group_name] = updated_members
                        if group_name in parser_obj.address_group_objects:
                            parser_obj.address_group_objects[group_name]["member"] = " ".join(updated_members)

                self._persist_current_address_data_to_selected_config()
                result.destroy()
                dialog.destroy()

            self._create_round_button(result_actions, "Скопировать", copy_payload).pack(side="right")
            self._create_round_button(result_actions, "Применил", mark_applied).pack(side="right", padx=(0, 8))
            self._create_round_button(result_actions, "Нет", result.destroy, style_kind="ghost").pack(
                side="right", padx=(0, 8)
            )

        self._create_round_button(actions, "Сформировать команды удаления", on_build_cleanup_commands).pack(side="left")
        self._create_round_button(actions, "Закрыть", dialog.destroy, style_kind="ghost").pack(side="right")

    def _save_editor_content(self) -> None:
        if self.editor_target_path is None or self.editor_text is None:
            return
        payload = self.editor_text.get("1.0", "end-1c")
        self.editor_target_path.write_text(payload, encoding="utf-8")
        self.status_var.set(f"Файл сохранен: {self.editor_target_path.name}")

    def _build_header(self) -> None:
        BG = UI_COLORS["bg"]

        # Top bar: search + toolbar chips (Termius-style, compact, no Panel wrapper)
        topbar = tk.Frame(self.ui_root, bg=BG)
        topbar.pack(fill="x", padx=14, pady=(10, 0))

        # Search field — rounded container
        search_canvas, search_inner = self._create_rounded_container(
            topbar,
            outer_bg=BG,
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_control"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_button_lg"],
        )
        search_canvas.pack(side="left", fill="x", expand=True)

        search_entry = tk.Entry(
            search_inner,
            textvariable=self.host_search_var,
            relief="flat",
            bd=0,
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            insertbackground=UI_COLORS["text"],
            font=UI_FONTS["label_md"],
        )
        search_entry.insert(0, "Find a host or device...")
        search_entry.pack(fill="both", expand=True, padx=10, pady=5)

        def _clear_placeholder(_event) -> None:
            if search_entry.get() == "Find a host or device...":
                search_entry.delete(0, "end")

        def _restore_placeholder(_event) -> None:
            if not search_entry.get().strip():
                search_entry.insert(0, "Find a host or device...")

        search_entry.bind("<FocusIn>", _clear_placeholder)
        search_entry.bind("<FocusOut>", _restore_placeholder)

        # Toolbar chips — rounded containers
        toolbar = tk.Frame(topbar, bg=BG)
        toolbar.pack(side="right", padx=(10, 0))

        def _make_chip(parent: tk.Frame, text: str) -> None:
            chip_canvas, chip_inner = self._create_rounded_container(
                parent,
                outer_bg=BG,
                fill_color=UI_COLORS["panel_soft"],
                border_color=UI_COLORS["line"],
                radius=UI_STYLE_KIT["radius_chip"],
                border_width=1,
                min_height=UI_STYLE_KIT["height_chip"],
            )
            chip_canvas.configure(width=76)
            chip_canvas.pack(side="left", padx=(0, 6))
            chip_lbl = tk.Label(
                chip_inner,
                text=text,
                bg=UI_COLORS["panel_soft"],
                fg=UI_COLORS["muted"],
                font=UI_FONTS["label_sm_bold"],
            )
            chip_lbl.pack(fill="both", expand=True)

            def _enter(_e, c=chip_canvas, lbl=chip_lbl) -> None:
                c._rounded_fill = UI_COLORS["chip_hover"]  # type: ignore[attr-defined]
                self._set_rounded_style(c, UI_COLORS["line_soft"], 1)
                lbl.configure(bg=UI_COLORS["chip_hover"], fg=UI_COLORS["text"])

            def _leave(_e, c=chip_canvas, lbl=chip_lbl) -> None:
                c._rounded_fill = UI_COLORS["panel_soft"]  # type: ignore[attr-defined]
                self._set_rounded_style(c, UI_COLORS["line"], 1)
                lbl.configure(bg=UI_COLORS["panel_soft"], fg=UI_COLORS["muted"])

            for w in (chip_canvas, chip_inner, chip_lbl):
                w.bind("<Enter>", _enter)
                w.bind("<Leave>", _leave)

        for chip_text in ("⊞ Grid", "⌕ Filter"):
            _make_chip(toolbar, chip_text)

        # Horizontal divider
        tk.Frame(self.ui_root, bg=UI_COLORS["line"], height=1).pack(fill="x", pady=(8, 0))

        # Tabs row — opened devices
        tabs_bar = tk.Frame(self.ui_root, bg=BG)
        tabs_bar.pack(fill="x", padx=14, pady=(4, 0))

        self.open_tabs_frame = tk.Frame(tabs_bar, bg=BG)
        self.open_tabs_frame.pack(side="left", fill="x", expand=True)
        self._refresh_open_tabs()

        # Horizontal divider under tabs
        tk.Frame(self.ui_root, bg=UI_COLORS["line"], height=1).pack(fill="x", pady=(4, 0))

    def _build_left_panel(self, panel: tk.Frame) -> None:
        S = UI_COLORS["sidebar"]

        # --- Logo block ---
        logo_block = tk.Frame(panel, bg=S)
        logo_block.pack(fill="x", padx=14, pady=(18, 14))

        logo_icon = self._create_icon_badge(logo_block, "FW", UI_COLORS["accent"], size=40, radius=14)
        logo_icon.pack(side="left")

        logo_text = tk.Frame(logo_block, bg=S)
        logo_text.pack(side="left", padx=(10, 0))
        tk.Label(
            logo_text,
            text="FortiAnalyzer",
            bg=S,
            fg=UI_COLORS["text"],
            font=UI_FONTS["sidebar_logo"],
            anchor="w",
        ).pack(anchor="w")
        tk.Label(
            logo_text,
            text="Device Vault",
            bg=S,
            fg=UI_COLORS["muted"],
            font=UI_FONTS["sidebar_logo_sub"],
            anchor="w",
        ).pack(anchor="w")

        # --- Divider ---
        tk.Frame(panel, bg=UI_COLORS["line"], height=1).pack(fill="x", padx=10)

        # --- Navigation items ---
        nav_frame = tk.Frame(panel, bg=S)
        nav_frame.pack(fill="x", pady=(8, 0))

        # nav_item_data: (icon, label, cmd)
        nav_items = [
            ("▦", "Устройства",  self._show_cards_view),
            ("◎", "Адреса",      self._show_addresses_for_selected_device),
            ("⊛", "Дубликаты",   self._show_address_duplicates_for_selected_device),
            ("⊕", "Группы",      self._open_group_sorting_for_selected_device),
            ("⇄", "Перенос",     self._open_transfer_direction_for_selected_device),
        ]

        self._sidebar_item_frames: list = []
        self._active_nav_item: Optional[tk.Frame] = None

        def _make_nav_item(parent: tk.Frame, icon: str, label: str, cmd, is_primary: bool = True) -> tk.Frame:
            item = tk.Frame(parent, bg=S, cursor="hand2", height=38)
            item.pack(fill="x")
            item.pack_propagate(False)

            # Active left-border indicator
            indicator = tk.Frame(item, bg=S, width=3)
            indicator.pack(side="left", fill="y")

            row = tk.Frame(item, bg=S)
            row.pack(side="left", fill="both", expand=True, padx=(12, 8))

            icon_lbl = tk.Label(
                row,
                text=icon,
                bg=S,
                fg=UI_COLORS["muted"],
                font=UI_FONTS["label_md"],
                width=2,
                anchor="center",
            )
            icon_lbl.pack(side="left")

            text_lbl = tk.Label(
                row,
                text=label,
                bg=S,
                fg=UI_COLORS["muted"],
                font=UI_FONTS["sidebar_item"],
                anchor="w",
            )
            text_lbl.pack(side="left", padx=(6, 0))

            def _activate(f=item, ind=indicator, il=icon_lbl, tl=text_lbl) -> None:
                if self._active_nav_item and self._active_nav_item is not f:
                    prev = self._active_nav_item
                    prev_ind = prev.winfo_children()[0]
                    prev_row = prev.winfo_children()[1] if len(prev.winfo_children()) > 1 else None
                    prev.configure(bg=S)
                    prev_ind.configure(bg=S)
                    if prev_row:
                        for w in prev_row.winfo_children():
                            w.configure(bg=S, fg=UI_COLORS["muted"])
                self._active_nav_item = f
                f.configure(bg=UI_COLORS["sidebar_item_active"])
                ind.configure(bg=UI_COLORS["accent"])
                row.configure(bg=UI_COLORS["sidebar_item_active"])
                il.configure(bg=UI_COLORS["sidebar_item_active"], fg=UI_COLORS["text"])
                tl.configure(bg=UI_COLORS["sidebar_item_active"], fg=UI_COLORS["text"])

            def _on_enter(_e, f=item, ind=indicator, r=row, il=icon_lbl, tl=text_lbl) -> None:
                if self._active_nav_item is not f:
                    f.configure(bg=UI_COLORS["sidebar_item_hover"])
                    r.configure(bg=UI_COLORS["sidebar_item_hover"])
                    il.configure(bg=UI_COLORS["sidebar_item_hover"], fg=UI_COLORS["sidebar_text_active"])
                    tl.configure(bg=UI_COLORS["sidebar_item_hover"], fg=UI_COLORS["sidebar_text_active"])

            def _on_leave(_e, f=item, ind=indicator, r=row, il=icon_lbl, tl=text_lbl) -> None:
                if self._active_nav_item is not f:
                    f.configure(bg=S)
                    r.configure(bg=S)
                    il.configure(bg=S, fg=UI_COLORS["muted"])
                    tl.configure(bg=S, fg=UI_COLORS["muted"])

            def _on_click(_e, c=cmd, act=_activate) -> None:
                act()
                c()

            for w in (item, row, icon_lbl, text_lbl):
                w.bind("<Enter>", _on_enter)
                w.bind("<Leave>", _on_leave)
                w.bind("<Button-1>", _on_click)

            return item

        for icon, label, cmd in nav_items:
            nav_item = _make_nav_item(nav_frame, icon, label, cmd)
            self._sidebar_item_frames.append(nav_item)

        # Activate first item by default
        if self._sidebar_item_frames:
            first = self._sidebar_item_frames[0]
            self._active_nav_item = first
            first.configure(bg=UI_COLORS["sidebar_item_active"])
            children = first.winfo_children()
            if children:
                children[0].configure(bg=UI_COLORS["accent"])  # indicator
            if len(children) > 1:
                for w in children[1].winfo_children():
                    w.configure(bg=UI_COLORS["sidebar_item_active"], fg=UI_COLORS["text"])

        # --- Divider ---
        tk.Frame(panel, bg=UI_COLORS["line"], height=1).pack(fill="x", padx=10, pady=(8, 0))

        # --- Secondary nav ---
        secondary_frame = tk.Frame(panel, bg=S)
        secondary_frame.pack(fill="x", pady=(4, 0))

        secondary_items = [
            ("↑", "Обновления",  self.check_for_updates),
            ("↻", "Обновить",    self._load_devices),
        ]
        for icon, label, cmd in secondary_items:
            _make_nav_item(secondary_frame, icon, label, cmd, is_primary=False)

        # --- Add device button at bottom ---
        bottom = tk.Frame(panel, bg=S)
        bottom.pack(side="bottom", fill="x", padx=12, pady=14)

        add_canvas, add_inner = self._create_rounded_container(
            bottom,
            outer_bg=S,
            fill_color=UI_COLORS["accent"],
            border_color=UI_COLORS["accent"],
            radius=UI_STYLE_KIT["radius_control"],
            border_width=0,
            min_height=UI_STYLE_KIT["height_button_md"],
        )
        add_canvas.pack(fill="x")
        add_lbl = tk.Label(
            add_inner,
            text="+ Добавить устройство",
            bg=UI_COLORS["accent"],
            fg="#FFFFFF",
            font=UI_FONTS["sidebar_item_bold"],
            cursor="hand2",
        )
        add_lbl.pack(fill="both", expand=True)

        def _add_hover(_e) -> None:
            add_canvas._rounded_fill = UI_COLORS["accent_hover"]  # type: ignore[attr-defined]
            self._set_rounded_style(add_canvas, UI_COLORS["accent_hover"], 0)
            add_lbl.configure(bg=UI_COLORS["accent_hover"])
            add_inner.configure(bg=UI_COLORS["accent_hover"])

        def _add_leave(_e) -> None:
            add_canvas._rounded_fill = UI_COLORS["accent"]  # type: ignore[attr-defined]
            self._set_rounded_style(add_canvas, UI_COLORS["accent"], 0)
            add_lbl.configure(bg=UI_COLORS["accent"])
            add_inner.configure(bg=UI_COLORS["accent"])

        for w in (add_canvas, add_inner, add_lbl):
            w.bind("<Enter>", _add_hover)
            w.bind("<Leave>", _add_leave)
            w.bind("<Button-1>", lambda _e: self.open_add_device_dialog())

        # --- Version label ---
        tk.Label(
            bottom,
            text=f"{self.local_version}",
            bg=S,
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_xs"],
        ).pack(pady=(8, 0))

    def _build_center_panel(self, panel: tk.Frame) -> None:
        PS = UI_COLORS["panel_soft"]

        # Section toolbar — Termius-style
        toolbar = tk.Frame(panel, bg=PS)
        toolbar.pack(fill="x", padx=14, pady=(12, 8))

        tk.Label(
            toolbar,
            text="Устройства",
            bg=PS,
            fg=UI_COLORS["text"],
            font=UI_FONTS["title_md_bold"],
        ).pack(side="left")

        tk.Label(
            toolbar,
            textvariable=self.status_var,
            bg=PS,
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_sm"],
        ).pack(side="left", padx=(10, 0))

        self._create_round_button(
            toolbar,
            "+ Новое",
            self.open_add_device_dialog,
            min_height=UI_STYLE_KIT["height_button_sm"],
        ).pack(side="right")

        # Divider under toolbar
        tk.Frame(panel, bg=UI_COLORS["line"], height=1).pack(fill="x")

        # Scrollable cards area — flat, no wrapper container
        cards_outer = tk.Frame(panel, bg=PS)
        cards_outer.pack(fill="both", expand=True)
        self.cards_outer_frame = cards_outer

        canvas = tk.Canvas(cards_outer, bg=PS, highlightthickness=0)
        scroll = self._create_scrollbar(cards_outer, canvas.yview)
        frame = tk.Frame(canvas, bg=PS)
        frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._bind_vertical_mousewheel(canvas, canvas, frame, cards_outer)
        self.cards_canvas = canvas
        self.cards_frame = frame
        self.cards_wrap_canvas = None

        self.editor_canvas, editor_wrap = self._create_rounded_container(
            panel,
            outer_bg=UI_COLORS["panel_soft"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["accent_soft"],
            radius=UI_STYLE_KIT["radius_block"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_main_card"],
        )
        editor_header = tk.Frame(editor_wrap, bg=UI_COLORS["panel_soft"])
        editor_header.pack(fill="x", pady=(4, 8))
        tk.Label(
            editor_header,
            textvariable=self.editor_title_var,
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            font=UI_FONTS["label_lg_bold"],
            anchor="w",
        ).pack(side="left")
        tk.Label(
            editor_header,
            textvariable=self.editor_file_var,
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_sm"],
        ).pack(side="left", padx=(10, 0))
        self._create_round_button(editor_header, "Сохранить", self._save_editor_content, min_height=UI_STYLE_KIT["height_device_menu_item"]).pack(side="right")

        editor_text_wrap = tk.Frame(editor_wrap, bg=UI_COLORS["panel_soft"])
        editor_text_wrap.pack(fill="both", expand=True)
        self.editor_text = tk.Text(
            editor_text_wrap,
            wrap="none",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["text"],
            insertbackground=UI_COLORS["text"],
            relief="flat",
            undo=True,
        )
        editor_scroll = self._create_scrollbar(editor_text_wrap, self.editor_text.yview)
        self.editor_text.configure(yscrollcommand=editor_scroll.set)
        self.editor_text.pack(side="left", fill="both", expand=True)
        editor_scroll.pack(side="right", fill="y")
        self.editor_canvas.pack_forget()

        self.device_page_canvas, device_page_wrap = self._create_rounded_container(
            panel,
            outer_bg=UI_COLORS["panel_soft"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["accent_soft"],
            radius=UI_STYLE_KIT["radius_block"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_main_card"],
        )
        device_page_scroll_canvas = tk.Canvas(device_page_wrap, bg=UI_COLORS["panel_soft"], highlightthickness=0)
        device_page_scroll = self._create_scrollbar(device_page_wrap, device_page_scroll_canvas.yview)
        device_page_content = tk.Frame(device_page_scroll_canvas, bg=UI_COLORS["panel_soft"])
        device_page_window = device_page_scroll_canvas.create_window((0, 0), window=device_page_content, anchor="nw")
        device_page_content.bind("<Configure>", lambda _event: device_page_scroll_canvas.configure(scrollregion=device_page_scroll_canvas.bbox("all")))
        device_page_scroll_canvas.bind(
            "<Configure>",
            lambda event: device_page_scroll_canvas.itemconfigure(device_page_window, width=event.width),
        )
        device_page_scroll_canvas.configure(yscrollcommand=device_page_scroll.set)
        device_page_scroll_canvas.pack(side="left", fill="both", expand=True)
        device_page_scroll.pack(side="right", fill="y")
        self.device_page_scroll_canvas = device_page_scroll_canvas
        self._bind_vertical_mousewheel(device_page_scroll_canvas, device_page_scroll_canvas, device_page_content)

        device_header = tk.Frame(device_page_content, bg=UI_COLORS["panel_soft"])
        device_header.pack(fill="x", pady=(4, 8))
        tk.Label(
            device_header,
            textvariable=self.device_page_title_var,
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            font=UI_FONTS["title_lg_bold"],
            anchor="w",
        ).pack(side="left")

        card_canvas, card = self._create_rounded_container(
            device_page_content,
            outer_bg=UI_COLORS["panel_soft"],
            fill_color=UI_COLORS["panel"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_inventory_panel"],
        )
        card_canvas.pack(fill="x", pady=(0, 8))
        card.configure(padx=12, pady=10)
        self._build_detail_row(card, "Имя", self.device_page_status_var)
        self._build_detail_row(card, "Конфиг", self.device_page_config_added_var)
        self._build_detail_row(card, "Excel", self.device_page_excel_var)
        self._build_detail_row(card, "CSV", self.device_page_csv_var)
        self._build_detail_row(card, "Папка", self.device_page_folder_var)

        actions = tk.Frame(device_page_content, bg=UI_COLORS["panel_soft"])
        actions.pack(fill="x", pady=(4, UI_SPACING["section"]))
        self._create_round_button(actions, "Добавить/заменить конфиг", self.attach_config_to_selected_device).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Добавить адреса", self._open_transfer_direction_for_selected_device).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Посмотреть адреса", self._show_addresses_for_selected_device).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Сортировка по группам", self._open_group_sorting_for_selected_device).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Найти дубликаты", self._show_address_duplicates_for_selected_device).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Открыть встроенный редактор", self._open_selected_device_editor).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Открыть Excel", self.open_selected_excel).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Открыть CSV", self.open_selected_config).pack(fill="x")
        self.device_page_canvas.pack_forget()

    def _build_right_panel(self, panel: tk.Frame) -> None:
        P = UI_COLORS["panel"]

        panel_scroll_canvas = tk.Canvas(panel, bg=P, highlightthickness=0)
        panel_scroll = self._create_scrollbar(panel, panel_scroll_canvas.yview)
        panel_content = tk.Frame(panel_scroll_canvas, bg=P)
        panel_window = panel_scroll_canvas.create_window((0, 0), window=panel_content, anchor="nw")
        panel_content.bind("<Configure>", lambda _event: panel_scroll_canvas.configure(scrollregion=panel_scroll_canvas.bbox("all")))
        panel_scroll_canvas.bind("<Configure>", lambda event: panel_scroll_canvas.itemconfigure(panel_window, width=event.width))
        panel_scroll_canvas.configure(yscrollcommand=panel_scroll.set)
        panel_scroll_canvas.pack(side="left", fill="both", expand=True)
        panel_scroll.pack(side="right", fill="y")
        self._bind_vertical_mousewheel(panel_scroll_canvas, panel_scroll_canvas, panel_content)

        # Section header
        title_row = tk.Frame(panel_content, bg=P)
        title_row.pack(fill="x", padx=14, pady=(14, 10))
        tk.Label(
            title_row,
            text="Host Details",
            bg=P,
            fg=UI_COLORS["text"],
            font=UI_FONTS["title_md_bold"],
        ).pack(side="left")

        # Divider
        tk.Frame(panel_content, bg=UI_COLORS["line"], height=1).pack(fill="x", padx=0)

        # Hosts list (flat, no rounded container)
        hosts_section = tk.Frame(panel_content, bg=P)
        hosts_section.pack(fill="x", padx=14, pady=(10, 0))
        tk.Label(
            hosts_section,
            text="УСТРОЙСТВА",
            bg=P,
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_xs"],
        ).pack(anchor="w", pady=(0, 6))

        hosts_canvas = tk.Canvas(hosts_section, height=160, bg=P, highlightthickness=0)
        hosts_scroll = self._create_scrollbar(hosts_section, hosts_canvas.yview)
        hosts_frame = tk.Frame(hosts_canvas, bg=P)
        hosts_frame.bind("<Configure>", lambda event: hosts_canvas.configure(scrollregion=hosts_canvas.bbox("all")))
        hosts_canvas.create_window((0, 0), window=hosts_frame, anchor="nw")
        hosts_canvas.configure(yscrollcommand=hosts_scroll.set)
        hosts_canvas.pack(side="left", fill="x", expand=True)
        hosts_scroll.pack(side="right", fill="y")
        self._bind_vertical_mousewheel(hosts_canvas, hosts_canvas, hosts_frame, fallback_canvas=panel_scroll_canvas)
        self.hosts_canvas = hosts_canvas
        self.hosts_frame = hosts_frame

        # Divider
        tk.Frame(panel_content, bg=UI_COLORS["line"], height=1).pack(fill="x", padx=0, pady=(10, 0))

        # Details section (flat rows)
        details_section = tk.Frame(panel_content, bg=P)
        details_section.pack(fill="x", padx=14, pady=(10, 0))
        tk.Label(
            details_section,
            text="ИНФОРМАЦИЯ",
            bg=P,
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_xs"],
        ).pack(anchor="w", pady=(0, 8))

        self.details_vars = {
            "name": tk.StringVar(value="-"),
            "folder": tk.StringVar(value="-"),
            "config": tk.StringVar(value="-"),
            "excel": tk.StringVar(value="-"),
            "csv": tk.StringVar(value="-"),
            "updated": tk.StringVar(value="-"),
        }
        self._build_detail_row(details_section, "Имя", self.details_vars["name"])
        self._build_detail_row(details_section, "Папка", self.details_vars["folder"])
        self._build_detail_row(details_section, "Конфиг", self.details_vars["config"])
        self._build_detail_row(details_section, "Excel", self.details_vars["excel"])
        self._build_detail_row(details_section, "CSV", self.details_vars["csv"])
        self._build_detail_row(details_section, "Обновлено", self.details_vars["updated"])

        # Divider
        tk.Frame(panel_content, bg=UI_COLORS["line"], height=1).pack(fill="x", padx=0, pady=(4, 0))

        # Actions
        actions = tk.Frame(panel_content, bg=P)
        actions.pack(fill="x", padx=14, pady=(10, 14))
        self._create_round_button(actions, "Добавить/заменить конфиг", self.attach_config_to_selected_device).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Открыть CSV конфиг", self.open_selected_config).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Открыть Excel", self.open_selected_excel).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Удалить устройство", self.delete_selected_device, style_kind="danger").pack(fill="x")

    def _build_detail_row(self, parent: tk.Frame, label: str, value_var: tk.StringVar) -> None:
        P = UI_COLORS["panel"]
        row = tk.Frame(parent, bg=P)
        row.pack(fill="x", pady=(0, 6))
        tk.Label(
            row,
            text=label,
            width=9,
            anchor="w",
            bg=P,
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_sm"],
        ).pack(side="left", padx=(0, 8))
        tk.Label(
            row,
            textvariable=value_var,
            anchor="w",
            justify="left",
            bg=P,
            fg=UI_COLORS["text"],
            font=UI_FONTS["label_sm"],
            wraplength=200,
        ).pack(side="left", fill="x", expand=True)
        tk.Frame(parent, bg=UI_COLORS["line"], height=1).pack(fill="x")

    def _draw_rounded_rect(
        self,
        canvas: tk.Canvas,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        radius: int,
        fill: str,
        outline: str,
        width: int,
        tag: str,
    ) -> None:
        r = max(2, min(radius, (x2 - x1) // 2, (y2 - y1) // 2))
        points = [
            x1 + r,
            y1,
            x2 - r,
            y1,
            x2,
            y1,
            x2,
            y1 + r,
            x2,
            y2 - r,
            x2,
            y2,
            x2 - r,
            y2,
            x1 + r,
            y2,
            x1,
            y2,
            x1,
            y2 - r,
            x1,
            y1 + r,
            x1,
            y1,
        ]
        canvas.create_polygon(
            points,
            smooth=True,
            splinesteps=18,
            fill=fill,
            outline=outline,
            width=width,
            tags=(tag,),
        )

    def _create_rounded_container(
        self,
        parent: tk.Widget,
        outer_bg: str,
        fill_color: str,
        border_color: str,
        radius: int,
        border_width: int = 1,
        min_height: int = UI_STYLE_KIT["height_container_min"],
    ) -> tuple[tk.Canvas, tk.Frame]:
        canvas = tk.Canvas(parent, bg=outer_bg, highlightthickness=0, bd=0, height=min_height)
        inner = tk.Frame(canvas, bg=fill_color)
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas._rounded_fill = fill_color  # type: ignore[attr-defined]
        canvas._rounded_border = border_color  # type: ignore[attr-defined]
        canvas._rounded_radius = radius  # type: ignore[attr-defined]
        canvas._rounded_border_width = border_width  # type: ignore[attr-defined]
        canvas._rounded_min_height = min_height  # type: ignore[attr-defined]
        canvas._rounded_window_id = window_id  # type: ignore[attr-defined]
        canvas.bind("<Configure>", lambda _event, c=canvas: self._redraw_rounded_canvas(c))
        self._redraw_rounded_canvas(canvas)
        return canvas, inner

    def _redraw_rounded_canvas(self, canvas: tk.Canvas) -> None:
        width = max(canvas.winfo_width(), 40)
        min_height = getattr(canvas, "_rounded_min_height", UI_STYLE_KIT["height_container_min"])
        height = max(canvas.winfo_height(), min_height)
        fill_color = getattr(canvas, "_rounded_fill", UI_COLORS["panel"])
        border_color = getattr(canvas, "_rounded_border", UI_COLORS["line"])
        radius = getattr(canvas, "_rounded_radius", UI_STYLE_KIT["radius_control"])
        border_width = getattr(canvas, "_rounded_border_width", 1)
        window_id = getattr(canvas, "_rounded_window_id", None)
        canvas.delete("shape")
        self._draw_rounded_rect(
            canvas,
            1,
            1,
            width - 2,
            height - 2,
            radius=radius,
            fill=fill_color,
            outline=border_color,
            width=border_width,
            tag="shape",
        )
        if window_id is not None:
            inset = max(6, border_width + 4)
            canvas.coords(window_id, inset, inset)
            canvas.itemconfigure(window_id, width=max(10, width - inset * 2), height=max(10, height - inset * 2))

    def _set_rounded_style(self, canvas: tk.Canvas, border_color: str, border_width: int) -> None:
        canvas._rounded_border = border_color  # type: ignore[attr-defined]
        canvas._rounded_border_width = border_width  # type: ignore[attr-defined]
        self._redraw_rounded_canvas(canvas)

    @staticmethod
    def _hex_lerp(color_a: str, color_b: str, t: float) -> str:
        """Interpolate between two hex colors (#RRGGBB). t=0 → a, t=1 → b."""
        def _parse(c: str) -> tuple:
            c = c.lstrip("#")
            return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
        ra, ga, ba = _parse(color_a)
        rb, gb, bb = _parse(color_b)
        r = int(ra + (rb - ra) * t)
        g = int(ga + (gb - ga) * t)
        b = int(ba + (bb - ba) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _animate_hover(
        self,
        canvas: tk.Canvas,
        widgets: list,
        color_from: str,
        color_to: str,
        border_color: str,
        border_width: int,
        steps: int = 6,
        delay: int = 16,
        _step: int = 0,
    ) -> None:
        """Smooth color transition for hover effects (runs via after())."""
        if _step > steps:
            return
        t = _step / steps
        mid = self._hex_lerp(color_from, color_to, t)
        try:
            canvas._rounded_fill = mid  # type: ignore[attr-defined]
            self._set_rounded_style(canvas, border_color, border_width)
            for w in widgets:
                w.configure(bg=mid)
        except tk.TclError:
            return
        self.root.after(
            delay,
            lambda: self._animate_hover(canvas, widgets, color_from, color_to, border_color, border_width, steps, delay, _step + 1),
        )

    def _create_icon_badge(
        self,
        parent: tk.Widget,
        text: str,
        bg_color: str,
        *,
        fg: str = "#FFFFFF",
        size: int = 32,
        radius: int = 10,
    ) -> tk.Canvas:
        """Rounded square icon badge drawn on Canvas."""
        outer_bg = parent.cget("bg") if hasattr(parent, "cget") else UI_COLORS["panel"]
        canvas = tk.Canvas(parent, width=size, height=size, bg=outer_bg, highlightthickness=0, bd=0)
        canvas.create_polygon(
            radius, 0,
            size - radius, 0,
            size, 0,
            size, radius,
            size, size - radius,
            size, size,
            size - radius, size,
            radius, size,
            0, size,
            0, size - radius,
            0, radius,
            0, 0,
            smooth=True, splinesteps=12,
            fill=bg_color, outline=bg_color,
        )
        canvas.create_text(size // 2, size // 2, text=text, fill=fg, font=UI_FONTS["label_sm_bold"])
        return canvas

    def _create_round_button(
        self,
        parent: tk.Widget,
        text: str,
        command,
        *,
        style_kind: str = "primary",
        min_height: int = UI_STYLE_KIT["control_height"],
    ) -> tk.Canvas:
        palette = UI_BUTTON_STYLES.get(style_kind, UI_BUTTON_STYLES["primary"])
        cfg = {
            "fill": UI_COLORS[palette["fill"]],
            "hover": UI_COLORS[palette["hover"]],
            "border": UI_COLORS[palette["border"]],
            "fg": UI_COLORS[palette["fg"]],
        }
        canvas, inner = self._create_rounded_container(
            parent,
            outer_bg=parent.cget("bg"),
            fill_color=cfg["fill"],
            border_color=cfg["border"],
            radius=UI_STYLE_KIT["radius_control"],
            border_width=1,
            min_height=min_height,
        )
        label = tk.Label(
            inner,
            text=text,
            bg=cfg["fill"],
            fg=cfg["fg"],
            font=UI_FONTS["action_bold"],
            anchor="center",
        )
        label.pack(fill="both", expand=True)

        def on_enter(_event) -> None:
            canvas._rounded_fill = cfg["hover"]  # type: ignore[attr-defined]
            self._set_rounded_style(canvas, UI_COLORS["accent_soft"], 1)
            label.configure(bg=cfg["hover"])

        def on_leave(_event) -> None:
            canvas._rounded_fill = cfg["fill"]  # type: ignore[attr-defined]
            self._set_rounded_style(canvas, cfg["border"], 1)
            label.configure(bg=cfg["fill"])

        def on_click(_event) -> None:
            command()

        for widget in (canvas, inner, label):
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)
            widget.bind("<Button-1>", on_click)
        return canvas

    def _create_round_entry(
        self, parent: tk.Widget, text_var: tk.StringVar, *, min_height: int = UI_STYLE_KIT["control_height"]
    ) -> tuple[tk.Canvas, tk.Entry]:
        bg_parent = parent.cget("bg") if hasattr(parent, "cget") else UI_COLORS["panel"]
        shell, body = self._create_rounded_container(
            parent,
            outer_bg=bg_parent,
            fill_color=UI_COLORS["panel"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_control"],
            border_width=1,
            min_height=min_height,
        )
        entry = tk.Entry(
            body,
            textvariable=text_var,
            relief="flat",
            bd=0,
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["text"],
            insertbackground=UI_COLORS["text"],
            highlightthickness=0,
            font=UI_FONTS["label_md"],
        )
        entry.pack(fill="both", expand=True, padx=10, pady=3)
        return shell, entry

    def _create_scrollbar(self, parent: tk.Widget, command) -> tk.Scrollbar:
        # Keep scrollbar native so macOS renders system style.
        return tk.Scrollbar(parent, orient="vertical", command=command, relief="flat", bd=0, highlightthickness=0)

    @staticmethod
    def _scroll_units_from_event(event: tk.Event) -> int:
        delta = getattr(event, "delta", 0)
        if delta:
            return -1 if delta > 0 else 1
        num = getattr(event, "num", 0)
        if num == 4:
            return -1
        if num == 5:
            return 1
        return 0

    def _ensure_global_wheel_binding(self) -> None:
        if self._global_wheel_bound:
            return
        self.root.bind_all("<MouseWheel>", self._on_global_mousewheel, add="+")
        self.root.bind_all("<Button-4>", self._on_global_mousewheel, add="+")
        self.root.bind_all("<Button-5>", self._on_global_mousewheel, add="+")
        self._global_wheel_bound = True

    def _resolve_scroll_target_for_widget(self, widget: Optional[tk.Widget]) -> Optional[tk.Canvas]:
        current = widget
        while current is not None:
            target = self._scroll_widget_targets.get(str(current))
            if target is not None:
                return target
            parent_name = current.winfo_parent()
            if not parent_name:
                break
            try:
                current = current.nametowidget(parent_name)
            except Exception:
                break
        return None

    @staticmethod
    def _scroll_canvas_once(canvas: tk.Canvas, units: int) -> bool:
        if units == 0:
            return False
        first, last = canvas.yview()
        can_scroll_up = first > 0.0
        can_scroll_down = last < 1.0
        if (units < 0 and not can_scroll_up) or (units > 0 and not can_scroll_down):
            return False
        canvas.yview_scroll(units, "units")
        return True

    def _scroll_with_fallback(self, target_canvas: tk.Canvas, units: int) -> bool:
        current: Optional[tk.Canvas] = target_canvas
        while current is not None:
            if self._scroll_canvas_once(current, units):
                return True
            current = self._scroll_fallback_targets.get(str(current))
        return False

    def _on_global_mousewheel(self, event: tk.Event) -> str:
        units = self._scroll_units_from_event(event)
        if not units:
            return ""
        event_widget = event.widget if isinstance(event.widget, tk.Widget) else None
        target = self._resolve_scroll_target_for_widget(event_widget) or self._active_scroll_canvas
        if target is None:
            return ""
        if self._scroll_with_fallback(target, units):
            return "break"
        return ""

    def _bind_vertical_mousewheel(
        self,
        target_canvas: tk.Canvas,
        *widgets: tk.Widget,
        fallback_canvas: Optional[tk.Canvas] = None,
    ) -> None:
        self._ensure_global_wheel_binding()
        if fallback_canvas is not None:
            self._scroll_fallback_targets[str(target_canvas)] = fallback_canvas

        visited: Set[str] = set()

        def _mark_active(event: tk.Event) -> None:
            event_widget = event.widget if isinstance(event.widget, tk.Widget) else None
            resolved = self._resolve_scroll_target_for_widget(event_widget)
            if resolved is not None:
                self._active_scroll_canvas = resolved

        def _bind_recursive(widget: tk.Widget) -> None:
            widget_id = str(widget)
            if widget_id in visited:
                return
            visited.add(widget_id)
            self._scroll_widget_targets[widget_id] = target_canvas
            widget.bind("<Button-1>", _mark_active, add="+")
            for child in widget.winfo_children():
                _bind_recursive(child)

        for widget in widgets:
            _bind_recursive(widget)

    def _attach_text_context_menu(self, text_widget: tk.Text, *, allow_edit_actions: bool = True) -> None:
        menu = tk.Menu(text_widget, tearoff=False)
        if allow_edit_actions:
            menu.add_command(label="Вырезать", command=lambda: text_widget.event_generate("<<Cut>>"))
        menu.add_command(label="Копировать", command=lambda: text_widget.event_generate("<<Copy>>"))
        if allow_edit_actions:
            menu.add_command(label="Вставить", command=lambda: text_widget.event_generate("<<Paste>>"))
            menu.add_separator()
            menu.add_command(label="Выделить все", command=lambda: text_widget.tag_add("sel", "1.0", "end-1c"))

        def _show_menu(event: tk.Event) -> str:
            text_widget.focus_set()
            menu.tk_popup(event.x_root, event.y_root)
            return "break"

        text_widget.bind("<Button-2>", _show_menu)
        text_widget.bind("<Button-3>", _show_menu)
        text_widget.bind("<Control-v>", lambda _e: (text_widget.event_generate("<<Paste>>"), "break")[1])
        text_widget.bind("<Command-v>", lambda _e: (text_widget.event_generate("<<Paste>>"), "break")[1])
        text_widget.bind("<Shift-Insert>", lambda _e: (text_widget.event_generate("<<Paste>>"), "break")[1])

    def _create_action_menu(self, device_name: str) -> None:
        self.select_device(device_name)
        menu = tk.Toplevel(self.root)
        menu.title("")
        menu.overrideredirect(True)
        menu.configure(bg=UI_COLORS["bg"])
        menu.transient(self.root)
        x = self.root.winfo_pointerx()
        y = self.root.winfo_pointery()
        menu.geometry(f"+{x}+{y}")

        shell, content = self._create_rounded_container(
            menu,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_block"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_dropdown"],
        )
        shell.pack(fill="both", expand=True)

        def _run_and_close(fn) -> None:
            menu.destroy()
            fn()

        self._create_round_button(content, "Открыть встроенный редактор", lambda: _run_and_close(lambda: self._open_device_editor(device_name))).pack(
            fill="x", padx=10, pady=(10, 6)
        )
        self._create_round_button(content, "Открыть страницу устройства", lambda: _run_and_close(lambda: self._open_device_page(device_name))).pack(
            fill="x", padx=10, pady=(0, 6)
        )
        self._create_round_button(content, "Добавить/заменить конфиг", lambda: _run_and_close(self.attach_config_to_selected_device)).pack(
            fill="x", padx=10, pady=(0, 6)
        )
        self._create_round_button(content, "Открыть CSV конфиг", lambda: _run_and_close(self.open_selected_config)).pack(
            fill="x", padx=10, pady=(0, 6)
        )
        self._create_round_button(content, "Открыть Excel", lambda: _run_and_close(self.open_selected_excel)).pack(
            fill="x", padx=10, pady=(0, 6)
        )
        self._create_round_button(content, "Удалить устройство", lambda: _run_and_close(self.delete_selected_device), style_kind="danger").pack(
            fill="x", padx=10, pady=(0, 10)
        )

        menu.bind("<FocusOut>", lambda _e: menu.destroy())
        menu.focus_force()

    def _choose_device_dialog(self, title: str, prompt: str, *, exclude_name: Optional[str] = None) -> Optional[str]:
        options = sorted([name for name in self.devices.keys() if name != exclude_name], key=str.lower)
        if not options:
            messagebox.showwarning("Нет устройств", "Нет доступных устройств для выбора.")
            return None
        decision = {"value": None}
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("520x180")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])
        body_canvas, body = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_color_picker"],
        )
        body_canvas.pack(fill="both", expand=True, padx=10, pady=10)
        tk.Label(body, text=prompt, bg=UI_COLORS["panel_soft"], fg=UI_COLORS["text"], anchor="w", justify="left").pack(fill="x", pady=(8, 8))
        selected_var = tk.StringVar(value=options[0])
        ttk.Combobox(body, values=options, textvariable=selected_var, state="readonly", width=32, style="Vault.TCombobox").pack(anchor="w")

        actions = tk.Frame(body, bg=UI_COLORS["panel_soft"])
        actions.pack(fill="x", pady=(10, 0))

        def on_ok() -> None:
            decision["value"] = selected_var.get().strip()
            dialog.destroy()

        self._create_round_button(actions, "Выбрать", on_ok).pack(side="right")
        self._create_round_button(actions, "Отмена", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))
        self.root.wait_window(dialog)
        return decision["value"]

    def _choose_devices_dialog(self, title: str, prompt: str, *, exclude_name: Optional[str] = None) -> List[str]:
        options = sorted([name for name in self.devices.keys() if name != exclude_name], key=str.lower)
        if not options:
            messagebox.showwarning("Нет устройств", "Нет доступных устройств для выбора.")
            return []

        selection: Dict[str, List[str]] = {"values": []}
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("560x420")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        body_canvas, body = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_transfer_editor"],
        )
        body_canvas.pack(fill="both", expand=True, padx=10, pady=10)

        tk.Label(body, text=prompt, bg=UI_COLORS["panel_soft"], fg=UI_COLORS["text"], anchor="w", justify="left").pack(fill="x", pady=(8, 8))

        list_wrap = tk.Frame(body, bg=UI_COLORS["panel_soft"])
        list_wrap.pack(fill="both", expand=True)
        listbox = tk.Listbox(
            list_wrap,
            selectmode="multiple",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["text"],
            relief="flat",
            highlightthickness=0,
            activestyle="none",
        )
        list_scroll = self._create_scrollbar(list_wrap, listbox.yview)
        listbox.configure(yscrollcommand=list_scroll.set)
        listbox.pack(side="left", fill="both", expand=True)
        list_scroll.pack(side="right", fill="y")
        for name in options:
            listbox.insert("end", name)
        self._bind_vertical_mousewheel(listbox, listbox, list_wrap, body)

        actions = tk.Frame(body, bg=UI_COLORS["panel_soft"])
        actions.pack(fill="x", pady=(10, 0))

        def _select_all() -> None:
            listbox.selection_set(0, "end")

        def _clear_all() -> None:
            listbox.selection_clear(0, "end")

        def _confirm() -> None:
            indices = listbox.curselection()
            selection["values"] = [options[i] for i in indices]
            dialog.destroy()

        self._create_round_button(actions, "Выбрать все", _select_all, style_kind="ghost").pack(side="left")
        self._create_round_button(actions, "Снять выбор", _clear_all, style_kind="ghost").pack(side="left", padx=(8, 0))
        self._create_round_button(actions, "Выбрать", _confirm).pack(side="right")
        self._create_round_button(actions, "Отмена", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

        self.root.wait_window(dialog)
        return selection["values"]

    def _build_merged_source_parser(self, source_names: List[str]) -> Optional[FortigateConfigParser]:
        if not source_names:
            return None
        loaded_parsers: List[FortigateConfigParser] = []
        current_selected = self.selected_device_name
        try:
            for source_name in source_names:
                if source_name not in self.devices:
                    continue
                self.select_device(source_name)
                parser = self._load_parser_for_selected_device(profile="addresses")
                if parser is not None:
                    loaded_parsers.append(parser)
        finally:
            if current_selected and current_selected in self.devices:
                self.select_device(current_selected)

        if not loaded_parsers:
            return None

        first = loaded_parsers[0]
        merged = FortigateConfigParser(first.config_path)
        merged.address_objects = {name: dict(obj) for name, obj in first.address_objects.items()}
        merged.address_group_objects = {name: dict(obj) for name, obj in first.address_group_objects.items()}
        merged.address_group_members = {name: list(members) for name, members in first.address_group_members.items()}
        merged.address_entries = [dict(obj) for obj in first.address_entries]
        merged.address_group_entries = [dict(obj) for obj in first.address_group_entries]

        conflicts: List[str] = []

        def _obj_signature(obj: Dict[str, str]) -> str:
            return json.dumps({k: str(v) for k, v in sorted(obj.items())}, ensure_ascii=False, sort_keys=True)

        for parser in loaded_parsers[1:]:
            for name, obj in parser.address_objects.items():
                if name in merged.address_objects:
                    if _obj_signature(merged.address_objects[name]) != _obj_signature(obj):
                        conflicts.append(f"address:{name}")
                    continue
                merged.address_objects[name] = dict(obj)
            for name, obj in parser.address_group_objects.items():
                if name in merged.address_group_objects:
                    if _obj_signature(merged.address_group_objects[name]) != _obj_signature(obj):
                        conflicts.append(f"group:{name}")
                else:
                    merged.address_group_objects[name] = dict(obj)
                existing_members = merged.address_group_members.get(name, [])
                for member in parser.address_group_members.get(name, []):
                    if member not in existing_members:
                        existing_members.append(member)
                merged.address_group_members[name] = existing_members
            merged.address_entries.extend(dict(obj) for obj in parser.address_entries if obj.get("_name", ""))
            merged.address_group_entries.extend(dict(obj) for obj in parser.address_group_entries if obj.get("_name", ""))

        if conflicts:
            preview = ", ".join(sorted(set(conflicts))[:10])
            suffix = " ..." if len(set(conflicts)) > 10 else ""
            messagebox.showwarning(
                "Конфликт имен в источниках",
                "Часть объектов с одинаковыми именами имеет разные значения между источниками.\n"
                f"Оставлены объекты из первого выбранного устройства.\nПримеры: {preview}{suffix}",
            )
        return merged

    def _open_transfer_direction_dialog(self, device_name: str) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Добавить адреса")
        dialog.geometry("560x210")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        body_canvas, body = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_add_device_dialog"],
        )
        body_canvas.pack(fill="both", expand=True, padx=10, pady=10)
        tk.Label(
            body,
            text=f"Устройство: {device_name}\nВыберите направление переноса адресов.",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(8, 10))

        actions = tk.Frame(body, bg=UI_COLORS["panel_soft"])
        actions.pack(fill="x")

        def on_to_this() -> None:
            source_names = self._choose_devices_dialog(
                "Источники адресов",
                f"Выберите одно или несколько устройств-источников для переноса на '{device_name}'.",
                exclude_name=device_name,
            )
            if not source_names:
                return
            merged_source_parser = self._build_merged_source_parser(source_names)
            if merged_source_parser is None:
                messagebox.showwarning("Нет данных", "Не удалось загрузить адреса из выбранных устройств.")
                return
            dialog.destroy()
            self.open_address_transfer_dialog(
                source_device_name=", ".join(source_names),
                source_device_names=source_names,
                target_device_name=device_name,
                parser_override=merged_source_parser,
            )

        def on_from_this() -> None:
            dialog.destroy()
            self.open_address_transfer_dialog(source_device_name=device_name)

        self._create_round_button(actions, "Добавить на это устройство", on_to_this).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Добавить с этого устройства", on_from_this, style_kind="ghost").pack(fill="x")

    def _open_transfer_direction_for_selected_device(self) -> None:
        record = self._get_selected_device()
        if not record:
            return
        self._open_transfer_direction_dialog(record.name)

    def _show_right_panel(self) -> None:
        if self.right_panel_canvas is None or self.right_panel_visible:
            return
        self.right_panel_canvas.pack(side="left", fill="y")
        self.right_panel_visible = True

    def _hide_right_panel(self) -> None:
        if self.right_panel_canvas is None or not self.right_panel_visible:
            return
        self.right_panel_canvas.pack_forget()
        self.right_panel_visible = False

    def _open_host_details(self, device_name: str) -> None:
        self._open_device_page(device_name)

    def _load_devices(self) -> None:
        self.devices = load_devices_from_disk(DEVICES_DIR)
        self.opened_devices = [name for name in self.opened_devices if name in self.devices]
        if self.active_device_tab not in self.devices:
            self.active_device_tab = self.opened_devices[-1] if self.opened_devices else None
        if self.active_editor_device not in self.devices:
            self.active_editor_device = self.opened_devices[-1] if self.opened_devices else None
        if self.selected_device_name not in self.devices:
            self.selected_device_name = next(iter(self.devices), None)
        self._refresh_open_tabs()
        self._refresh_devices_view()

    def _build_empty_state(self, parent: tk.Frame) -> None:
        """Termius-style centered empty state."""
        PS = UI_COLORS["panel_soft"]
        wrap = tk.Frame(parent, bg=PS)
        wrap.place(relx=0.5, rely=0.45, anchor="center")

        badge = self._create_icon_badge(wrap, "FW", UI_COLORS["panel"], fg=UI_COLORS["muted"], size=60, radius=22)
        badge.pack(pady=(0, 20))

        tk.Label(
            wrap,
            text="Нет устройств",
            bg=PS,
            fg=UI_COLORS["text"],
            font=UI_FONTS["title_md_bold"],
        ).pack()
        tk.Label(
            wrap,
            text="Добавьте FortiGate конфигурацию чтобы начать анализ",
            bg=PS,
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_md"],
        ).pack(pady=(6, 20))
        self._create_round_button(wrap, "+ Добавить устройство", self.open_add_device_dialog).pack()

    def _refresh_devices_view(self) -> None:
        self._refresh_right_hosts()
        self.card_canvases = {}

        if self.cards_frame is not None:
            for child in self.cards_frame.winfo_children():
                child.destroy()
            if not self.devices:
                self._build_empty_state(self.cards_frame)
            else:
                PS = UI_COLORS["panel_soft"]
                P = UI_COLORS["panel"]

                # Badge accent colours — rotate for visual variety
                BADGE_COLORS = ["#5B6BDF", "#E07B54", "#54A0D0", "#7B54D0", "#54C08A", "#D05470"]

                # 2-column grid like Termius
                self.cards_frame.grid_columnconfigure(0, weight=1)
                self.cards_frame.grid_columnconfigure(1, weight=1)

                for index, record in enumerate(self.devices.values()):
                    is_selected = record.name == self.selected_device_name
                    badge_color = BADGE_COLORS[index % len(BADGE_COLORS)]
                    card_bg = UI_COLORS["sidebar_item_active"] if is_selected else P

                    # Termius-style tile: rounded container, no border by default
                    card_canvas, card_inner = self._create_rounded_container(
                        self.cards_frame,
                        outer_bg=PS,
                        fill_color=card_bg,
                        border_color=UI_COLORS["accent"] if is_selected else card_bg,
                        radius=UI_STYLE_KIT["radius_device_card"],
                        border_width=2 if is_selected else 1,
                        min_height=UI_STYLE_KIT["height_device_card"] + 20,
                    )
                    card_canvas.grid(
                        row=index // 2,
                        column=index % 2,
                        sticky="nsew",
                        padx=6,
                        pady=6,
                    )
                    self.card_canvases[record.name] = card_canvas

                    body = tk.Frame(card_inner, bg=card_bg)
                    body.pack(fill="both", expand=True, padx=10, pady=10)

                    # Top row: icon + name
                    top_row = tk.Frame(body, bg=card_bg)
                    top_row.pack(fill="x")

                    icon_badge = self._create_icon_badge(top_row, "FW", badge_color, size=36, radius=12)
                    icon_badge.configure(bg=card_bg)
                    icon_badge.pack(side="left")

                    name_lbl = tk.Label(
                        top_row,
                        text=record.name,
                        bg=card_bg,
                        fg=UI_COLORS["text"],
                        font=UI_FONTS["label_lg_bold"],
                        anchor="w",
                    )
                    name_lbl.pack(side="left", padx=(10, 0))

                    # Detail row
                    config_text = record.config_path.name if record.config_path else "нет конфига"
                    detail_lbl = tk.Label(
                        body,
                        text=f"{config_text}  ·  {record.updated_at}",
                        bg=card_bg,
                        fg=UI_COLORS["muted"],
                        font=UI_FONTS["label_sm"],
                        anchor="w",
                    )
                    detail_lbl.pack(anchor="w", pady=(6, 0))

                    # Click on whole card = open device page
                    click_targets = (card_canvas, card_inner, body, top_row, name_lbl, detail_lbl)
                    for w in click_targets:
                        w.bind("<Button-1>", lambda _e, n=record.name: self._open_device_page(n))

                    hover_bg = UI_COLORS["sidebar_item_hover"] if not is_selected else UI_COLORS["sidebar_item_active"]
                    anim_widgets = [card_inner, body, top_row]

                    def _on_enter(
                        _e, cv=card_canvas, ws=anim_widgets, from_c=card_bg, to_c=hover_bg, sel=is_selected,
                    ) -> None:
                        self._animate_hover(
                            cv, ws, from_c, to_c,
                            border_color=UI_COLORS["line_soft"] if sel else UI_COLORS["line"],
                            border_width=1,
                        )

                    def _on_leave(
                        _e, cv=card_canvas, ws=anim_widgets, from_c=hover_bg, to_c=card_bg, sel=is_selected,
                    ) -> None:
                        self._animate_hover(
                            cv, ws, from_c, to_c,
                            border_color=UI_COLORS["line_soft"] if sel else card_bg,
                            border_width=1,
                        )

                    for w in (card_canvas, card_inner, body, top_row, name_lbl, detail_lbl):
                        w.bind("<Enter>", _on_enter)
                        w.bind("<Leave>", _on_leave)

        if self.selected_device_name:
            self.select_device(self.selected_device_name, refresh_hosts=False)
        else:
            self._fill_details(None)
        if self.active_editor_device and self.active_editor_device in self.devices:
            self._open_device_editor(self.active_editor_device)
        elif self.active_device_tab and self.active_device_tab in self.devices:
            self._open_device_page(self.active_device_tab)
        elif not self.opened_devices:
            self._show_cards_view()

    def select_device(self, name: str, *, refresh_hosts: bool = True) -> None:
        if name not in self.devices:
            return
        self.selected_device_name = name
        if refresh_hosts:
            self._refresh_right_hosts()
        for device_name, canvas in self.card_canvases.items():
            is_sel = device_name == self.selected_device_name
            self._set_rounded_style(canvas, UI_COLORS["line_soft"] if is_sel else UI_COLORS["line"], 1)
        self._fill_details(self.devices[name])

    def _refresh_right_hosts(self) -> None:
        if self.hosts_frame is None:
            return
        self.host_tile_canvases = {}
        for child in self.hosts_frame.winfo_children():
            child.destroy()
        if not self.devices:
            tk.Label(
                self.hosts_frame,
                text="Нет устройств",
                bg=UI_COLORS["panel_soft"],
                fg=UI_COLORS["muted"],
                anchor="w",
            ).pack(fill="x", padx=8, pady=8)
            return
        for record in self.devices.values():
            is_selected = record.name == self.selected_device_name
            tile_canvas, tile = self._create_rounded_container(
                self.hosts_frame,
                outer_bg=UI_COLORS["panel_soft"],
                fill_color=UI_COLORS["panel"],
                border_color=UI_COLORS["line_soft"] if is_selected else UI_COLORS["line"],
                radius=UI_STYLE_KIT["radius_card"],
                border_width=1,
                min_height=UI_STYLE_KIT["height_tile"],
            )
            tile_canvas.pack(fill="x", padx=4, pady=4)
            self.host_tile_canvases[record.name] = tile_canvas
            tile_top = tk.Frame(tile, bg=UI_COLORS["panel"])
            tile_top.pack(fill="x")
            name_label = tk.Label(
                tile_top,
                text=record.name,
                bg=UI_COLORS["panel"],
                fg=UI_COLORS["text"],
                font=UI_FONTS["action_bold"],
                anchor="w",
            )
            name_label.pack(side="left", fill="x", expand=True)
            edit_btn = tk.Label(
                tile_top,
                text="✎",
                bg=UI_COLORS["panel_soft"],
                fg=UI_COLORS["muted"],
                font=UI_FONTS["label_sm_bold"],
                padx=6,
                pady=1,
            )
            edit_btn.pack(side="right")
            edit_btn.bind("<Button-1>", lambda _event, n=record.name: self._open_device_page(n))
            ts_label = tk.Label(
                tile,
                text=record.updated_at,
                bg=UI_COLORS["panel"],
                fg=UI_COLORS["muted"],
                font=UI_FONTS["label_xs"],
                anchor="w",
            )
            ts_label.pack(fill="x", pady=(2, 0))
            for widget in (tile_canvas, tile, tile_top, name_label, ts_label):
                widget.bind("<Button-1>", lambda _event, n=record.name: self._open_device_page(n))
                widget.bind("<Enter>", lambda _event, n=record.name, s=is_selected: self._set_host_hover(n, s, True))
                widget.bind("<Leave>", lambda _event, n=record.name, s=is_selected: self._set_host_hover(n, s, False))

    def _set_card_hover(self, device_name: str, is_selected: bool, hover: bool) -> None:
        canvas = self.card_canvases.get(device_name)
        if canvas is None:
            return
        if is_selected:
            self._set_rounded_style(canvas, UI_COLORS["line_soft"], 1)
            return
        self._set_rounded_style(canvas, UI_COLORS["line_soft"] if hover else UI_COLORS["line"], 1)

    def _set_host_hover(self, device_name: str, is_selected: bool, hover: bool) -> None:
        canvas = self.host_tile_canvases.get(device_name)
        if canvas is None:
            return
        if is_selected:
            self._set_rounded_style(canvas, UI_COLORS["line_soft"], 1)
            return
        self._set_rounded_style(canvas, UI_COLORS["line_soft"] if hover else UI_COLORS["line"], 1)

    def _fill_details(self, record: Optional[DeviceRecord]) -> None:
        if record is None:
            for key in self.details_vars:
                self.details_vars[key].set("-")
            return
        self.details_vars["name"].set(record.name)
        self.details_vars["folder"].set(str(record.folder.name))
        self.details_vars["config"].set(record.config_path.name if record.config_path else "-")
        self.details_vars["excel"].set(record.excel_path.name if record.excel_path else "-")
        self.details_vars["csv"].set(record.csv_path.name if record.csv_path else "-")
        self.details_vars["updated"].set(record.updated_at)

    def _ask_commands_applied_dialog(self, title: str, message: str, parent: tk.Widget) -> bool:
        decision = {"applied": False}
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("520x180")
        dialog.transient(parent)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        wrap_canvas, wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_block"],
            border_width=1,
            min_height=120,
        )
        wrap_canvas.pack(fill="both", expand=True, padx=10, pady=10)
        tk.Label(
            wrap,
            text=message,
            anchor="w",
            justify="left",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
        ).pack(fill="x", pady=(8, 12))

        actions = tk.Frame(wrap, bg=UI_COLORS["panel_soft"])
        actions.pack(fill="x")

        def on_applied() -> None:
            decision["applied"] = True
            dialog.destroy()

        def on_not_applied() -> None:
            decision["applied"] = False
            dialog.destroy()

        self._create_round_button(actions, "Применил", on_applied).pack(side="right")
        self._create_round_button(actions, "Нет", on_not_applied, style_kind="ghost").pack(side="right", padx=(0, 8))
        self.root.wait_window(dialog)
        return decision["applied"]

    @staticmethod
    def _replace_name_in_members(members: List[str], old_name: str, new_name: str) -> List[str]:
        return [new_name if item == old_name else item for item in members]

    def _persist_current_address_data_to_selected_config(self) -> bool:
        if self.last_parser is None:
            return False
        record = self._get_selected_device()
        if not record or not record.config_path or not record.config_path.exists():
            return False

        parser = self.last_parser
        try:
            safe_config = self._ensure_device_vault_path(record.config_path, must_exist=True)
        except ValueError:
            messagebox.showerror("Ошибка доступа", "Нельзя записать конфиг вне devices vault.")
            return False

        address_lines = parser.render_address_config_lines()
        group_lines = parser.render_addrgrp_config_lines()

        text = safe_config.read_text(encoding="utf-8", errors="ignore")
        text = replace_or_append_config_section(text, "firewall address", "\n".join(address_lines))
        text = replace_or_append_config_section(text, "firewall addrgrp", "\n".join(group_lines))
        safe_config.write_text(text, encoding="utf-8")
        self.status_var.set(f"Конфиг устройства '{record.name}' обновлен по примененным командам.")
        self._load_devices()
        self.select_device(record.name)
        return True

    def show_device_menu(self, device_name: str) -> None:
        self._create_action_menu(device_name)

    def open_add_device_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Добавить устройство")
        dialog.geometry("680x360")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        name_var = tk.StringVar()
        config_var = tk.StringVar()
        status_var = tk.StringVar(value="Укажите имя устройства. Конфиг можно добавить сразу или позже.")

        frame_shell_canvas, frame = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_block"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_add_device_dialog"] + 28,
        )
        frame_shell_canvas.pack(fill="both", expand=True, padx=UI_SPACING["section"], pady=UI_SPACING["section"])
        frame.configure(padx=UI_SPACING["section"], pady=UI_SPACING["section"])
        tk.Label(frame, text="Имя устройства:", bg=UI_COLORS["panel_soft"], fg=UI_COLORS["text"]).pack(anchor="w")
        name_shell, _name_entry = self._create_round_entry(frame, name_var, min_height=UI_STYLE_KIT["control_height"])
        name_shell.pack(fill="x", pady=(4, UI_SPACING["gap"]))

        tk.Label(frame, text="Конфиг FortiGate (необязательно):", bg=UI_COLORS["panel_soft"], fg=UI_COLORS["text"]).pack(anchor="w")
        config_row = tk.Frame(frame, bg=UI_COLORS["panel_soft"])
        config_row.pack(fill="x", pady=(4, 0))
        cfg_shell, _cfg_entry = self._create_round_entry(config_row, config_var, min_height=UI_STYLE_KIT["control_height"])
        cfg_shell.pack(side="left", fill="x", expand=True, padx=(0, UI_SPACING["tight"]))
        self._create_round_button(
            config_row, "Выбрать...", lambda: self._pick_config_for_dialog(config_var), min_height=UI_STYLE_KIT["control_height"]
        ).pack(side="left")

        tk.Label(
            frame,
            textvariable=status_var,
            anchor="w",
            justify="left",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["muted"],
        ).pack(fill="x", pady=(UI_SPACING["section"], 0))

        actions = tk.Frame(frame, bg=UI_COLORS["panel_soft"])
        actions.pack(fill="x", pady=(UI_SPACING["section"], 0))

        def on_create() -> None:
            try:
                device_name = self._create_device_from_config(name_var.get())
            except Exception as exc:
                status_var.set(str(exc))
                return
            dialog.destroy()
            self.select_device(device_name)
            if config_var.get().strip():
                self._attach_config_to_device_async(
                    device_name,
                    Path(config_var.get().strip()).expanduser(),
                    final_status=f"Устройство '{device_name}' добавлено. Конфиг, Excel и CSV созданы.",
                )

        self._create_round_button(actions, "Создать", on_create).pack(side="right")
        self._create_round_button(actions, "Отмена", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

    def _pick_config_for_dialog(self, target_var: tk.StringVar) -> None:
        file_path = filedialog.askopenfilename(
            title="Выберите конфигурацию FortiGate",
            filetypes=[("FortiGate config", "*.conf *.txt"), ("All files", "*.*")],
        )
        if file_path:
            target_var.set(file_path)

    def _is_device_vault_path(self, path: Path, *, must_exist: bool = True) -> bool:
        try:
            ensure_under_root(path, DEVICES_DIR.resolve(), must_exist=must_exist)
            return True
        except Exception:
            return False

    def _ensure_device_vault_path(self, path: Path, *, must_exist: bool = True) -> Path:
        return ensure_under_root(path, DEVICES_DIR.resolve(), must_exist=must_exist)

    def _record_perf(self, metric: str, started_at: float, **extra: object) -> None:
        elapsed_ms = (time.perf_counter() - started_at) * 1000.0
        self.perf_recorder.record(metric, elapsed_ms, extra if extra else None)

    @staticmethod
    def _sanitize_dataframe_for_csv(df):
        sanitized = df.copy()
        for col_name in sanitized.columns:
            if sanitized[col_name].dtype == object:
                sanitized[col_name] = sanitized[col_name].map(
                    lambda value: sanitize_spreadsheet_text(value) if isinstance(value, str) else value
                )
        return sanitized

    def _create_device_from_config(self, raw_name: str) -> str:
        safe_name = sanitize_device_name(raw_name)
        if not safe_name:
            raise ValueError("Введите корректное имя устройства.")
        device_dir = DEVICES_DIR / safe_name
        if device_dir.exists():
            should_replace = messagebox.askyesno(
                "Устройство уже существует",
                f"Устройство '{safe_name}' уже есть. Пересоздать папку устройства?",
            )
            if not should_replace:
                raise RuntimeError("Создание отменено пользователем.")
            safe_dir = self._ensure_device_vault_path(device_dir, must_exist=True)
            shutil.rmtree(safe_dir)
        device_dir.mkdir(parents=True, exist_ok=True)
        self.status_var.set(f"Устройство '{safe_name}' добавлено без конфига.")
        self._load_devices()
        return safe_name

    def _attach_config_to_device(self, device_name: str, source_config: Path) -> None:
        started_at = time.perf_counter()
        src = source_config.expanduser()
        if not src.exists():
            raise FileNotFoundError("Файл конфигурации не найден.")
        if src.is_symlink():
            raise ValueError("Символические ссылки не поддерживаются для исходного конфига.")
        device_dir = DEVICES_DIR / device_name
        device_dir.mkdir(parents=True, exist_ok=True)
        safe_device_dir = self._ensure_device_vault_path(device_dir, must_exist=True)

        config_target = safe_device_dir / f"{device_name}.conf"
        excel_target = safe_device_dir / f"{device_name}_analysis.xlsx"
        csv_target = safe_device_dir / f"{device_name}_analysis.csv"
        shutil.copy2(src, config_target)

        parser_started = time.perf_counter()
        parser = analyze_config(config_target, excel_target)
        self._record_perf("parser.analyze_config", parser_started, device=device_name, source=str(config_target))
        for step_name, duration in parser.profile.items():
            self.perf_recorder.record(
                f"parser.{step_name}",
                duration * 1000.0,
                {"device": device_name, "source": str(config_target)},
            )
        self.last_parser = parser

        # CSV нужен для быстрого просмотра/импорта в другие инструменты.
        sheet = next(iter(parser.dataframes.values()), None)
        if sheet is not None:
            safe_sheet = self._sanitize_dataframe_for_csv(sheet)
            safe_sheet.to_csv(csv_target, index=False, encoding="utf-8-sig")
        self._record_perf("device.attach_config", started_at, device=device_name)

    def _attach_config_to_device_async(self, device_name: str, source_config: Path, *, final_status: str) -> None:
        self.status_var.set(f"Анализируем конфиг устройства '{device_name}'...")

        def worker() -> None:
            try:
                self._attach_config_to_device(device_name, source_config)
            except Exception as exc:
                _msg = str(exc)
                self.root.after(0, lambda m=_msg: messagebox.showerror("Ошибка", m))
                return

            def on_done() -> None:
                self.status_var.set(final_status)
                self._load_devices()
                self.select_device(device_name)

            self.root.after(0, on_done)

        threading.Thread(target=worker, daemon=True).start()

    def attach_config_to_selected_device(self) -> None:
        record = self._get_selected_device()
        if not record:
            return
        file_path = filedialog.askopenfilename(
            title=f"Выберите конфиг для устройства {record.name}",
            filetypes=[("FortiGate config", "*.conf *.txt"), ("All files", "*.*")],
        )
        if not file_path:
            return
        self._attach_config_to_device_async(
            record.name,
            Path(file_path),
            final_status=f"Конфиг устройства '{record.name}' обновлен. Excel и CSV пересобраны.",
        )

    def _get_selected_device(self) -> Optional[DeviceRecord]:
        if not self.selected_device_name:
            messagebox.showwarning("Нет устройства", "Сначала выберите устройство.")
            return None
        record = self.devices.get(self.selected_device_name)
        if not record:
            messagebox.showwarning("Нет устройства", "Устройство не найдено, обновите список.")
            return None
        return record

    def open_selected_config(self) -> None:
        record = self._get_selected_device()
        if not record:
            return
        if record.csv_path and record.csv_path.exists():
            self._open_path(record.csv_path)
            return
        messagebox.showwarning(
            "CSV не найден",
            "CSV файл не найден. Добавьте или замените конфиг, чтобы CSV был сгенерирован.",
        )

    def open_selected_excel(self) -> None:
        record = self._get_selected_device()
        if not record:
            return
        if not record.excel_path:
            messagebox.showwarning("Excel не найден", "Для устройства пока нет Excel. Добавьте или замените конфиг.")
            return
        self._open_path(record.excel_path)

    def _open_path(self, target: Path) -> None:
        if not self._is_device_vault_path(target, must_exist=True):
            messagebox.showerror("Ошибка доступа", "Открытие файла вне devices vault запрещено.")
            return
        if not target.exists():
            messagebox.showerror("Файл не найден", f"Файл не найден:\n{target}")
            return
        system = platform.system().lower()
        if system == "windows":
            os.startfile(str(target))  # type: ignore[attr-defined]
            return
        if system == "darwin":
            subprocess.Popen(["open", str(target)])
            return
        subprocess.Popen(["xdg-open", str(target)])

    def delete_selected_device(self) -> None:
        record = self._get_selected_device()
        if not record:
            return
        confirmed = messagebox.askyesno(
            "Удалить устройство",
            f"Удалить устройство '{record.name}'?\nБудет удалена вся папка devices/{record.name} с файлами внутри.",
        )
        if not confirmed:
            return
        safe_folder = self._ensure_device_vault_path(record.folder, must_exist=True)
        shutil.rmtree(safe_folder, ignore_errors=False)
        self.selected_device_name = None
        self.last_parser = None
        self.status_var.set(f"Устройство '{record.name}' удалено.")
        self._load_devices()

    def _load_parser_for_selected_device(self, profile: str = "full") -> Optional[FortigateConfigParser]:
        started_at = time.perf_counter()
        record = self._get_selected_device()
        if not record:
            return None
        if not record.config_path:
            messagebox.showwarning("Нет конфига", "У выбранного устройства еще нет конфига. Добавьте или замените конфиг.")
            return None
        if not record.config_path.exists():
            messagebox.showerror("Ошибка", f"Конфиг не найден:\n{record.config_path}")
            return None
        try:
            safe_config = self._ensure_device_vault_path(record.config_path, must_exist=True)
        except ValueError:
            messagebox.showerror("Ошибка доступа", "Конфиг находится вне devices vault.")
            return None
        parse_profile = "addresses" if profile == "addresses" else "full"
        mtime = safe_config.stat().st_mtime
        cache_key = (str(safe_config), mtime, parse_profile)
        cache_hit = cache_key in self._parser_cache
        parser = self._parser_cache.get(cache_key)
        if not cache_hit or parser is None:
            parser = FortigateConfigParser(str(safe_config))
            if parse_profile == "addresses":
                parser.parse_addresses_only()
            else:
                parser.parse_all()
            self._parser_cache[cache_key] = parser
            # Drop stale cache entries for the same file/profile.
            stale_keys = [
                key
                for key in self._parser_cache
                if key[0] == str(safe_config) and key[2] == parse_profile and key[1] != mtime
            ]
            for stale_key in stale_keys:
                self._parser_cache.pop(stale_key, None)
            for step_name, duration in parser.profile.items():
                self.perf_recorder.record(
                    f"parser.{step_name}",
                    duration * 1000.0,
                    {"device": record.name, "source": str(safe_config), "cache_hit": False, "profile": parse_profile},
                )
        self.last_parser = parser
        self._record_perf(
            "parser.load_selected_device",
            started_at,
            device=record.name,
            cache_hit=cache_hit,
            profile=parse_profile,
        )
        return parser

    def _get_address_display_value(self, address_name: str) -> str:
        if self.last_parser is None:
            return ""
        return get_address_display_value(self.last_parser.address_objects, address_name)

    def _address_sort_key(self, address_name: str) -> Tuple[int, object, str]:
        if self.last_parser is None:
            return (2, address_name.lower(), address_name.lower())
        return address_sort_key(self.last_parser.address_objects, address_name)

    def _address_sort_mode_key(self, address_name: str, sort_mode: str) -> Tuple[int, object, str]:
        if self.last_parser is None:
            return (2, address_name.lower(), address_name.lower())
        return address_sort_mode_key(self.last_parser.address_objects, address_name, sort_mode)

    def _get_address_editor_state(self, address_name: str) -> Tuple[str, str]:
        assert self.last_parser is not None
        obj = self.last_parser.address_objects.get(address_name, {})
        fqdn_value = obj.get("fqdn", "").strip()
        if fqdn_value:
            return "fqdn", fqdn_value
        iprange_value = obj.get("iprange", "").strip()
        if iprange_value:
            return "iprange", iprange_value
        subnet_value = obj.get("subnet", "").strip()
        return "subnet", subnet_to_display(subnet_value) if subnet_value else ""

    def _open_address_editor_dialog(self, selected_addresses: Set[str]) -> bool:
        if self.last_parser is None:
            return False
        ordered_names = sorted(selected_addresses, key=self._address_sort_key)
        if not ordered_names:
            return False

        dialog = tk.Toplevel(self.root)
        dialog.title("Редактор адресов")
        dialog.geometry("980x640")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        tk.Label(
            dialog,
            text="Измените тип и значение адреса. Для subnet можно вводить CIDR (например, 10.10.30.0/24).",
            anchor="w",
            justify="left",
            bg=UI_COLORS["bg"],
            fg=UI_COLORS["text"],
        ).pack(fill="x", padx=10, pady=(10, 6))

        editor_canvas, editor_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_transfer_editor"],
        )
        editor_canvas.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        canvas = tk.Canvas(editor_wrap, highlightthickness=0, bg=UI_COLORS["panel"])
        scrollbar = self._create_scrollbar(editor_wrap, canvas.yview)
        rows_frame = tk.Frame(canvas, bg=UI_COLORS["panel"])
        rows_frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=rows_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        header = tk.Frame(rows_frame, bg=UI_COLORS["panel"])
        header.pack(fill="x", padx=6, pady=(4, 6))
        tk.Label(header, text="Имя объекта", width=30, anchor="w", bg=UI_COLORS["panel"], fg=UI_COLORS["muted"]).pack(side="left")
        tk.Label(header, text="Тип", width=12, anchor="w", bg=UI_COLORS["panel"], fg=UI_COLORS["muted"]).pack(side="left")
        tk.Label(header, text="Значение", anchor="w", bg=UI_COLORS["panel"], fg=UI_COLORS["muted"]).pack(side="left")

        field_vars: Dict[str, Tuple[tk.StringVar, tk.StringVar]] = {}
        for name in ordered_names:
            initial_type, initial_value = self._get_address_editor_state(name)
            type_var = tk.StringVar(value=initial_type)
            value_var = tk.StringVar(value=initial_value)
            row = tk.Frame(rows_frame, bg=UI_COLORS["panel"])
            row.pack(fill="x", padx=6, pady=2)
            tk.Label(row, text=name, width=30, anchor="w", bg=UI_COLORS["panel"], fg=UI_COLORS["text"]).pack(side="left")
            ttk.Combobox(
                row,
                textvariable=type_var,
                values=["subnet", "iprange", "fqdn"],
                width=10,
                state="readonly",
                style="Vault.TCombobox",
            ).pack(side="left", padx=(0, 8))
            value_shell, _ = self._create_round_entry(row, value_var, min_height=UI_STYLE_KIT["height_device_menu_item"])
            value_shell.pack(side="left", fill="x", expand=True)
            field_vars[name] = (type_var, value_var)

        self._bind_vertical_mousewheel(canvas, canvas, rows_frame, editor_wrap, dialog)

        saved = {"done": False}
        actions = tk.Frame(dialog, bg=UI_COLORS["bg"])
        actions.pack(fill="x", padx=10, pady=(0, 10))

        def on_save() -> None:
            assert self.last_parser is not None
            updates: Dict[str, Tuple[str, str]] = {}
            try:
                for name, (type_var, value_var) in field_vars.items():
                    edit_type = type_var.get().strip()
                    raw_value = value_var.get().strip()
                    if edit_type == "subnet":
                        normalized = normalize_subnet_value(raw_value)
                    elif edit_type == "iprange":
                        normalized = normalize_iprange_value(raw_value)
                    elif edit_type == "fqdn":
                        if not raw_value:
                            raise ValueError(f"FQDN для '{name}' не может быть пустым.")
                        normalized = raw_value
                    else:
                        raise ValueError(f"Неизвестный тип '{edit_type}' для '{name}'.")
                    updates[name] = (edit_type, normalized)
            except ValueError as exc:
                messagebox.showerror("Ошибка валидации", str(exc), parent=dialog)
                return

            for name, (edit_type, normalized_value) in updates.items():
                obj = dict(self.last_parser.address_objects.get(name, {}))
                obj.pop("subnet", None)
                obj.pop("iprange", None)
                obj.pop("fqdn", None)
                if edit_type == "subnet":
                    obj.pop("type", None)
                    obj["subnet"] = normalized_value
                elif edit_type == "iprange":
                    obj["type"] = "iprange"
                    obj["iprange"] = normalized_value
                else:
                    obj["type"] = "fqdn"
                    obj["fqdn"] = normalized_value
                self.last_parser.address_objects[name] = obj

            saved["done"] = True
            dialog.destroy()

        self._create_round_button(actions, "Сохранить", on_save).pack(side="right")
        self._create_round_button(actions, "Отмена", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

        self.root.wait_window(dialog)
        return saved["done"]

    def _open_address_color_dialog(
        self,
        selected_addresses: Set[str],
        current_overrides: Dict[str, int],
    ) -> Optional[Dict[str, int]]:
        ordered_names = sorted(selected_addresses, key=self._address_sort_key)
        if not ordered_names:
            return None

        dialog = tk.Toplevel(self.root)
        dialog.title("Цвета выбранных адресов")
        dialog.geometry("900x560")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        tk.Label(
            dialog,
            text="Задайте цвет для выбранных адресов. Можно применить один цвет ко всем.",
            anchor="w",
            justify="left",
            bg=UI_COLORS["bg"],
            fg=UI_COLORS["text"],
        ).pack(fill="x", padx=10, pady=(10, 6))

        top_controls = tk.Frame(dialog, bg=UI_COLORS["bg"])
        top_controls.pack(fill="x", padx=10, pady=(0, 8))
        tk.Label(top_controls, text="Цвет для всех:", bg=UI_COLORS["bg"], fg=UI_COLORS["muted"]).pack(side="left")
        apply_all_var = tk.StringVar(value="(из конфига)")
        apply_all_cb = ttk.Combobox(
            top_controls,
            textvariable=apply_all_var,
            values=FORTIGATE_COLOR_OPTIONS,
            width=22,
            state="readonly",
            style="Vault.TCombobox",
        )
        apply_all_cb.pack(side="left", padx=(8, 8))

        content_canvas, content_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_transfer_editor"],
        )
        content_canvas.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        canvas = tk.Canvas(content_wrap, highlightthickness=0, bg=UI_COLORS["panel"])
        scrollbar = self._create_scrollbar(content_wrap, canvas.yview)
        rows_frame = tk.Frame(canvas, bg=UI_COLORS["panel"])
        rows_frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=rows_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        color_vars: Dict[str, tk.StringVar] = {}
        for name in ordered_names:
            row = tk.Frame(rows_frame, bg=UI_COLORS["panel"])
            row.pack(fill="x", padx=6, pady=2)
            tk.Label(row, text=name, width=36, anchor="w", bg=UI_COLORS["panel"], fg=UI_COLORS["text"]).pack(side="left")
            default_option = "(из конфига)"
            if name in current_overrides:
                default_option = format_fortigate_color_option(current_overrides[name])
            row_var = tk.StringVar(value=default_option)
            ttk.Combobox(
                row,
                textvariable=row_var,
                values=FORTIGATE_COLOR_OPTIONS,
                width=22,
                state="readonly",
                style="Vault.TCombobox",
            ).pack(side="right")
            color_vars[name] = row_var

        self._bind_vertical_mousewheel(canvas, canvas, rows_frame, content_wrap, dialog)

        def apply_to_all() -> None:
            selected_option = apply_all_var.get().strip()
            for var in color_vars.values():
                var.set(selected_option)

        self._create_round_button(top_controls, "Применить ко всем", apply_to_all, style_kind="ghost").pack(side="left")

        result: Dict[str, int] = dict(current_overrides)
        saved = {"done": False}
        actions = tk.Frame(dialog, bg=UI_COLORS["bg"])
        actions.pack(fill="x", padx=10, pady=(0, 10))

        def on_save() -> None:
            result.clear()
            for address_name, value_var in color_vars.items():
                parsed = parse_fortigate_color_code(value_var.get().strip())
                if parsed is not None:
                    result[address_name] = parsed
            saved["done"] = True
            dialog.destroy()

        self._create_round_button(actions, "Сохранить", on_save).pack(side="right")
        self._create_round_button(actions, "Отмена", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))
        self.root.wait_window(dialog)
        if not saved["done"]:
            return None
        return result

    def _create_scrollable_checklist(
        self,
        parent: tk.Widget,
        title: str,
        items: List[str],
        right_text_map: Optional[Dict[str, str]] = None,
        sort_options: Optional[List[Tuple[str, str]]] = None,
        sort_key_builder: Optional[Callable[[str, str], Tuple[int, object, str]]] = None,
    ) -> Dict[str, tk.BooleanVar]:
        container_canvas, container = self._create_rounded_container(
            parent,
            outer_bg=UI_COLORS["panel_soft"],
            fill_color=UI_COLORS["panel"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_transfer_target"],
        )
        container_canvas.pack(side="left", fill="both", expand=True, padx=6, pady=6)

        tk.Label(
            container,
            text=title,
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["text"],
            font=UI_FONTS["action_bold"],
            anchor="w",
        ).pack(fill="x", pady=(0, 6))

        filter_var = tk.StringVar()
        filter_frame = tk.Frame(container, bg=UI_COLORS["panel"])
        filter_frame.pack(fill="x", pady=(0, 6))
        tk.Label(filter_frame, text="Поиск:", bg=UI_COLORS["panel"], fg=UI_COLORS["muted"]).pack(side="left")
        filter_shell, filter_entry = self._create_round_entry(filter_frame, filter_var, min_height=UI_STYLE_KIT["height_device_menu_item"])
        filter_shell.pack(side="left", fill="x", expand=True, padx=(6, 0))

        controls = tk.Frame(container, bg=UI_COLORS["panel"])
        controls.pack(fill="x", pady=(0, 6))
        controls_left = tk.Frame(controls, bg=UI_COLORS["panel"])
        controls_left.pack(side="left", fill="x", expand=True)
        controls_right = tk.Frame(controls, bg=UI_COLORS["panel"])
        controls_right.pack(side="right", padx=(8, 0))
        sort_var = tk.StringVar(value=(sort_options[0][0] if sort_options else ""))

        canvas = tk.Canvas(container, highlightthickness=0, bg=UI_COLORS["panel"])
        scrollbar = self._create_scrollbar(container, canvas.yview)
        frame = tk.Frame(canvas, bg=UI_COLORS["panel"])
        frame.bind(
            "<Configure>",
            lambda event: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        vars_map: Dict[str, tk.BooleanVar] = {}
        widgets_map: Dict[str, tk.Frame] = {}
        searchable_map: Dict[str, str] = {}
        right_text_by_name: Dict[str, str] = {}
        visible_names_cache: List[str] = []
        visible_name_set: Set[str] = set()
        for name in items:
            var = tk.BooleanVar(value=False)
            vars_map[name] = var
            right_text = (right_text_map or {}).get(name, "")
            right_text_by_name[name] = right_text
            searchable_map[name] = f"{name} {right_text}".lower()

        def _create_row_widget(name: str) -> tk.Frame:
            row = tk.Frame(frame, bg=UI_COLORS["panel"])
            row_var = vars_map[name]
            chk = tk.Checkbutton(
                row,
                text=name,
                variable=row_var,
                anchor="w",
                justify="left",
                bg=UI_COLORS["panel"],
                fg=UI_COLORS["text"],
                selectcolor=UI_COLORS["panel_soft"],
                activebackground=UI_COLORS["panel"],
                activeforeground=UI_COLORS["text"],
            )
            chk.pack(side="left", fill="x", expand=True, anchor="w")
            right_text = right_text_by_name.get(name, "")
            right_label: Optional[tk.Label] = None
            if right_text:
                right_label = tk.Label(
                    row,
                    text=right_text,
                    anchor="e",
                    justify="right",
                    bg=UI_COLORS["panel"],
                    fg=UI_COLORS["muted"],
                    font=UI_FONTS["label_md"],
                )
                right_label.pack(side="right", padx=(6, 4))

            def _toggle_row(_event: tk.Event, row_state=row_var) -> str:
                row_state.set(not row_state.get())
                return "break"

            row.bind("<Button-1>", _toggle_row)
            if right_label is not None:
                right_label.bind("<Button-1>", _toggle_row)
            return row

        def _ensure_row_widget(name: str) -> tk.Frame:
            widget = widgets_map.get(name)
            if widget is None:
                widget = _create_row_widget(name)
                widgets_map[name] = widget
            return widget

        def apply_filter() -> None:
            nonlocal visible_names_cache, visible_name_set
            started_at = time.perf_counter()
            query = filter_var.get().strip().lower()
            visible_names = [name for name in items if query in searchable_map.get(name, name.lower())]

            if sort_options and sort_key_builder and sort_var.get():
                current_mode = sort_var.get()
                reverse = current_mode.endswith("_desc")
                visible_names = sorted(visible_names, key=lambda name: sort_key_builder(name, current_mode), reverse=reverse)

            new_visible_set = set(visible_names)
            if visible_names == visible_names_cache:
                return

            render_batch_id = object()
            active_batch["id"] = render_batch_id

            # Hide rows that are no longer visible.
            for name in (visible_name_set - new_visible_set):
                row_widget = widgets_map.get(name)
                if row_widget is None:
                    continue
                if row_widget.winfo_ismapped():
                    row_widget.pack_forget()

            visible_names_cache = visible_names
            visible_name_set = new_visible_set

            def render_batch(start_index: int = 0) -> None:
                if active_batch.get("id") is not render_batch_id:
                    return
                batch_end = min(start_index + 120, len(visible_names_cache))
                for name in visible_names_cache[start_index:batch_end]:
                    row_widget = _ensure_row_widget(name)
                    if row_widget.winfo_ismapped():
                        row_widget.pack_forget()
                    row_widget.pack(fill="x", anchor="w")
                canvas.configure(scrollregion=canvas.bbox("all"))
                if batch_end < len(visible_names_cache):
                    self.root.after(1, lambda: render_batch(batch_end))

            render_batch()
            elapsed_ms = (time.perf_counter() - started_at) * 1000.0
            if elapsed_ms >= 16.0:
                self.perf_recorder.record(
                    "ui.checklist_filter",
                    elapsed_ms,
                    {"title": title, "query_len": len(query), "visible_items": len(visible_names)},
                )

        def select_filtered(select_value: bool) -> None:
            target_names = visible_names_cache if visible_names_cache else items
            for name in target_names:
                vars_map[name].set(select_value)

        select_all_btn = self._create_round_button(controls_left, "Выбрать все", lambda: select_filtered(True), style_kind="ghost")
        select_all_btn.configure(width=180)
        select_all_btn.pack(side="left")
        clear_btn = self._create_round_button(controls_left, "Снять выбор", lambda: select_filtered(False), style_kind="ghost")
        clear_btn.configure(width=180)
        clear_btn.pack(side="left", padx=(8, 0))

        if sort_options and sort_key_builder:
            sort_button = tk.Menubutton(
                controls,
                text="▼ Сортировка",
                relief="flat",
                bg=UI_COLORS["button_primary_fill"],
                fg=UI_COLORS["button_primary_text"],
                activebackground=UI_COLORS["button_primary_hover"],
                activeforeground=UI_COLORS["button_primary_text"],
                borderwidth=1,
                highlightthickness=0,
                padx=10,
                pady=5,
            )
            sort_button.pack(side="right", in_=controls_right)
            sort_menu = tk.Menu(
                sort_button,
                tearoff=False,
                bg=UI_COLORS["panel"],
                fg=UI_COLORS["text"],
                activebackground=UI_COLORS["button_primary_hover"],
                activeforeground=UI_COLORS["text"],
            )
            sort_button.configure(menu=sort_menu)

            option_label_map = {mode: label for mode, label in sort_options}

            def _refresh_sort_button_text() -> None:
                current_mode = sort_var.get()
                sort_button.configure(text=f"▼ {option_label_map.get(current_mode, 'Сортировка')}")

            for mode, label in sort_options:
                sort_menu.add_radiobutton(
                    label=label,
                    value=mode,
                    variable=sort_var,
                    command=lambda: (_refresh_sort_button_text(), _schedule_filter_apply()),
                )
            _refresh_sort_button_text()

        pending_filter_job: Dict[str, Optional[str]] = {"id": None}
        active_batch: Dict[str, object] = {"id": object()}

        # Tk returns an identifier string from after(); assign explicitly to keep mypy happy.
        def _schedule_filter_apply(*_args: object) -> None:
            if pending_filter_job["id"] is not None:
                self.root.after_cancel(pending_filter_job["id"])
            pending_filter_job["id"] = self.root.after(120, _run_filter_apply)

        def _run_filter_apply() -> None:
            pending_filter_job["id"] = None
            apply_filter()

        filter_var.trace_add("write", _schedule_filter_apply)
        apply_filter()

        self._bind_vertical_mousewheel(canvas, canvas, frame, container, filter_frame, controls)

        return vars_map

    def open_address_transfer_dialog(
        self,
        preselected_addresses: Optional[Set[str]] = None,
        preselected_groups: Optional[Set[str]] = None,
        preselected_address_color_overrides: Optional[Dict[str, int]] = None,
        reuse_current_parser: bool = False,
        source_device_name: Optional[str] = None,
        source_device_names: Optional[List[str]] = None,
        target_device_name: Optional[str] = None,
        parser_override: Optional[FortigateConfigParser] = None,
    ) -> None:
        if source_device_name and source_device_name in self.devices:
            self.select_device(source_device_name)
        if parser_override is not None:
            parser = parser_override
            self.last_parser = parser
        elif reuse_current_parser and self.last_parser is not None:
            parser = self.last_parser
        else:
            parser = self._load_parser_for_selected_device(profile="addresses")
            if parser is None:
                return
            self.last_parser = parser

        address_names = sorted(self.last_parser.address_objects.keys(), key=self._address_sort_key)
        group_names = sorted(self.last_parser.address_group_objects.keys())
        if not address_names and not group_names:
            messagebox.showwarning("Нет объектов", "В конфиге не найдены firewall address/addrgrp.")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Выбор адресов и групп")
        dialog.geometry("980x620")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        tk.Label(
            dialog,
            text=(
                "Выберите адреса и/или группы адресов для подготовки команд переноса."
                if not source_device_name or not target_device_name
                else f"Источник: {source_device_name}  →  Цель: {target_device_name}"
            ),
            anchor="w",
            justify="left",
        ).pack(fill="x", padx=10, pady=(10, 4))

        body_canvas, body = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_block"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_transfer_panel"],
        )
        body_canvas.pack(fill="both", expand=True, padx=10, pady=6)

        address_right_text = {name: self._get_address_display_value(name) for name in address_names}
        address_sort_options = [
            ("name_asc", "Имя ↑"),
            ("name_desc", "Имя ↓"),
            ("ip_asc", "IP адрес ↑"),
            ("ip_desc", "IP адрес ↓"),
        ]
        address_vars = self._create_scrollable_checklist(
            body,
            "firewall address",
            address_names,
            right_text_map=address_right_text,
            sort_options=address_sort_options,
            sort_key_builder=self._address_sort_mode_key,
        )
        group_vars = self._create_scrollable_checklist(body, "firewall addrgrp", group_names)

        for name in (preselected_addresses or set()):
            if name in address_vars:
                address_vars[name].set(True)
        for name in (preselected_groups or set()):
            if name in group_vars:
                group_vars[name].set(True)
        address_color_overrides: Dict[str, int] = dict(preselected_address_color_overrides or {})

        actions = tk.Frame(dialog, bg=UI_COLORS["bg"])
        actions.pack(fill="x", padx=10, pady=8)

        def get_selected_addresses() -> Set[str]:
            return {name for name, var in address_vars.items() if var.get()}

        def get_selected_groups() -> Set[str]:
            return {name for name, var in group_vars.items() if var.get()}

        def on_edit_addresses() -> None:
            selected_addresses = get_selected_addresses()
            if not selected_addresses:
                messagebox.showwarning("Нечего редактировать", "Сначала выберите хотя бы один адрес.")
                return
            selected_groups = get_selected_groups()
            if self._open_address_editor_dialog(selected_addresses):
                dialog.destroy()
                self.open_address_transfer_dialog(
                    preselected_addresses=selected_addresses,
                    preselected_groups=selected_groups,
                    preselected_address_color_overrides={k: v for k, v in address_color_overrides.items() if k in selected_addresses},
                    reuse_current_parser=True,
                    source_device_name=source_device_name,
                    source_device_names=source_device_names,
                    target_device_name=target_device_name,
                )

        def on_set_address_colors() -> None:
            selected_addresses = get_selected_addresses()
            if not selected_addresses:
                messagebox.showwarning("Нет адресов", "Сначала выберите адреса для назначения цвета.")
                return
            updated = self._open_address_color_dialog(selected_addresses, address_color_overrides)
            if updated is not None:
                address_color_overrides.clear()
                address_color_overrides.update(updated)

        def on_done() -> None:
            selected_addresses = get_selected_addresses()
            selected_groups = get_selected_groups()
            if not selected_addresses and not selected_groups:
                messagebox.showwarning("Пустой выбор", "Выберите хотя бы один адрес или группу.")
                return
            dialog.destroy()
            filtered_color_overrides = {k: v for k, v in address_color_overrides.items() if k in selected_addresses}
            self._show_selection_summary(
                selected_addresses,
                selected_groups,
                filtered_color_overrides,
                source_device_name=source_device_name,
                target_device_name=target_device_name,
            )

        self._create_round_button(actions, "Готово", on_done).pack(side="right")
        self._create_round_button(actions, "Редактор адресов", on_edit_addresses, style_kind="ghost").pack(side="left")
        self._create_round_button(actions, "Цвет выбранных адресов", on_set_address_colors, style_kind="ghost").pack(
            side="left", padx=(8, 0)
        )
        self._create_round_button(actions, "Отмена", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

    def _show_selection_summary(
        self,
        selected_addresses: Set[str],
        selected_groups: Set[str],
        initial_address_color_overrides: Optional[Dict[str, int]] = None,
        source_device_name: Optional[str] = None,
        target_device_name: Optional[str] = None,
    ) -> None:
        assert self.last_parser is not None

        summary = tk.Toplevel(self.root)
        summary.title("Проверка выбора")
        summary.geometry("980x700")
        summary.transient(self.root)
        summary.grab_set()
        summary.configure(bg=UI_COLORS["bg"])

        group_color_map: Dict[str, tk.StringVar] = {}
        address_color_map: Dict[str, tk.StringVar] = {}

        if selected_groups or selected_addresses:
            color_box_canvas, color_box = self._create_rounded_container(
                summary,
                outer_bg=UI_COLORS["bg"],
                fill_color=UI_COLORS["panel_soft"],
                border_color=UI_COLORS["line"],
                radius=UI_STYLE_KIT["radius_card"],
                border_width=1,
                min_height=UI_STYLE_KIT["height_host_list"],
            )
            color_box_canvas.pack(fill="x", padx=10, pady=(10, 6))
            tk.Label(
                color_box,
                text="Цвета объектов (FortiGate color)",
                bg=UI_COLORS["panel_soft"],
                fg=UI_COLORS["text"],
                font=UI_FONTS["action_bold"],
                anchor="w",
            ).pack(fill="x", pady=(0, 6))

            color_canvas = tk.Canvas(color_box, height=140, highlightthickness=0, bg=UI_COLORS["panel_soft"])
            color_scroll = self._create_scrollbar(color_box, color_canvas.yview)
            color_frame = tk.Frame(color_canvas, bg=UI_COLORS["panel_soft"])
            color_frame.bind(
                "<Configure>",
                lambda event: color_canvas.configure(scrollregion=color_canvas.bbox("all")),
            )
            color_canvas.create_window((0, 0), window=color_frame, anchor="nw")
            color_canvas.configure(yscrollcommand=color_scroll.set)
            color_canvas.pack(side="left", fill="both", expand=True)
            color_scroll.pack(side="right", fill="y")

            def _add_color_row(obj_name: str, target_map: Dict[str, tk.StringVar]) -> None:
                row = tk.Frame(color_frame, bg=UI_COLORS["panel_soft"])
                row.pack(fill="x", pady=2)
                tk.Label(row, text=obj_name, anchor="w", bg=UI_COLORS["panel_soft"], fg=UI_COLORS["text"]).pack(
                    side="left", fill="x", expand=True
                )
                selected = tk.StringVar(value="(из конфига)")
                target_map[obj_name] = selected
                cb = ttk.Combobox(
                    row,
                    textvariable=selected,
                    values=FORTIGATE_COLOR_OPTIONS,
                    width=22,
                    state="readonly",
                    style="Vault.TCombobox",
                )
                cb.pack(side="right")

            if selected_groups:
                tk.Label(
                    color_frame,
                    text="Группы адресов:",
                    anchor="w",
                    bg=UI_COLORS["panel_soft"],
                    fg=UI_COLORS["muted"],
                    font=UI_FONTS["label_sm_bold"],
                ).pack(fill="x", pady=(0, 4))
                for group_name in sorted(selected_groups):
                    _add_color_row(group_name, group_color_map)

            if selected_addresses:
                tk.Label(
                    color_frame,
                    text="Адреса:",
                    anchor="w",
                    bg=UI_COLORS["panel_soft"],
                    fg=UI_COLORS["muted"],
                    font=UI_FONTS["label_sm_bold"],
                ).pack(fill="x", pady=(8, 4))
                for address_name in sorted(selected_addresses, key=self._address_sort_key):
                    _add_color_row(address_name, address_color_map)
                    if initial_address_color_overrides and address_name in initial_address_color_overrides:
                        address_color_map[address_name].set(format_fortigate_color_option(initial_address_color_overrides[address_name]))

            self._bind_vertical_mousewheel(color_canvas, color_canvas, color_frame, color_box)

        text_wrap_canvas, text_wrap = self._create_rounded_container(
            summary,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_inventory_panel"],
        )
        text_wrap_canvas.pack(fill="both", expand=True, padx=10, pady=10)
        text = tk.Text(
            text_wrap,
            wrap="word",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            relief="flat",
            insertbackground=UI_COLORS["text"],
        )
        text.pack(fill="both", expand=True)

        lines: List[str] = []
        lines.append("Выбраны группы адресов:\n")
        if selected_groups:
            for group_name in sorted(selected_groups):
                lines.append(f"- {group_name}")
                members = self.last_parser.address_group_members.get(group_name, [])
                if members:
                    for member in members:
                        lines.append(f"    • {member}")
                else:
                    lines.append("    • (пустая группа)")
        else:
            lines.append("- (группы не выбраны)")

        members_from_selected_groups: Set[str] = set()
        for group_name in selected_groups:
            members_from_selected_groups.update(self.last_parser.address_group_members.get(group_name, []))

        standalone = sorted(name for name in selected_addresses if name not in members_from_selected_groups)
        lines.append("\nОтдельно выбранные адреса (вне выбранных групп):")
        if standalone:
            for name in standalone:
                lines.append(f"- {name}")
        else:
            lines.append("- (нет)")

        text.insert("1.0", "\n".join(lines))
        text.configure(state="disabled")

        actions = tk.Frame(summary, bg=UI_COLORS["bg"])
        actions.pack(fill="x", padx=10, pady=(0, 10))

        def on_next() -> None:
            group_color_overrides: Dict[str, int] = {}
            address_color_overrides: Dict[str, int] = {}
            for group_name, var in group_color_map.items():
                selected_color = var.get().strip()
                parsed_code = parse_fortigate_color_code(selected_color)
                if parsed_code is not None:
                    group_color_overrides[group_name] = parsed_code
            for address_name, var in address_color_map.items():
                selected_color = var.get().strip()
                parsed_code = parse_fortigate_color_code(selected_color)
                if parsed_code is not None:
                    address_color_overrides[address_name] = parsed_code
            summary.destroy()
            self._show_duplicate_check_dialog(
                selected_addresses,
                selected_groups,
                group_color_overrides,
                address_color_overrides,
                source_device_name=source_device_name,
                target_device_name=target_device_name,
            )

        self._create_round_button(actions, "Далее", on_next).pack(side="right")
        self._create_round_button(actions, "Назад", summary.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

    def _show_duplicate_check_dialog(
        self,
        selected_addresses: Set[str],
        selected_groups: Set[str],
        group_color_overrides: Dict[str, int],
        address_color_overrides: Dict[str, int],
        source_device_name: Optional[str] = None,
        target_device_name: Optional[str] = None,
    ) -> None:
        assert self.last_parser is not None

        dialog = tk.Toplevel(self.root)
        dialog.title("Проверка дублей на целевом FortiGate")
        dialog.geometry("980x700")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        tk.Label(
            dialog,
            text=(
                "1) Выполните на целевом FortiGate команду ниже.\n"
                "2) Вставьте вывод в поле.\n"
                "3) Нажмите 'Сгенерировать команды'."
                + (f"\nИсточник: {source_device_name}" if source_device_name else "")
                + (f"\nЦель: {target_device_name}" if target_device_name else "")
            ),
            anchor="w",
            justify="left",
        ).pack(fill="x", padx=10, pady=(10, 6))

        check_canvas, check_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_control"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_check_command"],
        )
        check_canvas.pack(fill="x", padx=10)
        check_cmd = tk.Text(check_wrap, height=8, wrap="none", bg=UI_COLORS["panel_soft"], fg=UI_COLORS["text"], relief="flat")
        check_cmd.pack(fill="both", expand=True)
        check_cmd.insert("1.0", CHECK_COMMAND_TEXT)
        check_cmd.configure(state="disabled")

        def copy_check_cmd() -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(CHECK_COMMAND_TEXT)
            messagebox.showinfo("Скопировано", "Команда проверки скопирована.")

        copy_row = tk.Frame(dialog, bg=UI_COLORS["bg"])
        copy_row.pack(fill="x", padx=10, pady=(6, 10))
        self._create_round_button(copy_row, "Скопировать команду проверки", copy_check_cmd).pack(side="right")

        tk.Label(dialog, text="Вставьте вывод с устройства:", anchor="w").pack(fill="x", padx=10)
        output_canvas, output_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_transfer_editor"],
        )
        output_canvas.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        output_text = tk.Text(
            output_wrap,
            wrap="word",
            height=18,
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            relief="flat",
            insertbackground=UI_COLORS["text"],
        )
        output_text.pack(fill="both", expand=True)
        self._attach_text_context_menu(output_text)
        output_text.focus_set()

        actions = tk.Frame(dialog, bg=UI_COLORS["bg"])
        actions.pack(fill="x", padx=10, pady=(0, 10))

        def _validate_cli_output(payload: str) -> None:
            lines = [line for line in payload.splitlines() if line.strip()]
            if len(lines) > 20000:
                raise ValueError("Слишком большой CLI вывод для обработки (лимит: 20000 строк).")
            normalized = payload.lower()
            if "config firewall address" not in normalized and "config firewall addrgrp" not in normalized:
                raise ValueError("Вставьте вывод секций firewall address/addrgrp для проверки дублей.")

        def on_generate() -> None:
            cli_output = output_text.get("1.0", "end").strip()
            try:
                _validate_cli_output(cli_output)
            except ValueError as exc:
                messagebox.showwarning("Невалидный ввод", str(exc), parent=dialog)
                return
            existing_index = self.last_parser.parse_existing_object_index(cli_output)
            existing_names = set(existing_index["address"].keys()) | set(existing_index["addrgrp"].keys())
            plan = self.last_parser.build_transfer_plan(
                selected_addresses,
                selected_groups,
                existing_names,
                existing_index=existing_index,
                group_color_overrides=group_color_overrides,
                address_color_overrides=address_color_overrides,
            )
            dialog.destroy()
            self._show_commands_dialog(plan)

        self._create_round_button(actions, "Сгенерировать команды", on_generate).pack(side="right")
        self._create_round_button(actions, "Отмена", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

    def _show_commands_dialog(self, plan: Dict[str, object]) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Готовые команды FortiGate")
        dialog.geometry("980x740")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        dup_canvas, dup_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_control"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_host_list"],
        )
        dup_canvas.pack(fill="x", padx=10, pady=(10, 8))
        duplicates = tk.Text(dup_wrap, height=10, wrap="word", bg=UI_COLORS["panel_soft"], fg=UI_COLORS["text"], relief="flat")
        duplicates.pack(fill="both", expand=True)
        duplicate_addresses = plan["duplicate_addresses"]
        duplicate_groups = plan["duplicate_groups"]
        recolor_addresses = plan.get("existing_addresses_to_recolor", [])
        recolor_groups = plan.get("existing_groups_to_recolor", [])
        lines: List[str] = []
        lines.append("Проверка на дубли выполнена.\n")
        if duplicate_groups or duplicate_addresses:
            lines.append("Найдены дубли и исключены из команд создания:")
            if duplicate_groups:
                lines.append(f"- Группы: {', '.join(duplicate_groups)}")
            if duplicate_addresses:
                lines.append(f"- Адреса: {', '.join(duplicate_addresses)}")
        else:
            lines.append("Дубли не найдены. Все выбранные объекты включены в команды.")
        if recolor_addresses or recolor_groups:
            lines.append("\nБудет выполнено обновление цвета существующих объектов:")
            if recolor_addresses:
                lines.append(f"- Адреса: {', '.join(recolor_addresses)}")
            if recolor_groups:
                lines.append(f"- Группы: {', '.join(recolor_groups)}")
        duplicates.insert("1.0", "\n".join(lines))
        duplicates.configure(state="disabled")

        cmd_text = str(plan["commands_text"])
        cmd_canvas, cmd_wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_duplicates_editor"],
        )
        cmd_canvas.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        commands = tk.Text(
            cmd_wrap,
            wrap="none",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            relief="flat",
            insertbackground=UI_COLORS["text"],
        )
        commands.pack(fill="both", expand=True)
        commands.insert("1.0", cmd_text)

        actions = tk.Frame(dialog, bg=UI_COLORS["bg"])
        actions.pack(fill="x", padx=10, pady=(0, 10))

        def copy_commands() -> None:
            payload = commands.get("1.0", "end").strip()
            self.root.clipboard_clear()
            self.root.clipboard_append(payload)
            messagebox.showinfo("Скопировано", "Команды скопированы в буфер обмена.")

        self._create_round_button(actions, "Скопировать", copy_commands).pack(side="right")
        self._create_round_button(actions, "Закрыть", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

    def _ask_update_decision(self, remote_version: str) -> bool:
        decision = {"update": False}
        dialog = tk.Toplevel(self.root)
        dialog.title("Доступно обновление")
        dialog.geometry("460x180")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=UI_COLORS["bg"])

        wrap_canvas, wrap = self._create_rounded_container(
            dialog,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_color_picker"],
        )
        wrap_canvas.pack(fill="both", expand=True, padx=10, pady=10)

        tk.Label(
            wrap,
            text=(
                f"Найдена новая версия: {remote_version}\n"
                f"Текущая версия: {self.local_version}\n\n"
                "Установить обновление сейчас?"
            ),
            justify="left",
            anchor="w",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
        ).pack(fill="both", expand=True, padx=10, pady=10)

        actions = tk.Frame(wrap, bg=UI_COLORS["panel_soft"])
        actions.pack(fill="x", padx=10, pady=(0, 10))

        def do_update() -> None:
            decision["update"] = True
            dialog.destroy()

        self._create_round_button(actions, "Обновить", do_update).pack(side="right")
        self._create_round_button(actions, "Позже", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

        self.root.wait_window(dialog)
        return decision["update"]


    def check_for_updates(self) -> None:
        self.status_var.set("Проверка обновлений...")

        def worker() -> None:
            try:
                remote_version = fetch_remote_version()
            except (URLError, TimeoutError, OSError) as exc:
                _msg = f"Не удалось проверить обновления: {exc}"
                self.root.after(0, lambda m=_msg: self.status_var.set(m))
                return
            except Exception as exc:
                _msg = f"Ошибка проверки обновлений: {exc}"
                self.root.after(0, lambda m=_msg: self.status_var.set(m))
                return

            if not is_newer_version(remote_version, self.local_version):
                self.root.after(0, lambda: self.status_var.set(f"Обновлений нет. Версия {self.local_version} актуальна."))
                return

            def on_found_update() -> None:
                should_update = self._ask_update_decision(remote_version)
                if not should_update:
                    self.status_var.set("Обновление отложено.")
                    return

                try:
                    asset_name = get_platform_asset_name()
                    asset_url, checksum_url = fetch_latest_asset_urls(asset_name)
                    expected_sha = fetch_asset_checksum(checksum_url, asset_name)
                    self.status_var.set(f"Скачивание обновления {remote_version}...")
                    installer = download_update_asset(asset_url, asset_name, expected_sha)
                    self.status_var.set("Запуск установщика обновления...")
                    run_installer(installer, on_quit=lambda: self.root.after(200, self.root.destroy))
                except Exception as exc:
                    self.status_var.set(f"Не удалось установить обновление: {exc}")
                    messagebox.showerror("Обновление", str(exc))

            self.root.after(0, on_found_update)

        threading.Thread(target=worker, daemon=True).start()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze FortiGate config and export to Excel.")
    parser.add_argument("--input", help="Path to source FortiGate config file")
    parser.add_argument("--output", help="Path to resulting XLSX file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.input:
        input_path = Path(args.input)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        output_path = Path(args.output) if args.output else input_path.with_name(f"{input_path.stem}_analysis.xlsx")
        if output_path.suffix.lower() != ".xlsx":
            output_path = output_path.with_suffix(".xlsx")
        analyze_config(input_path, output_path)
        print(f"Done: {output_path}")
        return

    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
