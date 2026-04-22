import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.error import URLError
from urllib.request import urlopen, urlretrieve

from fortigate_analyzer import FortigateConfigParser


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
APP_NAME = "FortiGateAnalyzer"
VERSION_FILE = APP_ROOT / "VERSION"


def get_app_data_dir() -> Path:
    system_name = platform.system().lower()
    if system_name == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    if system_name == "windows":
        appdata = os.getenv("APPDATA")
        return Path(appdata) / APP_NAME if appdata else Path.home() / "AppData" / "Roaming" / APP_NAME
    xdg_data_home = os.getenv("XDG_DATA_HOME")
    return Path(xdg_data_home) / APP_NAME if xdg_data_home else Path.home() / ".local" / "share" / APP_NAME


APP_DATA_DIR = get_app_data_dir() if getattr(sys, "frozen", False) else APP_ROOT
DEVICES_DIR = APP_DATA_DIR / "devices"
GITHUB_PROFILE_URL = f"https://github.com/{GITHUB_OWNER}"
COPYRIGHT_TEXT = f"© {GITHUB_OWNER} (GitHub)"
UI_STYLE_TOKENS = {
    "colors": {
        "bg": "#1B2033",
        "panel": "#232940",
        "panel_soft": "#1F253A",
        "panel_shadow": "#151A2B",
        "line": "#2E3550",
        "line_soft": "#3A4261",
        "accent": "#3ED17F",
        "accent_soft": "#4B7BE3",
        "text": "#E9EEFF",
        "muted": "#8F99B8",
        "button_app_fg": "#E9EEFF",
        "button_app_bg": "#2A314A",
        "button_app_bg_active": "#343C59",
        "button_app_bg_pressed": "#3E4769",
        "button_app_bg_disabled": "#262C42",
        "button_app_fg_disabled": "#6F7898",
        "button_danger_fg": "#FFC9CD",
        "button_danger_bg": "#4C2B36",
        "button_danger_bg_active": "#603242",
        "button_danger_bg_pressed": "#743A4E",
        "entry_light": "#202741",
        "scrollbar_track": "#262D45",
        "scrollbar_thumb": "#8A94AF",
        "scrollbar_thumb_active": "#A3ABC0",
        "chip_hover": "#323B5A",
        "button_primary_fill": "#2A314A",
        "button_primary_hover": "#353E5D",
        "button_primary_border": "#3E486B",
        "button_primary_text": "#E9EEFF",
        "button_danger_fill": "#4C2B36",
        "button_danger_hover": "#623445",
        "button_danger_border": "#7A4258",
        "button_danger_text": "#FFC9CD",
        "button_ghost_hover": "#2D3552",
        "window_ctrl_close": "#FF5F57",
        "window_ctrl_minimize": "#FEBB2E",
        "window_ctrl_maximize": "#28C840",
        "window_ctrl_idle": "#3A415E",
        "window_ctrl_idle_border": "#4A5274",
    },
    "fonts": {
        "label_xs": ("Helvetica", 8),
        "label_sm": ("Helvetica", 9),
        "label_sm_bold": ("Helvetica", 9, "bold"),
        "label_md": ("Helvetica", 10),
        "label_lg": ("Helvetica", 11),
        "label_lg_bold": ("Helvetica", 11, "bold"),
        "title_md_bold": ("Helvetica", 13, "bold"),
        "title_lg_bold": ("Helvetica", 15, "bold"),
        "title_xl_bold": ("Helvetica", 17, "bold"),
        "action_bold": ("Helvetica", 10, "bold"),
    },
    "spacing": {
        "outer": 14,
        "section": 16,
        "gap": 10,
        "tight": 6,
    },
    "metrics": {
        "radius_panel": 14,
        "radius_block": 10,
        "radius_card": 9,
        "radius_control": 8,
        "radius_chip": 8,
        "radius_device_card": 10,
        "height_shell_panel": 360,
        "height_device_menu_bar": 46,
        "height_device_menu_item": 32,
        "height_chip": 30,
        "height_main_card": 320,
        "height_host_list": 170,
        "height_dropdown": 340,
        "height_device_card": 214,
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
        "height_header": 132,
        "height_titlebar": 34,
        "height_container_min": 110,
        "height_button_sm": 32,
        "height_button_md": 34,
        "height_button_lg": 36,
        "control_height": 38,
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


@dataclass
class DeviceRecord:
    name: str
    folder: Path
    config_path: Optional[Path]
    excel_path: Optional[Path]
    csv_path: Optional[Path]
    updated_at: str


def analyze_config(input_path: Path, output_path: Path) -> FortigateConfigParser:
    parser = FortigateConfigParser(str(input_path))
    parser.parse_all()
    parser.save_to_excel(str(output_path))
    return parser


def get_local_version() -> str:
    if VERSION_FILE.exists():
        return VERSION_FILE.read_text(encoding="utf-8").strip()
    return "0.0.0"


def get_display_version() -> str:
    base = get_local_version().strip()
    if not base:
        return "v0.0.0"
    return base if base.startswith("v") else f"v{base}"


def parse_version(version: str) -> tuple:
    cleaned = version.strip().lstrip("v")
    parts = []
    for token in cleaned.split("."):
        digits = "".join(ch for ch in token if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def is_newer_version(remote_version: str, local_version: str) -> bool:
    return parse_version(remote_version) > parse_version(local_version)


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


class RoundedScrollbar(tk.Canvas):
    def __init__(
        self,
        parent: tk.Widget,
        command: Callable[..., None],
        *,
        track_color: str,
        thumb_color: str,
        thumb_hover_color: str,
        width: int = 11,
    ) -> None:
        super().__init__(parent, width=width, highlightthickness=0, bd=0, bg=track_color, takefocus=0, cursor="arrow")
        self._command = command
        self._track_color = track_color
        self._thumb_color = thumb_color
        self._thumb_hover_color = thumb_hover_color
        self._first = 0.0
        self._last = 1.0
        self._hover = False
        self._drag_offset = 0.0
        self._thumb_top = 0.0
        self._thumb_bottom = 0.0
        self._thumb_tag = "thumb"
        self.bind("<Configure>", lambda _e: self._redraw())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_press)
        self.bind("<B1-Motion>", self._on_drag)

    def set(self, first: str, last: str) -> None:
        self._first = max(0.0, min(1.0, float(first)))
        self._last = max(self._first, min(1.0, float(last)))
        self._redraw()

    def _draw_pill(self, x1: float, y1: float, x2: float, y2: float, color: str, tag: str) -> None:
        radius = max(1.0, min((x2 - x1) / 2, (y2 - y1) / 2))
        self.create_rectangle(x1 + radius, y1, x2 - radius, y2, fill=color, outline=color, tags=(tag,))
        self.create_oval(x1, y1, x1 + radius * 2, y2, fill=color, outline=color, tags=(tag,))
        self.create_oval(x2 - radius * 2, y1, x2, y2, fill=color, outline=color, tags=(tag,))

    def _redraw(self) -> None:
        self.delete("all")
        w = max(8, self.winfo_width())
        h = max(20, self.winfo_height())
        x1, x2 = 2, w - 2
        self._draw_pill(x1, 1, x2, h - 1, self._track_color, "track")
        span = max(0.05, self._last - self._first)
        thumb_h = max(24.0, h * span)
        y1 = min(h - thumb_h - 1, max(1.0, h * self._first))
        y2 = y1 + thumb_h
        self._thumb_top = y1
        self._thumb_bottom = y2
        thumb_color = self._thumb_hover_color if self._hover else self._thumb_color
        self._draw_pill(x1 + 1, y1, x2 - 1, y2, thumb_color, self._thumb_tag)

    def _on_enter(self, _event: tk.Event) -> None:
        self._hover = True
        self._redraw()

    def _on_leave(self, _event: tk.Event) -> None:
        self._hover = False
        self._redraw()

    def _on_press(self, event: tk.Event) -> None:
        y = float(getattr(event, "y", 0))
        if self._thumb_top <= y <= self._thumb_bottom:
            self._drag_offset = y - self._thumb_top
            return
        self._drag_offset = (self._thumb_bottom - self._thumb_top) / 2
        if y < self._thumb_top:
            self._command("scroll", -1, "pages")
        else:
            self._command("scroll", 1, "pages")

    def _on_drag(self, event: tk.Event) -> None:
        h = max(20.0, float(self.winfo_height()))
        size = max(0.05, self._last - self._first)
        y = float(getattr(event, "y", 0)) - self._drag_offset
        first = max(0.0, min(1.0 - size, y / h))
        self._command("moveto", str(first))


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FortiGate Config Analyzer")
        self.root.geometry("1280x760")
        self.root.minsize(1120, 680)
        self.root.configure(bg=UI_COLORS["bg"])
        self._configure_window_chrome()
        self._set_window_icon()

        self.local_version = get_display_version()
        self.status_var = tk.StringVar(value="Добавьте устройство, чтобы начать анализ.")
        self.devices: Dict[str, DeviceRecord] = {}
        self.selected_device_name: Optional[str] = None
        self.last_parser: Optional[FortigateConfigParser] = None
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
            padding=(12, 9),
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
            padding=(12, 9),
            foreground=UI_COLORS["button_danger_fg"],
            background=UI_COLORS["button_danger_bg"],
            borderwidth=0,
            focusthickness=0,
        )
        style.map("Danger.TButton", background=[("active", UI_COLORS["button_danger_bg_active"]), ("pressed", UI_COLORS["button_danger_bg_pressed"])])
        style.configure("Rounded.TEntry", fieldbackground=UI_COLORS["entry_light"], borderwidth=0, relief="flat", padding=(8, 7))
        style.configure("Card.TFrame", background=UI_COLORS["panel"], borderwidth=1, relief="solid")
        style.configure("Ghost.TButton", font=UI_FONTS["label_sm_bold"], padding=(10, 6), foreground=UI_COLORS["muted"])
        style.configure(
            "Vault.Vertical.TScrollbar",
            troughcolor=UI_COLORS["scrollbar_track"],
            background=UI_COLORS["scrollbar_thumb"],
            bordercolor=UI_COLORS["scrollbar_track"],
            arrowcolor=UI_COLORS["scrollbar_track"],
            darkcolor=UI_COLORS["scrollbar_thumb"],
            lightcolor=UI_COLORS["scrollbar_thumb"],
            gripcount=0,
            relief="flat",
            borderwidth=0,
            arrowsize=8,
            width=9,
        )
        style.map("Vault.Vertical.TScrollbar", background=[("active", UI_COLORS["scrollbar_thumb_active"]), ("pressed", UI_COLORS["scrollbar_thumb_active"])])
        style.configure(
            "Vault.TCombobox",
            fieldbackground=UI_COLORS["panel"],
            background=UI_COLORS["panel"],
            foreground=UI_COLORS["text"],
            arrowcolor=UI_COLORS["text"],
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
                radius=22,
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

        shell = tk.Frame(self.ui_root, bg=UI_COLORS["bg"])
        shell.pack(fill="both", expand=True, padx=UI_SPACING["outer"], pady=(UI_SPACING["gap"], UI_SPACING["outer"]))

        left_canvas, left = self._create_rounded_container(
            shell,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel"],
            border_color=UI_COLORS["line_soft"],
            radius=UI_STYLE_KIT["radius_panel"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_shell_panel"],
        )
        left_canvas.configure(width=210)
        left_canvas.pack(side="left", fill="y")
        self._build_left_panel(left)

        center_canvas, center = self._create_rounded_container(
            shell,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line_soft"],
            radius=UI_STYLE_KIT["radius_panel"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_shell_panel"],
        )
        center_canvas.pack(side="left", fill="both", expand=True, padx=UI_SPACING["outer"])
        self._build_center_panel(center)

        right_canvas, right = self._create_rounded_container(
            shell,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel"],
            border_color=UI_COLORS["line_soft"],
            radius=UI_STYLE_KIT["radius_panel"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_shell_panel"],
        )
        right_canvas.configure(width=360)
        self.right_panel_canvas = right_canvas
        self._build_right_panel(right)

        footer = tk.Frame(self.ui_root, bg=UI_COLORS["bg"])
        footer.pack(fill="x", padx=UI_SPACING["outer"], pady=(0, UI_SPACING["tight"]))
        footer_right = tk.Frame(footer, bg=UI_COLORS["bg"])
        footer_right.pack(side="right")
        tk.Label(
            footer_right,
            text=f"Версия {self.local_version}  |  ",
            anchor="w",
            bg=UI_COLORS["bg"],
            fg=UI_COLORS["muted"],
        ).pack(side="left")
        clickable_style = {
            "bg": UI_COLORS["bg"],
            "fg": UI_COLORS["muted"],
            "font": UI_FONTS["label_sm"],
        }
        copyright_link = tk.Label(footer_right, text="© Mr-DrSwan", **clickable_style)
        copyright_link.pack(side="left")
        tk.Label(footer_right, text="  ·  ", bg=UI_COLORS["bg"], fg=UI_COLORS["muted"]).pack(side="left")
        github_link = tk.Label(footer_right, text="GitHub", **clickable_style)
        github_link.pack(side="left")
        for widget in (copyright_link, github_link):
            widget.bind("<Button-1>", self._open_github_profile)

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

        menu_active = self.active_device_tab is None
        menu_canvas, menu_inner = self._create_rounded_container(
            self.open_tabs_frame,
            outer_bg=UI_COLORS["panel"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["accent"] if menu_active else UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_control"],
            border_width=2 if menu_active else 1,
            min_height=UI_STYLE_KIT["height_device_menu_item"],
        )
        menu_canvas.configure(width=120)
        menu_canvas.pack(side="left", padx=(0, 8), pady=(0, 2))
        menu_label = tk.Label(
            menu_inner,
            text="MENU",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"] if menu_active else UI_COLORS["muted"],
            font=UI_FONTS["label_sm_bold"],
        )
        menu_label.pack(fill="both", expand=True)
        menu_label.bind("<Button-1>", lambda _e: self._activate_menu_tab())

        for device_name in self.opened_devices:
            is_active = device_name == self.active_device_tab
            tab_canvas, tab_inner = self._create_rounded_container(
                self.open_tabs_frame,
                outer_bg=UI_COLORS["panel"],
                fill_color=UI_COLORS["panel_soft"],
                border_color=UI_COLORS["accent"] if is_active else UI_COLORS["line"],
                radius=UI_STYLE_KIT["radius_control"],
                border_width=2 if is_active else 1,
                min_height=UI_STYLE_KIT["height_device_menu_item"],
            )
            tab_canvas.pack(side="left", padx=(0, 8), pady=(0, 2))
            tab_canvas.configure(width=170)
            title = tk.Label(
                tab_inner,
                text=device_name,
                bg=UI_COLORS["panel_soft"],
                fg=UI_COLORS["text"],
                font=UI_FONTS["label_sm_bold"],
                anchor="w",
            )
            title.pack(side="left", fill="x", expand=True, padx=(8, 4))
            close_btn = tk.Label(
                tab_inner,
                text="x",
                bg=UI_COLORS["panel_soft"],
                fg=UI_COLORS["muted"],
                font=UI_FONTS["label_sm_bold"],
            )
            close_btn.pack(side="right", padx=(0, 8))
            title.bind("<Button-1>", lambda _e, n=device_name: self._activate_device_tab(n))
            close_btn.bind("<Button-1>", lambda _e, n=device_name: self._close_open_tab(n))

        if not self.opened_devices:
            tk.Label(
                self.open_tabs_frame,
                text="Нет открытых устройств",
                bg=UI_COLORS["panel"],
                fg=UI_COLORS["muted"],
                font=UI_FONTS["label_sm"],
            ).pack(side="left", padx=(6, 0))

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
        if self.cards_wrap_canvas is not None and not self.cards_wrap_canvas.winfo_manager():
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

        if self.cards_wrap_canvas is not None and self.cards_wrap_canvas.winfo_manager():
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
        record = self.devices.get(device_name)
        if record is None:
            return
        self.select_device(device_name)
        self._ensure_device_tab(device_name, activate=True)
        self.active_editor_device = None
        self._show_right_panel()

        if self.cards_wrap_canvas is not None and self.cards_wrap_canvas.winfo_manager():
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
        parser = self._load_parser_for_selected_device()
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
        parser = self._load_parser_for_selected_device()
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
        parser = self._load_parser_for_selected_device()
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
        header_canvas, header = self._create_rounded_container(
            self.ui_root,
            outer_bg=UI_COLORS["bg"],
            fill_color=UI_COLORS["panel"],
            border_color=UI_COLORS["line_soft"],
            radius=UI_STYLE_KIT["radius_block"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_header"],
        )
        top_pad = UI_SPACING["gap"]
        header_canvas.pack(fill="x", padx=UI_SPACING["outer"], pady=(top_pad, 0))

        top_row = tk.Frame(header, bg=UI_COLORS["panel"])
        top_row.pack(fill="x", padx=10, pady=(8, 4))

        left = tk.Frame(top_row, bg=UI_COLORS["panel"])
        left.pack(side="left", fill="y")

        if hasattr(self, "_header_icon_ref"):
            tk.Label(left, image=self._header_icon_ref, bg=UI_COLORS["panel"]).pack(side="left", padx=(16, 10))
        elif hasattr(self, "_small_icon_ref"):
            tk.Label(left, image=self._small_icon_ref, bg=UI_COLORS["panel"]).pack(side="left", padx=(16, 10))

        title_wrap = tk.Frame(left, bg=UI_COLORS["panel"])
        title_wrap.pack(side="left", fill="y")
        tk.Label(
            title_wrap,
            text="Forti Analyzer",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["text"],
            font=UI_FONTS["title_xl_bold"],
        ).pack(anchor="w", pady=(4, 0))
        tk.Label(
            title_wrap,
            text="Device Vault",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_md"],
        ).pack(anchor="w")

        search_shell, search_inner = self._create_rounded_container(
            top_row,
            outer_bg=UI_COLORS["panel"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line"],
            radius=UI_STYLE_KIT["radius_control"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_button_lg"],
        )
        search_shell.pack(side="left", fill="x", expand=True, padx=(14, 12), pady=(2, 0))
        search_entry = tk.Entry(
            search_inner,
            textvariable=self.host_search_var,
            relief="flat",
            bd=0,
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            insertbackground=UI_COLORS["text"],
        )
        search_entry.insert(0, "Find a host or device...")
        search_entry.pack(fill="both", expand=True, padx=10, pady=4)

        def _clear_placeholder(_event) -> None:
            if search_entry.get() == "Find a host or device...":
                search_entry.delete(0, "end")

        def _restore_placeholder(_event) -> None:
            if not search_entry.get().strip():
                search_entry.insert(0, "Find a host or device...")

        search_entry.bind("<FocusIn>", _clear_placeholder)
        search_entry.bind("<FocusOut>", _restore_placeholder)

        toolbar = tk.Frame(top_row, bg=UI_COLORS["panel"])
        toolbar.pack(side="right", padx=(0, 6))
        for item in ("GRID", "SEARCH", "FILTER"):
            chip_canvas, chip_inner = self._create_rounded_container(
                toolbar,
                outer_bg=UI_COLORS["panel"],
                fill_color=UI_COLORS["panel_soft"],
                border_color=UI_COLORS["line"],
                radius=UI_STYLE_KIT["radius_chip"],
                border_width=1,
                min_height=UI_STYLE_KIT["height_chip"],
            )
            chip_canvas.configure(width=84)
            chip_canvas.pack(side="left", padx=(0, 8), pady=8)
            chip = tk.Label(
                chip_inner,
                text=item,
                bg=UI_COLORS["panel_soft"],
                fg=UI_COLORS["muted"],
                font=UI_FONTS["label_sm_bold"],
            )
            chip.pack(fill="both", expand=True)

            def on_enter(_event, c=chip_canvas, l=chip) -> None:
                c._rounded_fill = UI_COLORS["chip_hover"]  # type: ignore[attr-defined]
                self._set_rounded_style(c, UI_COLORS["accent_soft"], 1)
                l.configure(bg=UI_COLORS["chip_hover"], fg=UI_COLORS["text"])

            def on_leave(_event, c=chip_canvas, l=chip) -> None:
                c._rounded_fill = UI_COLORS["panel_soft"]  # type: ignore[attr-defined]
                self._set_rounded_style(c, UI_COLORS["line"], 1)
                l.configure(bg=UI_COLORS["panel_soft"], fg=UI_COLORS["muted"])

            for widget in (chip_canvas, chip_inner, chip):
                widget.bind("<Enter>", on_enter)
                widget.bind("<Leave>", on_leave)

        tabs_row = tk.Frame(header, bg=UI_COLORS["panel"])
        tabs_row.pack(fill="x", padx=10, pady=(2, 8))
        self.open_tabs_frame = tk.Frame(tabs_row, bg=UI_COLORS["panel"])
        self.open_tabs_frame.pack(side="left", fill="x", expand=True)
        self._refresh_open_tabs()

        right = tk.Frame(tabs_row, bg=UI_COLORS["panel"])
        right.pack(side="right", padx=(10, 0))
        tk.Label(
            right,
            text="Opened devices",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_sm_bold"],
        ).pack(side="right")

    def _build_left_panel(self, panel: tk.Frame) -> None:
        logo = tk.Frame(panel, bg=UI_COLORS["panel"])
        logo.pack(fill="x", padx=UI_SPACING["section"], pady=(UI_SPACING["section"], UI_SPACING["gap"]))
        tk.Label(
            logo,
            text="Actions",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["muted"],
            font=UI_FONTS["action_bold"],
        ).pack(anchor="w")

        self._create_round_button(panel, "+  Добавить устройство", self.open_add_device_dialog).pack(
            fill="x", padx=UI_SPACING["section"], pady=(0, UI_SPACING["gap"])
        )
        self._create_round_button(panel, "o  Обновить список", self._load_devices).pack(
            fill="x", padx=UI_SPACING["section"], pady=(0, UI_SPACING["gap"])
        )
        self._create_round_button(panel, ">  Добавить адреса", self.open_address_transfer_dialog).pack(
            fill="x", padx=UI_SPACING["section"], pady=(0, UI_SPACING["gap"])
        )
        self._create_round_button(panel, "[]  Страница устройства", self._open_selected_device_page).pack(
            fill="x", padx=UI_SPACING["section"], pady=(0, UI_SPACING["gap"])
        )
        self._create_round_button(panel, "^  Проверка обновлений", self.check_for_updates).pack(
            fill="x", padx=UI_SPACING["section"], pady=(0, UI_SPACING["gap"])
        )

        tk.Label(
            panel,
            text="Configs and reports are saved\ninside the local devices vault.",
            justify="left",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_sm"],
        ).pack(anchor="w", padx=UI_SPACING["section"], pady=(UI_SPACING["section"], 0))

    def _build_center_panel(self, panel: tk.Frame) -> None:
        header = tk.Frame(panel, bg=UI_COLORS["panel_soft"])
        header.pack(fill="x", padx=UI_SPACING["section"], pady=(UI_SPACING["section"], UI_SPACING["gap"]))
        tk.Label(
            header,
            text="Добавленные устройства",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            font=UI_FONTS["title_lg_bold"],
        ).pack(anchor="w")
        tk.Label(
            header,
            textvariable=self.status_var,
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["muted"],
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

        self.cards_wrap_canvas, cards_wrap = self._create_rounded_container(
            panel,
            outer_bg=UI_COLORS["panel_soft"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line_soft"],
            radius=UI_STYLE_KIT["radius_block"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_main_card"],
        )
        self.cards_wrap_canvas.pack(fill="both", expand=True, padx=UI_SPACING["section"], pady=(0, UI_SPACING["section"]))

        canvas = tk.Canvas(cards_wrap, bg=UI_COLORS["panel_soft"], highlightthickness=0)
        scroll = self._create_scrollbar(cards_wrap, canvas.yview)
        frame = tk.Frame(canvas, bg=UI_COLORS["panel_soft"])
        frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.cards_canvas = canvas
        self.cards_frame = frame

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
        self._create_round_button(actions, "Посмотреть адреса", self._show_addresses_for_selected_device).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Сортировка по группам", self._open_group_sorting_for_selected_device).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Найти дубликаты", self._show_address_duplicates_for_selected_device).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Открыть встроенный редактор", self._open_selected_device_editor).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Открыть Excel", self.open_selected_excel).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Открыть CSV", self.open_selected_config).pack(fill="x")
        self.device_page_canvas.pack_forget()

    def _build_right_panel(self, panel: tk.Frame) -> None:
        panel_scroll_canvas = tk.Canvas(panel, bg=UI_COLORS["panel"], highlightthickness=0)
        panel_scroll = self._create_scrollbar(panel, panel_scroll_canvas.yview)
        panel_content = tk.Frame(panel_scroll_canvas, bg=UI_COLORS["panel"])
        panel_window = panel_scroll_canvas.create_window((0, 0), window=panel_content, anchor="nw")
        panel_content.bind("<Configure>", lambda _event: panel_scroll_canvas.configure(scrollregion=panel_scroll_canvas.bbox("all")))
        panel_scroll_canvas.bind("<Configure>", lambda event: panel_scroll_canvas.itemconfigure(panel_window, width=event.width))
        panel_scroll_canvas.configure(yscrollcommand=panel_scroll.set)
        panel_scroll_canvas.pack(side="left", fill="both", expand=True)
        panel_scroll.pack(side="right", fill="y")
        self._bind_vertical_mousewheel(panel_scroll_canvas, panel_scroll_canvas, panel_content)

        title_row = tk.Frame(panel_content, bg=UI_COLORS["panel"])
        title_row.pack(fill="x", padx=UI_SPACING["section"], pady=(UI_SPACING["section"], UI_SPACING["gap"]))
        tk.Label(
            title_row,
            text="Host Details",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["text"],
            font=UI_FONTS["title_md_bold"],
        ).pack(side="left")
        tk.Label(
            title_row,
            text="Закрыть",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["muted"],
            font=UI_FONTS["label_sm_bold"],
        ).pack(side="right")
        title_row.winfo_children()[-1].bind("<Button-1>", lambda _e: self._hide_right_panel())

        list_wrap = tk.Frame(panel_content, bg=UI_COLORS["panel"])
        list_wrap.pack(fill="x", padx=UI_SPACING["section"])
        hosts_wrap_canvas, hosts_wrap = self._create_rounded_container(
            list_wrap,
            outer_bg=UI_COLORS["panel"],
            fill_color=UI_COLORS["panel_soft"],
            border_color=UI_COLORS["line_soft"],
            radius=UI_STYLE_KIT["radius_card"],
            border_width=1,
            min_height=UI_STYLE_KIT["height_transfer_color_map"],
        )
        hosts_wrap_canvas.pack(fill="x")
        hosts_canvas = tk.Canvas(hosts_wrap, height=160, bg=UI_COLORS["panel_soft"], highlightthickness=0)
        hosts_scroll = self._create_scrollbar(hosts_wrap, hosts_canvas.yview)
        hosts_frame = tk.Frame(hosts_canvas, bg=UI_COLORS["panel_soft"])
        hosts_frame.bind("<Configure>", lambda event: hosts_canvas.configure(scrollregion=hosts_canvas.bbox("all")))
        hosts_canvas.create_window((0, 0), window=hosts_frame, anchor="nw")
        hosts_canvas.configure(yscrollcommand=hosts_scroll.set)
        hosts_canvas.pack(side="left", fill="x", expand=True)
        hosts_scroll.pack(side="right", fill="y")
        self._bind_vertical_mousewheel(hosts_canvas, hosts_canvas, hosts_frame, fallback_canvas=panel_scroll_canvas)
        self.hosts_canvas = hosts_canvas
        self.hosts_frame = hosts_frame

        details = tk.Frame(panel_content, bg=UI_COLORS["panel"])
        details.pack(fill="both", expand=True, padx=UI_SPACING["section"], pady=(UI_SPACING["section"], UI_SPACING["tight"]))
        self.details_vars = {
            "name": tk.StringVar(value="-"),
            "folder": tk.StringVar(value="-"),
            "config": tk.StringVar(value="-"),
            "excel": tk.StringVar(value="-"),
            "csv": tk.StringVar(value="-"),
            "updated": tk.StringVar(value="-"),
        }
        self._build_detail_row(details, "Имя", self.details_vars["name"])
        self._build_detail_row(details, "Папка", self.details_vars["folder"])
        self._build_detail_row(details, "Конфиг", self.details_vars["config"])
        self._build_detail_row(details, "Excel", self.details_vars["excel"])
        self._build_detail_row(details, "CSV", self.details_vars["csv"])
        self._build_detail_row(details, "Обновлено", self.details_vars["updated"])

        actions = tk.Frame(panel_content, bg=UI_COLORS["panel"])
        actions.pack(fill="x", padx=UI_SPACING["section"], pady=(0, UI_SPACING["section"]))
        self._create_round_button(actions, "Добавить/заменить конфиг", self.attach_config_to_selected_device).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Открыть CSV конфиг", self.open_selected_config).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Открыть Excel", self.open_selected_excel).pack(fill="x", pady=(0, 6))
        self._create_round_button(actions, "Удалить устройство", self.delete_selected_device, style_kind="danger").pack(fill="x")

    def _build_detail_row(self, parent: tk.Frame, label: str, value_var: tk.StringVar) -> None:
        row = tk.Frame(parent, bg=UI_COLORS["panel"])
        row.pack(fill="x", pady=(0, UI_SPACING["gap"]))
        tk.Label(row, text=label, width=11, anchor="w", bg=UI_COLORS["panel"], fg=UI_COLORS["muted"]).pack(side="left", padx=(0, 6))
        tk.Label(
            row,
            textvariable=value_var,
            anchor="w",
            justify="left",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            padx=10,
            pady=7,
            wraplength=195,
        ).pack(side="left", fill="x", expand=True)

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

    def _create_scrollbar(self, parent: tk.Widget, command) -> RoundedScrollbar:
        return RoundedScrollbar(
            parent,
            command,
            track_color=UI_COLORS["scrollbar_track"],
            thumb_color=UI_COLORS["scrollbar_thumb"],
            thumb_hover_color=UI_COLORS["scrollbar_thumb_active"],
        )

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
        records: Dict[str, DeviceRecord] = {}
        for folder in sorted(DEVICES_DIR.iterdir()):
            if not folder.is_dir():
                continue
            config_files = sorted(folder.glob("*.conf")) + sorted(folder.glob("*.txt"))
            excel_files = sorted(folder.glob("*.xlsx"))
            csv_files = sorted(folder.glob("*.csv"))
            mtime = datetime.fromtimestamp(folder.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            records[folder.name] = DeviceRecord(
                name=folder.name,
                folder=folder,
                config_path=config_files[0] if config_files else None,
                excel_path=excel_files[0] if excel_files else None,
                csv_path=csv_files[0] if csv_files else None,
                updated_at=mtime,
            )
        self.devices = records
        self.opened_devices = [name for name in self.opened_devices if name in self.devices]
        if self.active_device_tab not in self.devices:
            self.active_device_tab = self.opened_devices[-1] if self.opened_devices else None
        if self.active_editor_device not in self.devices:
            self.active_editor_device = self.opened_devices[-1] if self.opened_devices else None
        if self.selected_device_name not in self.devices:
            self.selected_device_name = next(iter(self.devices), None)
        self._refresh_open_tabs()
        self._refresh_devices_view()

    def _refresh_devices_view(self) -> None:
        self._refresh_right_hosts()
        self.card_canvases = {}

        if self.cards_frame is not None:
            for child in self.cards_frame.winfo_children():
                child.destroy()
            if not self.devices:
                tk.Label(
                    self.cards_frame,
                    text="Пока нет устройств.\nНажмите «Добавить устройство» слева.",
                    bg=UI_COLORS["panel_soft"],
                    fg=UI_COLORS["muted"],
                    justify="left",
                    font=UI_FONTS["label_lg"],
                ).pack(anchor="w", padx=UI_SPACING["section"], pady=UI_SPACING["section"])
            else:
                for index, record in enumerate(self.devices.values()):
                    is_selected = record.name == self.selected_device_name
                    card_canvas, card = self._create_rounded_container(
                        self.cards_frame,
                        outer_bg=UI_COLORS["panel_soft"],
                        fill_color=UI_COLORS["panel"],
                        border_color=UI_COLORS["accent"] if is_selected else UI_COLORS["line"],
                        radius=UI_STYLE_KIT["radius_device_card"],
                        border_width=2 if is_selected else 1,
                        min_height=UI_STYLE_KIT["height_device_card"] + UI_STYLE_KIT["height_button_md"] + 28,
                    )
                    card_canvas.grid(
                        row=index // 2,
                        column=index % 2,
                        sticky="nsew",
                        padx=UI_SPACING["gap"],
                        pady=UI_SPACING["gap"],
                    )
                    self.card_canvases[record.name] = card_canvas
                    self.cards_frame.grid_columnconfigure(0, weight=1)
                    self.cards_frame.grid_columnconfigure(1, weight=1)

                    top = tk.Frame(card, bg=UI_COLORS["panel"])
                    top.pack(fill="x", padx=UI_SPACING["section"], pady=(UI_SPACING["section"], UI_SPACING["tight"]))
                    if hasattr(self, "_small_icon_ref"):
                        tk.Label(top, image=self._small_icon_ref, bg=UI_COLORS["panel"]).pack(side="left")
                    else:
                        tk.Label(top, text="[]", bg=UI_COLORS["panel"], fg=UI_COLORS["muted"]).pack(side="left")
                    tk.Label(
                        top,
                        text=record.name,
                        bg=UI_COLORS["panel"],
                        fg=UI_COLORS["text"],
                        font=UI_FONTS["label_lg_bold"],
                    ).pack(side="left", padx=(8, 0))
                    edit_btn = tk.Label(
                        top,
                        text="✎",
                        bg=UI_COLORS["panel_soft"],
                        fg=UI_COLORS["muted"],
                        font=UI_FONTS["action_bold"],
                        padx=8,
                        pady=2,
                    )
                    edit_btn.pack(side="right")
                    edit_btn.bind("<Button-1>", lambda _event, n=record.name: self._open_device_page(n))

                    tk.Label(
                        card,
                        text=(
                            f"config: {record.config_path.name if record.config_path else '-'}\n"
                            f"excel: {record.excel_path.name if record.excel_path else '-'}\n"
                            f"csv: {record.csv_path.name if record.csv_path else '-'}"
                        ),
                        bg=UI_COLORS["panel"],
                        fg=UI_COLORS["muted"],
                        justify="left",
                        anchor="w",
                    ).pack(fill="x", padx=UI_SPACING["section"])
                    tk.Label(
                        card,
                        text=f"updated: {record.updated_at}",
                        bg=UI_COLORS["panel"],
                        fg=UI_COLORS["muted"],
                        justify="left",
                        anchor="w",
                    ).pack(fill="x", padx=UI_SPACING["section"], pady=(UI_SPACING["tight"], UI_SPACING["gap"]))

                    action_row = tk.Frame(card, bg=UI_COLORS["panel"])
                    action_row.pack(fill="x", padx=UI_SPACING["section"], pady=(0, UI_SPACING["section"]))
                    self._create_round_button(
                        action_row,
                        "Открыть страницу устройства",
                        lambda device_name=record.name: self._open_device_page(device_name),
                        min_height=UI_STYLE_KIT["height_button_md"],
                    ).pack(fill="x", pady=(0, 6))
                    self._create_round_button(
                        action_row,
                        "Открыть в редакторе",
                        lambda device_name=record.name: self._open_device_editor(device_name),
                        style_kind="ghost",
                        min_height=UI_STYLE_KIT["height_button_md"],
                    ).pack(fill="x")
                    click_widgets = (card_canvas, card, top)
                    for widget in click_widgets:
                        widget.bind("<Button-1>", lambda _event, n=record.name: self._open_device_page(n))
                    hover_widgets = (card_canvas, card, top, action_row)
                    for widget in hover_widgets:
                        widget.bind("<Enter>", lambda _event, n=record.name, s=is_selected: self._set_card_hover(n, s, True))
                        widget.bind("<Leave>", lambda _event, n=record.name, s=is_selected: self._set_card_hover(n, s, False))

        if self.selected_device_name:
            self.select_device(self.selected_device_name)
        else:
            self._fill_details(None)
        if self.active_editor_device and self.active_editor_device in self.devices:
            self._open_device_editor(self.active_editor_device)
        elif self.active_device_tab and self.active_device_tab in self.devices:
            self._open_device_page(self.active_device_tab)
        elif not self.opened_devices:
            self._show_cards_view()

    def select_device(self, name: str) -> None:
        if name not in self.devices:
            return
        self.selected_device_name = name
        self._refresh_right_hosts()
        for device_name, canvas in self.card_canvases.items():
            if device_name == self.selected_device_name:
                self._set_rounded_style(canvas, UI_COLORS["accent"], 2)
            else:
                self._set_rounded_style(canvas, UI_COLORS["line"], 1)
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
                border_color=UI_COLORS["accent"] if is_selected else UI_COLORS["line"],
                radius=UI_STYLE_KIT["radius_card"],
                border_width=2 if is_selected else 1,
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
            self._set_rounded_style(canvas, UI_COLORS["accent"], 2)
            return
        self._set_rounded_style(canvas, UI_COLORS["accent_soft"] if hover else UI_COLORS["line"], 2 if hover else 1)

    def _set_host_hover(self, device_name: str, is_selected: bool, hover: bool) -> None:
        canvas = self.host_tile_canvases.get(device_name)
        if canvas is None:
            return
        if is_selected:
            self._set_rounded_style(canvas, UI_COLORS["accent"], 2)
            return
        self._set_rounded_style(canvas, UI_COLORS["accent_soft"] if hover else UI_COLORS["line"], 2 if hover else 1)

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

    def _replace_or_append_config_section(self, config_text: str, section_name: str, section_body: str) -> str:
        target = f"config {section_name}".lower()
        lines = config_text.splitlines()
        start_idx = -1
        end_idx = -1
        depth = 0
        in_target = False

        for idx, raw in enumerate(lines):
            line = raw.strip().lower()
            if not in_target:
                if line == target:
                    in_target = True
                    start_idx = idx
                    depth = 1
                continue
            if line.startswith("config "):
                depth += 1
                continue
            if line == "end":
                depth -= 1
                if depth == 0:
                    end_idx = idx
                    break

        section_lines = section_body.splitlines()
        if start_idx >= 0 and end_idx >= start_idx:
            rebuilt = lines[:start_idx] + section_lines + lines[end_idx + 1 :]
        else:
            rebuilt = lines[:]
            if rebuilt and rebuilt[-1].strip():
                rebuilt.append("")
            rebuilt.extend(section_lines)
        return "\n".join(rebuilt).rstrip() + "\n"

    def _persist_current_address_data_to_selected_config(self) -> bool:
        if self.last_parser is None:
            return False
        record = self._get_selected_device()
        if not record or not record.config_path or not record.config_path.exists():
            return False

        parser = self.last_parser
        address_lines: List[str] = ["config firewall address"]
        for name in sorted(parser.address_objects.keys(), key=str.lower):
            address_lines.extend(parser._build_address_command_block(name))  # type: ignore[attr-defined]
        address_lines.append("end")

        group_lines: List[str] = ["config firewall addrgrp"]
        for name in sorted(parser.address_group_objects.keys(), key=str.lower):
            group_lines.extend(parser._build_addrgrp_command_block(name))  # type: ignore[attr-defined]
        group_lines.append("end")

        text = record.config_path.read_text(encoding="utf-8", errors="ignore")
        text = self._replace_or_append_config_section(text, "firewall address", "\n".join(address_lines))
        text = self._replace_or_append_config_section(text, "firewall addrgrp", "\n".join(group_lines))
        record.config_path.write_text(text, encoding="utf-8")
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
                device_name = self._create_device_from_config(name_var.get(), config_var.get())
            except Exception as exc:
                status_var.set(str(exc))
                return
            dialog.destroy()
            self.select_device(device_name)

        self._create_round_button(actions, "Создать", on_create).pack(side="right")
        self._create_round_button(actions, "Отмена", dialog.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

    def _pick_config_for_dialog(self, target_var: tk.StringVar) -> None:
        file_path = filedialog.askopenfilename(
            title="Выберите конфигурацию FortiGate",
            filetypes=[("FortiGate config", "*.conf *.txt"), ("All files", "*.*")],
        )
        if file_path:
            target_var.set(file_path)

    def _create_device_from_config(self, raw_name: str, source_config: str) -> str:
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
            shutil.rmtree(device_dir)
        device_dir.mkdir(parents=True, exist_ok=True)
        if source_config.strip():
            self._attach_config_to_device(safe_name, Path(source_config).expanduser())
            self.status_var.set(f"Устройство '{safe_name}' добавлено. Конфиг, Excel и CSV созданы.")
        else:
            self.status_var.set(f"Устройство '{safe_name}' добавлено без конфига.")
        self._load_devices()
        return safe_name

    def _attach_config_to_device(self, device_name: str, source_config: Path) -> None:
        src = source_config.expanduser()
        if not src.exists():
            raise FileNotFoundError("Файл конфигурации не найден.")
        device_dir = DEVICES_DIR / device_name
        device_dir.mkdir(parents=True, exist_ok=True)

        config_target = device_dir / f"{device_name}.conf"
        excel_target = device_dir / f"{device_name}_analysis.xlsx"
        csv_target = device_dir / f"{device_name}_analysis.csv"
        shutil.copy2(src, config_target)

        self.status_var.set(f"Анализируем конфиг устройства '{device_name}'...")
        parser = analyze_config(config_target, excel_target)
        self.last_parser = parser

        # CSV нужен для быстрого просмотра/импорта в другие инструменты.
        sheet = next(iter(parser.dataframes.values()), None)
        if sheet is not None:
            sheet.to_csv(csv_target, index=False, encoding="utf-8-sig")

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
        try:
            self._attach_config_to_device(record.name, Path(file_path))
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))
            return
        self.status_var.set(f"Конфиг устройства '{record.name}' обновлен. Excel и CSV пересобраны.")
        self._load_devices()
        self.select_device(record.name)

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
        shutil.rmtree(record.folder, ignore_errors=False)
        self.selected_device_name = None
        self.last_parser = None
        self.status_var.set(f"Устройство '{record.name}' удалено.")
        self._load_devices()

    def _load_parser_for_selected_device(self) -> Optional[FortigateConfigParser]:
        record = self._get_selected_device()
        if not record:
            return None
        if not record.config_path:
            messagebox.showwarning("Нет конфига", "У выбранного устройства еще нет конфига. Добавьте или замените конфиг.")
            return None
        if not record.config_path.exists():
            messagebox.showerror("Ошибка", f"Конфиг не найден:\n{record.config_path}")
            return None
        parser = FortigateConfigParser(str(record.config_path))
        parser.parse_all()
        self.last_parser = parser
        return parser

    @staticmethod
    def _extract_first_ipv4(value: str) -> Optional[int]:
        match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", value)
        if not match:
            return None
        try:
            return int(ipaddress.ip_address(match.group(0)))
        except ValueError:
            return None

    @staticmethod
    def _subnet_to_display(subnet: str) -> str:
        parts = subnet.split()
        if len(parts) != 2:
            return subnet
        try:
            network = ipaddress.IPv4Network((parts[0], parts[1]), strict=False)
        except ValueError:
            return subnet
        return f"{parts[0]}/{network.prefixlen}"

    @staticmethod
    def _normalize_subnet_value(raw_value: str) -> str:
        value = raw_value.strip()
        if not value:
            raise ValueError("Subnet не может быть пустым.")
        if "/" in value:
            iface = ipaddress.ip_interface(value)
            return f"{iface.ip} {iface.network.netmask}"
        parts = value.split()
        if len(parts) != 2:
            raise ValueError("Subnet должен быть в формате 10.0.0.0/24 или 10.0.0.0 255.255.255.0.")
        ipaddress.ip_address(parts[0])
        ipaddress.ip_address(parts[1])
        return f"{parts[0]} {parts[1]}"

    @staticmethod
    def _normalize_iprange_value(raw_value: str) -> str:
        value = raw_value.strip()
        if not value:
            raise ValueError("IP range не может быть пустым.")
        if "-" in value:
            parts = [part.strip() for part in value.split("-", maxsplit=1)]
        else:
            parts = value.split()
        if len(parts) != 2:
            raise ValueError("IP range должен быть в формате 10.0.0.1-10.0.0.254.")
        ipaddress.ip_address(parts[0])
        ipaddress.ip_address(parts[1])
        return f"{parts[0]} {parts[1]}"

    def _get_address_display_value(self, address_name: str) -> str:
        if self.last_parser is None:
            return ""
        obj = self.last_parser.address_objects.get(address_name, {})
        fqdn_value = obj.get("fqdn", "").strip()
        if fqdn_value:
            return fqdn_value
        iprange_value = obj.get("iprange", "").strip()
        if iprange_value:
            parts = iprange_value.split()
            if len(parts) >= 2:
                return f"{parts[0]} - {parts[1]}"
            return iprange_value
        subnet_value = obj.get("subnet", "").strip()
        if subnet_value:
            return self._subnet_to_display(subnet_value)
        return obj.get("type", "").strip()

    def _address_sort_key(self, address_name: str) -> Tuple[int, object, str]:
        display = self._get_address_display_value(address_name)
        numeric_ip = self._extract_first_ipv4(display)
        if numeric_ip is not None:
            return (0, numeric_ip, address_name.lower())
        if display:
            return (1, display.lower(), address_name.lower())
        return (2, address_name.lower(), address_name.lower())

    def _address_sort_mode_key(self, address_name: str, sort_mode: str) -> Tuple[int, object, str]:
        if sort_mode.startswith("name_"):
            return (0, address_name.lower(), address_name.lower())
        display = self._get_address_display_value(address_name)
        numeric_ip = self._extract_first_ipv4(display)
        if numeric_ip is not None:
            return (0, numeric_ip, address_name.lower())
        if display:
            return (1, display.lower(), address_name.lower())
        return (2, address_name.lower(), address_name.lower())

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
        return "subnet", self._subnet_to_display(subnet_value) if subnet_value else ""

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

        def _on_mousewheel(event: tk.Event) -> str:
            units = _scroll_units_from_event(event)
            if units:
                canvas.yview_scroll(units, "units")
                return "break"
            return ""

        def _bind_mousewheel_recursive(widget: tk.Widget) -> None:
            widget.bind("<MouseWheel>", _on_mousewheel)
            widget.bind("<Button-4>", _on_mousewheel)
            widget.bind("<Button-5>", _on_mousewheel)
            for child in widget.winfo_children():
                _bind_mousewheel_recursive(child)

        _bind_mousewheel_recursive(editor_wrap)
        _bind_mousewheel_recursive(rows_frame)
        _bind_mousewheel_recursive(canvas)

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
                        normalized = self._normalize_subnet_value(raw_value)
                    elif edit_type == "iprange":
                        normalized = self._normalize_iprange_value(raw_value)
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

        def _on_mousewheel(event: tk.Event) -> str:
            units = _scroll_units_from_event(event)
            if units:
                canvas.yview_scroll(units, "units")
                return "break"
            return ""

        def _bind_mousewheel_recursive(widget: tk.Widget) -> None:
            widget.bind("<MouseWheel>", _on_mousewheel)
            widget.bind("<Button-4>", _on_mousewheel)
            widget.bind("<Button-5>", _on_mousewheel)
            for child in widget.winfo_children():
                _bind_mousewheel_recursive(child)

        _bind_mousewheel_recursive(content_wrap)
        _bind_mousewheel_recursive(rows_frame)
        _bind_mousewheel_recursive(canvas)

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
        for name in items:
            var = tk.BooleanVar(value=False)
            vars_map[name] = var
            right_text = (right_text_map or {}).get(name, "")
            row = tk.Frame(frame, bg=UI_COLORS["panel"])
            chk = tk.Checkbutton(
                row,
                text=name,
                variable=var,
                anchor="w",
                justify="left",
                bg=UI_COLORS["panel"],
                fg=UI_COLORS["text"],
                selectcolor=UI_COLORS["panel_soft"],
                activebackground=UI_COLORS["panel"],
                activeforeground=UI_COLORS["text"],
            )
            chk.pack(side="left", fill="x", expand=True, anchor="w")
            if right_text:
                tk.Label(
                    row,
                    text=right_text,
                    anchor="e",
                    justify="right",
                    bg=UI_COLORS["panel"],
                    fg=UI_COLORS["muted"],
                    font=UI_FONTS["label_md"],
                ).pack(side="right", padx=(6, 4))
            row.pack(fill="x", anchor="w")
            widgets_map[name] = row
            searchable_map[name] = f"{name} {right_text}".lower()

        def apply_filter(*_args: object) -> None:
            query = filter_var.get().strip().lower()
            visible_names = [name for name in items if query in searchable_map.get(name, name.lower())]

            if sort_options and sort_key_builder and sort_var.get():
                current_mode = sort_var.get()
                reverse = current_mode.endswith("_desc")
                visible_names = sorted(visible_names, key=lambda name: sort_key_builder(name, current_mode), reverse=reverse)

            for widget in widgets_map.values():
                if widget.winfo_ismapped():
                    widget.pack_forget()
            for name in visible_names:
                widgets_map[name].pack(fill="x", anchor="w")
            canvas.configure(scrollregion=canvas.bbox("all"))

        def select_filtered(select_value: bool) -> None:
            query = filter_var.get().strip().lower()
            for name, var in vars_map.items():
                if query and query not in searchable_map.get(name, name.lower()):
                    continue
                var.set(select_value)

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
                    command=lambda: (_refresh_sort_button_text(), apply_filter()),
                )
            _refresh_sort_button_text()

        filter_var.trace_add("write", apply_filter)
        apply_filter()

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

        def _on_mousewheel(event: tk.Event) -> str:
            units = _scroll_units_from_event(event)
            if units:
                canvas.yview_scroll(units, "units")
                return "break"
            return ""

        def _bind_mousewheel_recursive(widget: tk.Widget) -> None:
            widget.bind("<MouseWheel>", _on_mousewheel)
            widget.bind("<Button-4>", _on_mousewheel)
            widget.bind("<Button-5>", _on_mousewheel)
            for child in widget.winfo_children():
                _bind_mousewheel_recursive(child)

        _bind_mousewheel_recursive(container)
        _bind_mousewheel_recursive(frame)
        _bind_mousewheel_recursive(canvas)

        return vars_map

    def open_address_transfer_dialog(
        self,
        preselected_addresses: Optional[Set[str]] = None,
        preselected_groups: Optional[Set[str]] = None,
        preselected_address_color_overrides: Optional[Dict[str, int]] = None,
        reuse_current_parser: bool = False,
    ) -> None:
        if reuse_current_parser and self.last_parser is not None:
            parser = self.last_parser
        else:
            parser = self._load_parser_for_selected_device()
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
            text="Выберите адреса и/или группы адресов для подготовки команд переноса.",
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
            self._show_selection_summary(selected_addresses, selected_groups, filtered_color_overrides)

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

            def _on_color_mousewheel(event: tk.Event) -> str:
                delta = getattr(event, "delta", 0)
                if delta > 0:
                    color_canvas.yview_scroll(-1, "units")
                    return "break"
                if delta < 0:
                    color_canvas.yview_scroll(1, "units")
                    return "break"
                num = getattr(event, "num", 0)
                if num == 4:
                    color_canvas.yview_scroll(-1, "units")
                    return "break"
                if num == 5:
                    color_canvas.yview_scroll(1, "units")
                    return "break"
                return ""

            for widget in (color_canvas, color_frame, color_box):
                widget.bind("<MouseWheel>", _on_color_mousewheel)
                widget.bind("<Button-4>", _on_color_mousewheel)
                widget.bind("<Button-5>", _on_color_mousewheel)

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
            )

        self._create_round_button(actions, "Далее", on_next).pack(side="right")
        self._create_round_button(actions, "Назад", summary.destroy, style_kind="ghost").pack(side="right", padx=(0, 8))

    def _show_duplicate_check_dialog(
        self,
        selected_addresses: Set[str],
        selected_groups: Set[str],
        group_color_overrides: Dict[str, int],
        address_color_overrides: Dict[str, int],
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

        def on_generate() -> None:
            cli_output = output_text.get("1.0", "end").strip()
            existing_names = self.last_parser.parse_existing_object_names(cli_output)
            plan = self.last_parser.build_transfer_plan(
                selected_addresses,
                selected_groups,
                existing_names,
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

    def _fetch_remote_version(self) -> str:
        url = f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/main/VERSION"
        with urlopen(url, timeout=15) as resp:
            return resp.read().decode("utf-8").strip()

    def _get_platform_asset_name(self) -> str:
        system = platform.system().lower()
        if system == "windows":
            return "FortiGateAnalyzer-Setup.exe"
        if system == "darwin":
            return "FortiGateAnalyzer-macOS.pkg"
        raise RuntimeError(f"Платформа не поддерживается автообновлением: {platform.system()}")

    def _fetch_latest_asset_url(self, asset_name: str) -> str:
        api_url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
        with urlopen(api_url, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        for asset in payload.get("assets", []):
            if asset.get("name") == asset_name:
                return asset.get("browser_download_url", "")
        raise RuntimeError(f"В релизе не найден файл: {asset_name}")

    def _download_update_asset(self, url: str, filename: str) -> Path:
        temp_dir = Path(tempfile.mkdtemp(prefix="forti-update-"))
        target = temp_dir / filename
        urlretrieve(url, target)
        return target

    def _run_installer_and_restart(self, installer_path: Path) -> None:
        system = platform.system().lower()
        if system == "windows":
            subprocess.Popen(
                [
                    str(installer_path),
                    "/CLOSEAPPLICATIONS",
                    "/RESTARTAPPLICATIONS",
                ],
                shell=False,
            )
            self.root.after(200, self.root.destroy)
            return

        if system == "darwin":
            # For macOS installer we open .pkg and schedule app relaunch.
            subprocess.Popen(["open", str(installer_path)])
            subprocess.Popen(
                [
                    "/bin/sh",
                    "-c",
                    "sleep 5; open -a FortiGateAnalyzer",
                ],
                start_new_session=True,
            )
            self.root.after(200, self.root.destroy)
            return

        raise RuntimeError(f"Платформа не поддерживается автообновлением: {platform.system()}")

    def check_for_updates(self) -> None:
        self.status_var.set("Проверка обновлений...")

        def worker() -> None:
            try:
                remote_version = self._fetch_remote_version()
            except (URLError, TimeoutError, OSError) as exc:
                self.root.after(0, lambda: self.status_var.set(f"Не удалось проверить обновления: {exc}"))
                return
            except Exception as exc:
                self.root.after(0, lambda: self.status_var.set(f"Ошибка проверки обновлений: {exc}"))
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
                    asset_name = self._get_platform_asset_name()
                    asset_url = self._fetch_latest_asset_url(asset_name)
                    self.status_var.set(f"Скачивание обновления {remote_version}...")
                    installer = self._download_update_asset(asset_url, asset_name)
                    self.status_var.set("Запуск установщика обновления...")
                    self._run_installer_and_restart(installer)
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
