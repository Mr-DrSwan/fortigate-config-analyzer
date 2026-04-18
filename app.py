import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
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

FORTIGATE_COLOR_OPTIONS = ["(из конфига)"] + [str(i) for i in range(0, 33)]
GITHUB_OWNER = "Mr-DrSwan"
GITHUB_REPO = "fortigate-config-analyzer"
VERSION_FILE = Path(__file__).resolve().parent / "VERSION"
DEVICES_DIR = Path(__file__).resolve().parent / "devices"
COPYRIGHT_TEXT = f"© {GITHUB_OWNER} (GitHub)"
UI_COLORS = {
    "bg": "#0E1324",
    "panel": "#151C33",
    "panel_soft": "#1B2440",
    "line": "#2A3559",
    "accent": "#22C55E",
    "text": "#E7ECFF",
    "muted": "#9AA7CB",
}


@dataclass
class DeviceRecord:
    name: str
    folder: Path
    config_path: Path
    excel_path: Path
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
        self._set_window_icon()

        self.local_version = get_local_version()
        self.status_var = tk.StringVar(value="Добавьте устройство, чтобы начать анализ.")
        self.devices: Dict[str, DeviceRecord] = {}
        self.selected_device_name: Optional[str] = None
        self.last_parser: Optional[FortigateConfigParser] = None
        self.details_vars: Dict[str, tk.StringVar] = {}
        self.devices_listbox: Optional[tk.Listbox] = None
        self.cards_canvas: Optional[tk.Canvas] = None
        self.cards_frame: Optional[tk.Frame] = None

        self._ensure_devices_dir()
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
        except tk.TclError:
            pass

    def _ensure_devices_dir(self) -> None:
        DEVICES_DIR.mkdir(parents=True, exist_ok=True)

    def _build_ui(self) -> None:
        shell = tk.Frame(self.root, bg=UI_COLORS["bg"])
        shell.pack(fill="both", expand=True, padx=12, pady=12)

        left = tk.Frame(shell, bg=UI_COLORS["panel"], width=190)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self._build_left_panel(left)

        center = tk.Frame(shell, bg=UI_COLORS["panel_soft"])
        center.pack(side="left", fill="both", expand=True, padx=12)
        self._build_center_panel(center)

        right = tk.Frame(shell, bg=UI_COLORS["panel"], width=340)
        right.pack(side="left", fill="y")
        right.pack_propagate(False)
        self._build_right_panel(right)

        footer = tk.Frame(self.root, bg=UI_COLORS["bg"])
        footer.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(
            footer,
            text=f"Версия {self.local_version} | {COPYRIGHT_TEXT}",
            anchor="e",
            bg=UI_COLORS["bg"],
            fg=UI_COLORS["muted"],
        ).pack(fill="x")

    def _build_left_panel(self, panel: tk.Frame) -> None:
        logo = tk.Frame(panel, bg=UI_COLORS["panel"])
        logo.pack(fill="x", padx=12, pady=(16, 18))
        tk.Label(
            logo,
            text="Forti Analyzer",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["text"],
            font=("Helvetica", 14, "bold"),
        ).pack(anchor="w")
        tk.Label(
            logo,
            text="Device Vault",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["muted"],
            font=("Helvetica", 10),
        ).pack(anchor="w", pady=(2, 0))

        style = {
            "bg": UI_COLORS["line"],
            "fg": UI_COLORS["text"],
            "activebackground": UI_COLORS["accent"],
            "activeforeground": "#0A0F1E",
            "relief": "flat",
            "bd": 0,
            "font": ("Helvetica", 10, "bold"),
            "cursor": "hand2",
        }

        tk.Button(panel, text="+ Добавить устройство", command=self.open_add_device_dialog, **style).pack(
            fill="x", padx=12, pady=(0, 8)
        )
        tk.Button(panel, text="Обновить список", command=self._load_devices, **style).pack(fill="x", padx=12, pady=(0, 8))
        tk.Button(panel, text="Добавить адреса", command=self.open_address_transfer_dialog, **style).pack(
            fill="x", padx=12, pady=(0, 8)
        )
        tk.Button(panel, text="Проверка обновлений", command=self.check_for_updates, **style).pack(
            fill="x", padx=12, pady=(0, 8)
        )

        tk.Label(
            panel,
            text="Configs and reports are saved\ninside the local devices vault.",
            justify="left",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["muted"],
            font=("Helvetica", 9),
        ).pack(anchor="w", padx=12, pady=(16, 0))

    def _build_center_panel(self, panel: tk.Frame) -> None:
        header = tk.Frame(panel, bg=UI_COLORS["panel_soft"])
        header.pack(fill="x", padx=14, pady=(14, 10))
        tk.Label(
            header,
            text="Добавленные устройства",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            font=("Helvetica", 16, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            textvariable=self.status_var,
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["muted"],
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

        cards_wrap = tk.Frame(panel, bg=UI_COLORS["panel_soft"], bd=1, highlightbackground=UI_COLORS["line"], highlightthickness=1)
        cards_wrap.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        canvas = tk.Canvas(cards_wrap, bg=UI_COLORS["panel_soft"], highlightthickness=0)
        scroll = tk.Scrollbar(cards_wrap, orient="vertical", command=canvas.yview)
        frame = tk.Frame(canvas, bg=UI_COLORS["panel_soft"])
        frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.cards_canvas = canvas
        self.cards_frame = frame

    def _build_right_panel(self, panel: tk.Frame) -> None:
        tk.Label(
            panel,
            text="Host Details",
            bg=UI_COLORS["panel"],
            fg=UI_COLORS["text"],
            font=("Helvetica", 14, "bold"),
        ).pack(anchor="w", padx=14, pady=(14, 8))

        list_wrap = tk.Frame(panel, bg=UI_COLORS["panel"])
        list_wrap.pack(fill="x", padx=14)
        self.devices_listbox = tk.Listbox(
            list_wrap,
            height=7,
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            selectbackground=UI_COLORS["accent"],
            selectforeground="#0A0F1E",
            borderwidth=0,
            highlightthickness=1,
            highlightcolor=UI_COLORS["line"],
            highlightbackground=UI_COLORS["line"],
            activestyle="none",
        )
        list_scroll = tk.Scrollbar(list_wrap, orient="vertical", command=self.devices_listbox.yview)
        self.devices_listbox.configure(yscrollcommand=list_scroll.set)
        self.devices_listbox.pack(side="left", fill="x", expand=True)
        list_scroll.pack(side="right", fill="y")
        self.devices_listbox.bind("<<ListboxSelect>>", self._on_device_list_select)

        details = tk.Frame(panel, bg=UI_COLORS["panel"])
        details.pack(fill="both", expand=True, padx=14, pady=(12, 8))
        self.details_vars = {
            "name": tk.StringVar(value="-"),
            "folder": tk.StringVar(value="-"),
            "config": tk.StringVar(value="-"),
            "excel": tk.StringVar(value="-"),
            "updated": tk.StringVar(value="-"),
        }
        self._build_detail_row(details, "Имя", self.details_vars["name"])
        self._build_detail_row(details, "Папка", self.details_vars["folder"])
        self._build_detail_row(details, "Конфиг", self.details_vars["config"])
        self._build_detail_row(details, "Excel", self.details_vars["excel"])
        self._build_detail_row(details, "Обновлено", self.details_vars["updated"])

        actions = tk.Frame(panel, bg=UI_COLORS["panel"])
        actions.pack(fill="x", padx=14, pady=(0, 14))
        btn_style = {
            "bg": UI_COLORS["line"],
            "fg": UI_COLORS["text"],
            "activebackground": UI_COLORS["accent"],
            "activeforeground": "#0A0F1E",
            "relief": "flat",
            "bd": 0,
            "font": ("Helvetica", 10, "bold"),
            "cursor": "hand2",
            "height": 1,
        }
        tk.Button(actions, text="Открыть конфиг", command=self.open_selected_config, **btn_style).pack(fill="x", pady=(0, 6))
        tk.Button(actions, text="Открыть Excel", command=self.open_selected_excel, **btn_style).pack(fill="x", pady=(0, 6))
        tk.Button(actions, text="Удалить устройство", command=self.delete_selected_device, **btn_style).pack(fill="x")

    def _build_detail_row(self, parent: tk.Frame, label: str, value_var: tk.StringVar) -> None:
        row = tk.Frame(parent, bg=UI_COLORS["panel"])
        row.pack(fill="x", pady=(0, 8))
        tk.Label(row, text=label, width=12, anchor="w", bg=UI_COLORS["panel"], fg=UI_COLORS["muted"]).pack(side="left")
        tk.Label(
            row,
            textvariable=value_var,
            anchor="w",
            justify="left",
            bg=UI_COLORS["panel_soft"],
            fg=UI_COLORS["text"],
            padx=8,
            pady=5,
            wraplength=195,
        ).pack(side="left", fill="x", expand=True)

    def _load_devices(self) -> None:
        records: Dict[str, DeviceRecord] = {}
        for folder in sorted(DEVICES_DIR.iterdir()):
            if not folder.is_dir():
                continue
            config_files = sorted(folder.glob("*.conf")) + sorted(folder.glob("*.txt"))
            excel_files = sorted(folder.glob("*.xlsx"))
            if not config_files or not excel_files:
                continue
            mtime = datetime.fromtimestamp(folder.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            records[folder.name] = DeviceRecord(
                name=folder.name,
                folder=folder,
                config_path=config_files[0],
                excel_path=excel_files[0],
                updated_at=mtime,
            )
        self.devices = records
        if self.selected_device_name not in self.devices:
            self.selected_device_name = next(iter(self.devices), None)
        self._refresh_devices_view()

    def _refresh_devices_view(self) -> None:
        if self.devices_listbox is not None:
            self.devices_listbox.delete(0, "end")
            for name in self.devices:
                self.devices_listbox.insert("end", name)

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
                    font=("Helvetica", 12),
                ).pack(anchor="w", padx=16, pady=18)
            else:
                for index, record in enumerate(self.devices.values()):
                    card = tk.Frame(
                        self.cards_frame,
                        bg=UI_COLORS["panel"],
                        bd=1,
                        highlightbackground=UI_COLORS["line"],
                        highlightthickness=1,
                    )
                    card.grid(row=index // 2, column=index % 2, sticky="nsew", padx=10, pady=10)
                    self.cards_frame.grid_columnconfigure(0, weight=1)
                    self.cards_frame.grid_columnconfigure(1, weight=1)

                    top = tk.Frame(card, bg=UI_COLORS["panel"])
                    top.pack(fill="x", padx=12, pady=(10, 6))
                    if hasattr(self, "_small_icon_ref"):
                        tk.Label(top, image=self._small_icon_ref, bg=UI_COLORS["panel"]).pack(side="left")
                    else:
                        tk.Label(top, text="[]", bg=UI_COLORS["panel"], fg=UI_COLORS["muted"]).pack(side="left")
                    tk.Label(
                        top,
                        text=record.name,
                        bg=UI_COLORS["panel"],
                        fg=UI_COLORS["text"],
                        font=("Helvetica", 12, "bold"),
                    ).pack(side="left", padx=(8, 0))

                    tk.Label(
                        card,
                        text=f"config: {record.config_path.name}\nexcel: {record.excel_path.name}",
                        bg=UI_COLORS["panel"],
                        fg=UI_COLORS["muted"],
                        justify="left",
                        anchor="w",
                    ).pack(fill="x", padx=12)
                    tk.Label(
                        card,
                        text=f"updated: {record.updated_at}",
                        bg=UI_COLORS["panel"],
                        fg=UI_COLORS["muted"],
                        justify="left",
                        anchor="w",
                    ).pack(fill="x", padx=12, pady=(6, 8))

                    action = tk.Button(
                        card,
                        text="Открыть меню устройства",
                        command=lambda device_name=record.name: self.show_device_menu(device_name),
                        bg=UI_COLORS["line"],
                        fg=UI_COLORS["text"],
                        activebackground=UI_COLORS["accent"],
                        activeforeground="#0A0F1E",
                        relief="flat",
                        bd=0,
                        cursor="hand2",
                    )
                    action.pack(fill="x", padx=12, pady=(0, 10))

        if self.selected_device_name:
            self.select_device(self.selected_device_name)
        else:
            self._fill_details(None)

    def select_device(self, name: str) -> None:
        if name not in self.devices:
            return
        self.selected_device_name = name
        if self.devices_listbox is not None:
            names = list(self.devices.keys())
            idx = names.index(name)
            self.devices_listbox.selection_clear(0, "end")
            self.devices_listbox.selection_set(idx)
            self.devices_listbox.activate(idx)
        self._fill_details(self.devices[name])

    def _fill_details(self, record: Optional[DeviceRecord]) -> None:
        if record is None:
            for key in self.details_vars:
                self.details_vars[key].set("-")
            return
        self.details_vars["name"].set(record.name)
        self.details_vars["folder"].set(str(record.folder.name))
        self.details_vars["config"].set(record.config_path.name)
        self.details_vars["excel"].set(record.excel_path.name)
        self.details_vars["updated"].set(record.updated_at)

    def _on_device_list_select(self, _event: tk.Event) -> None:
        if self.devices_listbox is None:
            return
        selected = self.devices_listbox.curselection()
        if not selected:
            return
        names = list(self.devices.keys())
        index = selected[0]
        if 0 <= index < len(names):
            self.select_device(names[index])

    def show_device_menu(self, device_name: str) -> None:
        self.select_device(device_name)
        menu = tk.Menu(self.root, tearoff=0, bg=UI_COLORS["panel"], fg=UI_COLORS["text"], activebackground=UI_COLORS["accent"])
        menu.add_command(label="Открыть конфиг", command=self.open_selected_config)
        menu.add_command(label="Открыть Excel", command=self.open_selected_excel)
        menu.add_separator()
        menu.add_command(label="Удалить устройство", command=self.delete_selected_device)
        x = self.root.winfo_pointerx()
        y = self.root.winfo_pointery()
        menu.tk_popup(x, y)

    def open_add_device_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Добавить устройство")
        dialog.geometry("560x250")
        dialog.transient(self.root)
        dialog.grab_set()

        name_var = tk.StringVar()
        config_var = tk.StringVar()
        status_var = tk.StringVar(value="Укажите имя устройства и файл конфига.")

        frame = tk.Frame(dialog, padx=14, pady=14)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="Имя устройства:").grid(row=0, column=0, sticky="w")
        tk.Entry(frame, textvariable=name_var).grid(row=1, column=0, columnspan=2, sticky="we", pady=(0, 10))

        tk.Label(frame, text="Конфиг FortiGate:").grid(row=2, column=0, sticky="w")
        tk.Entry(frame, textvariable=config_var).grid(row=3, column=0, sticky="we", padx=(0, 8))
        tk.Button(
            frame,
            text="Выбрать...",
            command=lambda: self._pick_config_for_dialog(config_var),
            width=14,
        ).grid(row=3, column=1, sticky="e")

        tk.Label(frame, textvariable=status_var, anchor="w", justify="left", fg="#3C4E82").grid(
            row=4, column=0, columnspan=2, sticky="we", pady=(12, 0)
        )

        actions = tk.Frame(frame)
        actions.grid(row=5, column=0, columnspan=2, sticky="e", pady=(14, 0))

        def on_create() -> None:
            try:
                device_name = self._create_device_from_config(name_var.get(), config_var.get())
            except Exception as exc:
                status_var.set(str(exc))
                return
            dialog.destroy()
            self.select_device(device_name)

        tk.Button(actions, text="Создать", width=14, command=on_create).pack(side="right")
        tk.Button(actions, text="Отмена", width=14, command=dialog.destroy).pack(side="right", padx=(0, 8))
        frame.columnconfigure(0, weight=1)

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
        src = Path(source_config).expanduser()
        if not src.exists():
            raise FileNotFoundError("Файл конфигурации не найден.")

        device_dir = DEVICES_DIR / safe_name
        if device_dir.exists():
            should_replace = messagebox.askyesno(
                "Устройство уже существует",
                f"Устройство '{safe_name}' уже есть. Пересобрать его из нового конфига?",
            )
            if not should_replace:
                raise RuntimeError("Создание отменено пользователем.")
            shutil.rmtree(device_dir)
        device_dir.mkdir(parents=True, exist_ok=True)

        config_target = device_dir / f"{safe_name}.conf"
        excel_target = device_dir / f"{safe_name}_analysis.xlsx"
        shutil.copy2(src, config_target)
        self.status_var.set(f"Анализируем конфиг устройства '{safe_name}'...")
        parser = analyze_config(config_target, excel_target)
        self.last_parser = parser

        self.status_var.set(f"Устройство '{safe_name}' добавлено. Конфиг и Excel сохранены в devices/{safe_name}.")
        self._load_devices()
        return safe_name

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
        self._open_path(record.config_path)

    def open_selected_excel(self) -> None:
        record = self._get_selected_device()
        if not record:
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
            f"Удалить устройство '{record.name}'?\nБудут удалены конфиг и Excel внутри папки devices/{record.name}.",
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
        if not record.config_path.exists():
            messagebox.showerror("Ошибка", f"Конфиг не найден:\n{record.config_path}")
            return None
        parser = FortigateConfigParser(str(record.config_path))
        parser.parse_all()
        self.last_parser = parser

    def _create_scrollable_checklist(self, parent: tk.Widget, title: str, items: List[str]) -> Dict[str, tk.BooleanVar]:
        container = tk.LabelFrame(parent, text=title, padx=8, pady=8)
        container.pack(side="left", fill="both", expand=True, padx=6, pady=6)

        filter_var = tk.StringVar()
        filter_frame = tk.Frame(container)
        filter_frame.pack(fill="x", pady=(0, 6))
        tk.Label(filter_frame, text="Поиск:").pack(side="left")
        filter_entry = tk.Entry(filter_frame, textvariable=filter_var)
        filter_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))

        canvas = tk.Canvas(container, highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        frame = tk.Frame(canvas)
        frame.bind(
            "<Configure>",
            lambda event: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        vars_map: Dict[str, tk.BooleanVar] = {}
        widgets_map: Dict[str, tk.Checkbutton] = {}
        for name in items:
            var = tk.BooleanVar(value=False)
            vars_map[name] = var
            chk = tk.Checkbutton(frame, text=name, variable=var, anchor="w", justify="left")
            chk.pack(fill="x", anchor="w")
            widgets_map[name] = chk

        def apply_filter(*_args: object) -> None:
            query = filter_var.get().strip().lower()
            for name, widget in widgets_map.items():
                visible = query in name.lower()
                if visible and not widget.winfo_ismapped():
                    widget.pack(fill="x", anchor="w")
                elif not visible and widget.winfo_ismapped():
                    widget.pack_forget()
            canvas.configure(scrollregion=canvas.bbox("all"))

        filter_var.trace_add("write", apply_filter)

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

        for widget in (canvas, frame, container):
            widget.bind("<MouseWheel>", _on_mousewheel)
            widget.bind("<Button-4>", _on_mousewheel)
            widget.bind("<Button-5>", _on_mousewheel)

        return vars_map

    def open_address_transfer_dialog(self) -> None:
        parser = self._load_parser_for_selected_device()
        if parser is None:
            return
        self.last_parser = parser

        address_names = sorted(self.last_parser.address_objects.keys())
        group_names = sorted(self.last_parser.address_group_objects.keys())
        if not address_names and not group_names:
            messagebox.showwarning("Нет объектов", "В конфиге не найдены firewall address/addrgrp.")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Выбор адресов и групп")
        dialog.geometry("980x620")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(
            dialog,
            text="Выберите адреса и/или группы адресов для подготовки команд переноса.",
            anchor="w",
            justify="left",
        ).pack(fill="x", padx=10, pady=(10, 4))

        body = tk.Frame(dialog)
        body.pack(fill="both", expand=True, padx=8, pady=6)

        address_vars = self._create_scrollable_checklist(body, "firewall address", address_names)
        group_vars = self._create_scrollable_checklist(body, "firewall addrgrp", group_names)

        actions = tk.Frame(dialog)
        actions.pack(fill="x", padx=10, pady=8)

        def on_done() -> None:
            selected_addresses = {name for name, var in address_vars.items() if var.get()}
            selected_groups = {name for name, var in group_vars.items() if var.get()}
            if not selected_addresses and not selected_groups:
                messagebox.showwarning("Пустой выбор", "Выберите хотя бы один адрес или группу.")
                return
            dialog.destroy()
            self._show_selection_summary(selected_addresses, selected_groups)

        tk.Button(actions, text="Готово", command=on_done, width=16).pack(side="right")
        tk.Button(actions, text="Отмена", command=dialog.destroy, width=16).pack(side="right", padx=(0, 8))

    def _show_selection_summary(self, selected_addresses: Set[str], selected_groups: Set[str]) -> None:
        assert self.last_parser is not None

        summary = tk.Toplevel(self.root)
        summary.title("Проверка выбора")
        summary.geometry("980x700")
        summary.transient(self.root)
        summary.grab_set()

        color_map: Dict[str, tk.StringVar] = {}

        if selected_groups:
            color_box = tk.LabelFrame(summary, text="Цвет групп (FortiGate color)", padx=8, pady=8)
            color_box.pack(fill="x", padx=10, pady=(10, 6))

            color_canvas = tk.Canvas(color_box, height=140, highlightthickness=0)
            color_scroll = tk.Scrollbar(color_box, orient="vertical", command=color_canvas.yview)
            color_frame = tk.Frame(color_canvas)
            color_frame.bind(
                "<Configure>",
                lambda event: color_canvas.configure(scrollregion=color_canvas.bbox("all")),
            )
            color_canvas.create_window((0, 0), window=color_frame, anchor="nw")
            color_canvas.configure(yscrollcommand=color_scroll.set)
            color_canvas.pack(side="left", fill="both", expand=True)
            color_scroll.pack(side="right", fill="y")

            for group_name in sorted(selected_groups):
                row = tk.Frame(color_frame)
                row.pack(fill="x", pady=2)
                tk.Label(row, text=group_name, anchor="w").pack(side="left", fill="x", expand=True)
                selected = tk.StringVar(value="(из конфига)")
                color_map[group_name] = selected
                cb = ttk.Combobox(row, textvariable=selected, values=FORTIGATE_COLOR_OPTIONS, width=16, state="readonly")
                cb.pack(side="right")

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

        text = tk.Text(summary, wrap="word")
        text.pack(fill="both", expand=True, padx=10, pady=10)

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

        actions = tk.Frame(summary)
        actions.pack(fill="x", padx=10, pady=(0, 10))

        def on_next() -> None:
            color_overrides: Dict[str, int] = {}
            for group_name, var in color_map.items():
                selected_color = var.get().strip()
                if selected_color and selected_color != "(из конфига)":
                    color_overrides[group_name] = int(selected_color)
            summary.destroy()
            self._show_duplicate_check_dialog(selected_addresses, selected_groups, color_overrides)

        tk.Button(actions, text="Далее", command=on_next, width=16).pack(side="right")
        tk.Button(actions, text="Назад", command=summary.destroy, width=16).pack(side="right", padx=(0, 8))

    def _show_duplicate_check_dialog(
        self,
        selected_addresses: Set[str],
        selected_groups: Set[str],
        group_color_overrides: Dict[str, int],
    ) -> None:
        assert self.last_parser is not None

        dialog = tk.Toplevel(self.root)
        dialog.title("Проверка дублей на целевом FortiGate")
        dialog.geometry("980x700")
        dialog.transient(self.root)
        dialog.grab_set()

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

        check_cmd = tk.Text(dialog, height=8, wrap="none")
        check_cmd.pack(fill="x", padx=10)
        check_cmd.insert("1.0", CHECK_COMMAND_TEXT)
        check_cmd.configure(state="disabled")

        def copy_check_cmd() -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(CHECK_COMMAND_TEXT)
            messagebox.showinfo("Скопировано", "Команда проверки скопирована.")

        tk.Button(dialog, text="Скопировать команду проверки", command=copy_check_cmd).pack(
            anchor="e", padx=10, pady=(6, 10)
        )

        tk.Label(dialog, text="Вставьте вывод с устройства:", anchor="w").pack(fill="x", padx=10)
        output_text = tk.Text(dialog, wrap="word", height=18)
        output_text.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        actions = tk.Frame(dialog)
        actions.pack(fill="x", padx=10, pady=(0, 10))

        def on_generate() -> None:
            cli_output = output_text.get("1.0", "end").strip()
            existing_names = self.last_parser.parse_existing_object_names(cli_output)
            plan = self.last_parser.build_transfer_plan(
                selected_addresses,
                selected_groups,
                existing_names,
                group_color_overrides=group_color_overrides,
            )
            dialog.destroy()
            self._show_commands_dialog(plan)

        tk.Button(actions, text="Сгенерировать команды", command=on_generate, width=24).pack(side="right")
        tk.Button(actions, text="Отмена", command=dialog.destroy, width=16).pack(side="right", padx=(0, 8))

    def _show_commands_dialog(self, plan: Dict[str, object]) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Готовые команды FortiGate")
        dialog.geometry("980x740")
        dialog.transient(self.root)
        dialog.grab_set()

        duplicates = tk.Text(dialog, height=10, wrap="word")
        duplicates.pack(fill="x", padx=10, pady=(10, 8))
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
        commands = tk.Text(dialog, wrap="none")
        commands.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        commands.insert("1.0", cmd_text)

        actions = tk.Frame(dialog)
        actions.pack(fill="x", padx=10, pady=(0, 10))

        def copy_commands() -> None:
            payload = commands.get("1.0", "end").strip()
            self.root.clipboard_clear()
            self.root.clipboard_append(payload)
            messagebox.showinfo("Скопировано", "Команды скопированы в буфер обмена.")

        tk.Button(actions, text="Скопировать", command=copy_commands, width=16).pack(side="right")
        tk.Button(actions, text="Закрыть", command=dialog.destroy, width=16).pack(side="right", padx=(0, 8))

    def _ask_update_decision(self, remote_version: str) -> bool:
        decision = {"update": False}
        dialog = tk.Toplevel(self.root)
        dialog.title("Доступно обновление")
        dialog.geometry("460x180")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(
            dialog,
            text=(
                f"Найдена новая версия: {remote_version}\n"
                f"Текущая версия: {self.local_version}\n\n"
                "Установить обновление сейчас?"
            ),
            justify="left",
            anchor="w",
        ).pack(fill="both", expand=True, padx=14, pady=14)

        actions = tk.Frame(dialog)
        actions.pack(fill="x", padx=14, pady=(0, 12))

        def do_update() -> None:
            decision["update"] = True
            dialog.destroy()

        tk.Button(actions, text="Обновить", width=14, command=do_update).pack(side="right")
        tk.Button(actions, text="Позже", width=14, command=dialog.destroy).pack(side="right", padx=(0, 8))

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
