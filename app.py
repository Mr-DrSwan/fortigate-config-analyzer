import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import threading
from typing import Dict, List, Optional, Set
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
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


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FortiGate Config Analyzer")
        self.root.geometry("780x280")
        self.root.resizable(False, False)
        self._set_window_icon()

        self.input_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Выберите файл конфигурации FortiGate (.conf).")

        self.last_parser: Optional[FortigateConfigParser] = None
        self._build_ui()
        self.local_version = get_local_version()

    def _set_window_icon(self) -> None:
        icon_path = Path(__file__).resolve().parent / "assets" / "forti-analyzer-icon.png"
        if not icon_path.exists():
            return
        try:
            icon = tk.PhotoImage(file=str(icon_path))
            self.root.iconphoto(True, icon)
            self._icon_ref = icon
        except tk.TclError:
            pass

    def _build_ui(self) -> None:
        frame = tk.Frame(self.root, padx=14, pady=14)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="Файл конфигурации FortiGate (.conf):").grid(row=0, column=0, sticky="w")
        tk.Entry(frame, textvariable=self.input_var, width=80).grid(row=1, column=0, sticky="we", padx=(0, 8))
        tk.Button(frame, text="Выбрать...", width=14, command=self.select_input).grid(row=1, column=1)

        tk.Label(frame, text="Сохранить Excel как:").grid(row=2, column=0, sticky="w", pady=(14, 0))
        tk.Entry(frame, textvariable=self.output_var, width=80).grid(row=3, column=0, sticky="we", padx=(0, 8))
        tk.Button(frame, text="Куда сохранить...", width=14, command=self.select_output).grid(row=3, column=1)

        tk.Button(frame, text="Проанализировать и сохранить", command=self.run_analyze, height=2).grid(
            row=4, column=0, sticky="we", pady=(18, 8), padx=(0, 8)
        )
        self.transfer_button = tk.Button(
            frame,
            text="Добавить адреса",
            command=self.open_address_transfer_dialog,
            height=2,
            state="disabled",
        )
        self.transfer_button.grid(row=4, column=1, sticky="we", pady=(18, 8))

        tk.Label(frame, textvariable=self.status_var, anchor="w", justify="left", fg="#2E3A59").grid(
            row=5, column=0, columnspan=2, sticky="we"
        )
        tk.Button(frame, text="Проверка обновлений", command=self.check_for_updates, height=1).grid(
            row=6, column=0, columnspan=2, sticky="we", pady=(8, 0)
        )
        frame.columnconfigure(0, weight=1)

    def select_input(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Выберите конфигурацию FortiGate",
            filetypes=[("FortiGate config", "*.conf *.txt"), ("All files", "*.*")],
        )
        if not file_path:
            return
        self.input_var.set(file_path)

        default_output = str(Path(file_path).with_suffix("")) + "_analysis.xlsx"
        if not self.output_var.get():
            self.output_var.set(default_output)

    def select_output(self) -> None:
        initial = self.output_var.get() or "fortigate_analysis.xlsx"
        file_path = filedialog.asksaveasfilename(
            title="Куда сохранить Excel",
            defaultextension=".xlsx",
            initialfile=Path(initial).name,
            filetypes=[("Excel file", "*.xlsx")],
        )
        if file_path:
            self.output_var.set(file_path)

    def run_analyze(self) -> None:
        input_value = self.input_var.get().strip()
        output_value = self.output_var.get().strip()

        if not input_value:
            messagebox.showwarning("Нет входного файла", "Сначала выберите .conf файл.")
            return

        input_path = Path(input_value)
        if not input_path.exists():
            messagebox.showerror("Ошибка", "Выбранный входной файл не найден.")
            return

        output_path = Path(output_value) if output_value else input_path.with_name(f"{input_path.stem}_analysis.xlsx")
        if output_path.suffix.lower() != ".xlsx":
            output_path = output_path.with_suffix(".xlsx")

        try:
            self.last_parser = analyze_config(input_path, output_path)
        except SystemExit:
            self.status_var.set("Ошибка: не удалось обработать файл конфигурации.")
            messagebox.showerror("Ошибка анализа", "Не удалось обработать файл конфигурации.")
            return
        except Exception as exc:
            self.status_var.set(f"Ошибка: {exc}")
            messagebox.showerror("Ошибка анализа", str(exc))
            return

        self.transfer_button.configure(state="normal")
        self.status_var.set(f"Готово: {output_path}")
        messagebox.showinfo("Успех", f"Excel файл сохранен:\n{output_path}")

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
        if self.last_parser is None:
            messagebox.showwarning("Нет данных", "Сначала проанализируйте конфиг.")
            return

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
