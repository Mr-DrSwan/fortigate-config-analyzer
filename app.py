import argparse
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox

from fortigate_analyzer import FortigateConfigParser


def analyze_config(input_path: Path, output_path: Path) -> None:
    parser = FortigateConfigParser(str(input_path))
    parser.parse_all()
    parser.save_to_excel(str(output_path))


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("FortiGate Config Analyzer")
        self.root.geometry("760x250")
        self.root.resizable(False, False)
        self._set_window_icon()

        self.input_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Выберите файл конфигурации FortiGate (.conf).")

        self._build_ui()

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
        tk.Entry(frame, textvariable=self.input_var, width=78).grid(row=1, column=0, sticky="we", padx=(0, 8))
        tk.Button(frame, text="Выбрать...", width=14, command=self.select_input).grid(row=1, column=1)

        tk.Label(frame, text="Сохранить Excel как:").grid(row=2, column=0, sticky="w", pady=(14, 0))
        tk.Entry(frame, textvariable=self.output_var, width=78).grid(row=3, column=0, sticky="we", padx=(0, 8))
        tk.Button(frame, text="Куда сохранить...", width=14, command=self.select_output).grid(row=3, column=1)

        tk.Button(frame, text="Проанализировать и сохранить", command=self.run_analyze, height=2).grid(
            row=4, column=0, columnspan=2, sticky="we", pady=(18, 8)
        )
        tk.Label(frame, textvariable=self.status_var, anchor="w", justify="left", fg="#2E3A59").grid(
            row=5, column=0, columnspan=2, sticky="we"
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
            analyze_config(input_path, output_path)
        except SystemExit:
            self.status_var.set("Ошибка: не удалось обработать файл конфигурации.")
            messagebox.showerror("Ошибка анализа", "Не удалось обработать файл конфигурации.")
            return
        except Exception as exc:
            self.status_var.set(f"Ошибка: {exc}")
            messagebox.showerror("Ошибка анализа", str(exc))
            return

        self.status_var.set(f"Готово: {output_path}")
        messagebox.showinfo("Успех", f"Excel файл сохранен:\n{output_path}")


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
