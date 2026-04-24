from pathlib import Path
import sys
import tkinter as tk

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as app_module
from app import App, analyze_config, parse_args, quote_cli, sanitize_device_name


@pytest.fixture
def app_instance():
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk is unavailable in current environment")
    root.withdraw()
    instance = App(root)
    try:
        yield instance
    finally:
        root.destroy()


def test_app_initializes_main_ui(app_instance: App) -> None:
    assert app_instance.root.title() == "FortiGate Config Analyzer"
    assert app_instance.status_var.get()
    assert app_instance.host_search_var.get()
    # right_panel is now a plain Frame (always visible), canvas is None by design
    assert app_instance.right_panel_canvas is None


def test_create_scrollbar_returns_native_tk_scrollbar(app_instance: App) -> None:
    scrollbar = app_instance._create_scrollbar(app_instance.root, lambda *_args: None)
    assert isinstance(scrollbar, tk.Scrollbar)


def test_get_selected_device_warns_when_missing_selection(app_instance: App, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = []

    def fake_warning(title: str, message: str) -> None:
        captured.append((title, message))

    monkeypatch.setattr(app_module.messagebox, "showwarning", fake_warning)
    app_instance.selected_device_name = None
    assert app_instance._get_selected_device() is None
    assert captured
    assert captured[0][0] == "Нет устройства"


def test_open_path_blocks_outside_device_vault(
    app_instance: App, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    devices_root = tmp_path / "devices"
    devices_root.mkdir()
    outside_file = tmp_path / "outside.xlsx"
    outside_file.write_text("x", encoding="utf-8")

    captured = []

    def fake_error(title: str, message: str) -> None:
        captured.append((title, message))

    monkeypatch.setattr(app_module, "DEVICES_DIR", devices_root)
    monkeypatch.setattr(app_module.messagebox, "showerror", fake_error)

    app_instance._open_path(outside_file)
    assert captured
    assert captured[0][0] == "Ошибка доступа"


def test_sanitize_dataframe_for_csv_escapes_formula_values(app_instance: App) -> None:
    source = pd.DataFrame(
        {
            "name": ["ok", "danger"],
            "value": ["normal", "=1+1"],
        }
    )
    sanitized = app_instance._sanitize_dataframe_for_csv(source)
    assert sanitized.loc[1, "value"] == "'=1+1"
    assert sanitized.loc[0, "value"] == "normal"


def test_sanitize_device_name_and_quote_cli_helpers() -> None:
    assert sanitize_device_name(" Device #1 / Prod ") == "Device_1_Prod"
    assert sanitize_device_name("...") == ""
    assert quote_cli('A "B"') == '"A \\"B\\""'


def test_parse_args_parses_cli_options(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["app.py", "--input", "in.conf", "--output", "out.xlsx"])
    args = parse_args()
    assert args.input == "in.conf"
    assert args.output == "out.xlsx"


def test_analyze_config_creates_excel_and_core_sheets(full_config_path: Path, tmp_path: Path) -> None:
    out = tmp_path / "result.xlsx"
    parser = analyze_config(full_config_path, out)
    assert out.exists()
    assert "Firewall_правила" in parser.dataframes
    assert "Адреса" in parser.dataframes
