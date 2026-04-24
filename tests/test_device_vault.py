from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.device_vault import DeviceRecord, get_app_data_dir, load_devices_from_disk


# ---------------------------------------------------------------------------
# get_app_data_dir
# ---------------------------------------------------------------------------

def test_get_app_data_dir_returns_path() -> None:
    result = get_app_data_dir()
    assert isinstance(result, Path)


def test_get_app_data_dir_contains_app_name() -> None:
    result = get_app_data_dir()
    assert "FortiGateAnalyzer" in str(result)


def test_get_app_data_dir_platform_specific() -> None:
    result = get_app_data_dir()
    system = platform.system().lower()
    if system == "darwin":
        assert "Library" in str(result) and "Application Support" in str(result)
    elif system == "windows":
        assert "AppData" in str(result) or "Roaming" in str(result)
    else:
        assert ".local" in str(result) or "XDG" in str(result) or "share" in str(result)


# ---------------------------------------------------------------------------
# load_devices_from_disk — directory layout
# ---------------------------------------------------------------------------

def test_load_devices_returns_empty_for_nonexistent_dir(tmp_path: Path) -> None:
    missing = tmp_path / "no_such_dir"
    result = load_devices_from_disk(missing)
    assert result == {}


def test_load_devices_returns_empty_for_empty_dir(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    result = load_devices_from_disk(devices_dir)
    assert result == {}


def test_load_devices_finds_single_device(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    (devices_dir / "FW-01").mkdir()
    result = load_devices_from_disk(devices_dir)
    assert "FW-01" in result


def test_load_devices_returns_device_record_type(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    (devices_dir / "FW-01").mkdir()
    result = load_devices_from_disk(devices_dir)
    assert isinstance(result["FW-01"], DeviceRecord)


def test_load_devices_skips_files_in_root(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    (devices_dir / "stray_file.txt").write_text("noise", encoding="utf-8")
    result = load_devices_from_disk(devices_dir)
    assert result == {}


def test_load_devices_multiple_devices_sorted(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    for name in ["FW-C", "FW-A", "FW-B"]:
        (devices_dir / name).mkdir()
    result = load_devices_from_disk(devices_dir)
    assert list(result.keys()) == ["FW-A", "FW-B", "FW-C"]


# ---------------------------------------------------------------------------
# load_devices_from_disk — file discovery inside device folder
# ---------------------------------------------------------------------------

def test_device_record_has_config_path(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    device_dir = devices_dir / "FW-01"
    device_dir.mkdir()
    conf = device_dir / "FW-01.conf"
    conf.write_text("config end", encoding="utf-8")
    result = load_devices_from_disk(devices_dir)
    assert result["FW-01"].config_path == conf


def test_device_record_config_path_is_none_when_missing(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    (devices_dir / "FW-01").mkdir()
    result = load_devices_from_disk(devices_dir)
    assert result["FW-01"].config_path is None


def test_device_record_excel_path_found(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    device_dir = devices_dir / "FW-01"
    device_dir.mkdir()
    xlsx = device_dir / "report.xlsx"
    xlsx.write_bytes(b"PK")
    result = load_devices_from_disk(devices_dir)
    assert result["FW-01"].excel_path == xlsx


def test_device_record_csv_path_found(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    device_dir = devices_dir / "FW-01"
    device_dir.mkdir()
    csv = device_dir / "export.csv"
    csv.write_text("a,b", encoding="utf-8")
    result = load_devices_from_disk(devices_dir)
    assert result["FW-01"].csv_path == csv


def test_device_record_name_matches_folder(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    (devices_dir / "MyFirewall").mkdir()
    result = load_devices_from_disk(devices_dir)
    assert result["MyFirewall"].name == "MyFirewall"


def test_device_record_updated_at_is_datetime_string(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    (devices_dir / "FW-01").mkdir()
    result = load_devices_from_disk(devices_dir)
    ts = result["FW-01"].updated_at
    # Format: "YYYY-MM-DD HH:MM"
    assert len(ts) == 16
    assert ts[4] == "-" and ts[7] == "-" and ts[10] == " " and ts[13] == ":"


def test_load_devices_skips_symlinks(tmp_path: Path) -> None:
    devices_dir = tmp_path / "devices"
    devices_dir.mkdir()
    real = tmp_path / "real_device"
    real.mkdir()
    link = devices_dir / "linked"
    link.symlink_to(real)
    result = load_devices_from_disk(devices_dir)
    assert "linked" not in result
