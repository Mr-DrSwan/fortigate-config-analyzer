"""Device vault: data model and disk I/O for saved FortiGate devices."""

import os
import platform
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from security_utils import ensure_under_root


APP_NAME = "FortiGateAnalyzer"


def get_app_data_dir() -> Path:
    system_name = platform.system().lower()
    if system_name == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    if system_name == "windows":
        appdata = os.getenv("APPDATA")
        return Path(appdata) / APP_NAME if appdata else Path.home() / "AppData" / "Roaming" / APP_NAME
    xdg_data_home = os.getenv("XDG_DATA_HOME")
    return Path(xdg_data_home) / APP_NAME if xdg_data_home else Path.home() / ".local" / "share" / APP_NAME


@dataclass
class DeviceRecord:
    name: str
    folder: Path
    config_path: Optional[Path]
    excel_path: Optional[Path]
    csv_path: Optional[Path]
    updated_at: str


def load_devices_from_disk(devices_dir: Path) -> Dict[str, DeviceRecord]:
    """Scan *devices_dir* and build a mapping of device-name → DeviceRecord.

    Only directories that reside strictly inside *devices_dir* are included
    (symlinks and path-traversal attempts are silently skipped).
    """
    records: Dict[str, DeviceRecord] = {}
    if not devices_dir.exists():
        return records

    vault_root = devices_dir.resolve()
    for folder in sorted(devices_dir.iterdir()):
        if not folder.is_dir() or folder.is_symlink():
            continue
        try:
            resolved_folder = ensure_under_root(folder, vault_root, must_exist=True)
        except ValueError:
            continue

        def _safe(path: Path) -> bool:
            try:
                ensure_under_root(path, vault_root, must_exist=True)
                return True
            except Exception:
                return False

        config_files = [p for p in sorted(folder.glob("*.conf")) + sorted(folder.glob("*.txt")) if _safe(p)]
        excel_files = [p for p in sorted(folder.glob("*.xlsx")) if _safe(p)]
        csv_files = [p for p in sorted(folder.glob("*.csv")) if _safe(p)]
        mtime = datetime.fromtimestamp(folder.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        records[folder.name] = DeviceRecord(
            name=folder.name,
            folder=resolved_folder,
            config_path=config_files[0] if config_files else None,
            excel_path=excel_files[0] if excel_files else None,
            csv_path=csv_files[0] if csv_files else None,
            updated_at=mtime,
        )
    return records
