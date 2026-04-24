"""Update checking and downloading logic (no UI dependencies)."""

import json
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Optional, Tuple
from urllib.request import urlopen

from security_utils import parse_sha256_file, sha256_file


GITHUB_OWNER = "Mr-DrSwan"
GITHUB_REPO = "fortigate-config-analyzer"


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

def parse_version(version: str) -> tuple:
    """Parse a version string like 'v1.2.3' into a comparable tuple (1, 2, 3)."""
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


def get_local_version(version_file: Path) -> str:
    if version_file.exists():
        return version_file.read_text(encoding="utf-8").strip()
    return "0.0.0"


def get_display_version(version_file: Path) -> str:
    base = get_local_version(version_file).strip()
    if not base:
        return "v0.0.0"
    return base if base.startswith("v") else f"v{base}"


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def fetch_remote_version(owner: str = GITHUB_OWNER, repo: str = GITHUB_REPO) -> str:
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/VERSION"
    with urlopen(url, timeout=15) as resp:
        return resp.read().decode("utf-8").strip()


def get_platform_asset_name() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "FortiGateAnalyzer-Setup.exe"
    if system == "darwin":
        return "FortiGateAnalyzer-macOS.pkg"
    raise RuntimeError(f"Платформа не поддерживается автообновлением: {platform.system()}")


def fetch_latest_asset_urls(
    asset_name: str,
    owner: str = GITHUB_OWNER,
    repo: str = GITHUB_REPO,
) -> Tuple[str, str]:
    api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    with urlopen(api_url, timeout=15) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    asset_url = ""
    checksum_url = ""
    for asset in payload.get("assets", []):
        name = asset.get("name")
        if name == asset_name:
            asset_url = asset.get("browser_download_url", "")
        elif name == f"{asset_name}.sha256":
            checksum_url = asset.get("browser_download_url", "")
    if not asset_url:
        raise RuntimeError(f"В релизе не найден файл: {asset_name}")
    if not checksum_url:
        raise RuntimeError(f"В релизе не найден checksum файл: {asset_name}.sha256")
    return asset_url, checksum_url


def download_binary(url: str, target: Path) -> None:
    with urlopen(url, timeout=60) as resp:
        with target.open("wb") as handle:
            shutil.copyfileobj(resp, handle)


def fetch_asset_checksum(checksum_url: str, expected_filename: str) -> str:
    with urlopen(checksum_url, timeout=30) as resp:
        payload = resp.read().decode("utf-8", errors="ignore")
    return parse_sha256_file(payload, expected_filename=expected_filename)


def download_update_asset(url: str, filename: str, expected_sha256: str) -> Path:
    temp_dir = Path(tempfile.mkdtemp(prefix="forti-update-"))
    target = temp_dir / filename
    download_binary(url, target)
    actual_sha = sha256_file(target)
    if actual_sha.lower() != expected_sha256.lower():
        raise RuntimeError("Скачанный установщик не прошел проверку SHA256.")
    return target


def run_installer(installer_path: Path, on_quit: Callable[[], None]) -> None:
    """Launch the platform-appropriate installer and schedule app shutdown via *on_quit*."""
    system = platform.system().lower()
    if system == "windows":
        subprocess.Popen(
            [str(installer_path), "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"],
            shell=False,
        )
        on_quit()
        return

    if system == "darwin":
        subprocess.Popen(["open", str(installer_path)])
        subprocess.Popen(
            ["/bin/sh", "-c", "sleep 5; open -a FortiGateAnalyzer"],
            start_new_session=True,
        )
        on_quit()
        return

    raise RuntimeError(f"Платформа не поддерживается автообновлением: {platform.system()}")
