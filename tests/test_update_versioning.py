from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.updater import (
    fetch_asset_checksum,
    fetch_latest_asset_urls,
    fetch_remote_version,
    get_display_version,
    get_local_version,
    get_platform_asset_name,
    is_newer_version,
    parse_version,
)


# ---------------------------------------------------------------------------
# parse_version
# ---------------------------------------------------------------------------

def test_parse_version_handles_prefix_and_short_versions() -> None:
    assert parse_version("v1.2.3") == (1, 2, 3)
    assert parse_version("2.5") == (2, 5, 0)
    assert parse_version("3") == (3, 0, 0)


def test_parse_version_strips_whitespace() -> None:
    assert parse_version("  v1.0.0  ") == (1, 0, 0)


def test_parse_version_handles_zero() -> None:
    assert parse_version("0.0.0") == (0, 0, 0)


def test_parse_version_ignores_non_digit_suffix() -> None:
    assert parse_version("v2.1.3-beta") == (2, 1, 3)


# ---------------------------------------------------------------------------
# is_newer_version
# ---------------------------------------------------------------------------

def test_is_newer_version_compares_semver_order() -> None:
    assert is_newer_version("1.0.1", "1.0.0")
    assert is_newer_version("1.2.0", "1.1.9")
    assert not is_newer_version("1.0.0", "1.0.0")
    assert not is_newer_version("0.9.9", "1.0.0")


def test_is_newer_version_major_beats_minor() -> None:
    assert is_newer_version("2.0.0", "1.9.9")


def test_is_newer_version_same_version_is_false() -> None:
    assert not is_newer_version("v1.2.3", "v1.2.3")


# ---------------------------------------------------------------------------
# get_local_version / get_display_version
# ---------------------------------------------------------------------------

def test_get_local_version_reads_file(tmp_path: Path) -> None:
    vf = tmp_path / "VERSION"
    vf.write_text("v1.2.3\n", encoding="utf-8")
    assert get_local_version(vf) == "v1.2.3"


def test_get_local_version_returns_fallback_for_missing_file(tmp_path: Path) -> None:
    assert get_local_version(tmp_path / "missing") == "0.0.0"


def test_get_display_version_adds_v_prefix(tmp_path: Path) -> None:
    vf = tmp_path / "VERSION"
    vf.write_text("1.0.0", encoding="utf-8")
    assert get_display_version(vf) == "v1.0.0"


def test_get_display_version_keeps_existing_prefix(tmp_path: Path) -> None:
    vf = tmp_path / "VERSION"
    vf.write_text("v2.3.0", encoding="utf-8")
    assert get_display_version(vf) == "v2.3.0"


def test_get_display_version_missing_file(tmp_path: Path) -> None:
    assert get_display_version(tmp_path / "missing") == "v0.0.0"


# ---------------------------------------------------------------------------
# get_platform_asset_name
# ---------------------------------------------------------------------------

def test_get_platform_asset_name_windows() -> None:
    with patch("services.updater.platform.system", return_value="Windows"):
        name = get_platform_asset_name()
    assert name == "FortiGateAnalyzer-Setup.exe"


def test_get_platform_asset_name_macos() -> None:
    with patch("services.updater.platform.system", return_value="Darwin"):
        name = get_platform_asset_name()
    assert name == "FortiGateAnalyzer-macOS.pkg"


def test_get_platform_asset_name_linux_raises() -> None:
    with patch("services.updater.platform.system", return_value="Linux"):
        with pytest.raises(RuntimeError):
            get_platform_asset_name()


# ---------------------------------------------------------------------------
# fetch_remote_version (mocked network)
# ---------------------------------------------------------------------------

def test_fetch_remote_version_returns_stripped_string() -> None:
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = b"v1.5.0\n"
    with patch("services.updater.urlopen", return_value=mock_resp):
        result = fetch_remote_version()
    assert result == "v1.5.0"


# ---------------------------------------------------------------------------
# fetch_latest_asset_urls (mocked network)
# ---------------------------------------------------------------------------

def test_fetch_latest_asset_urls_parses_response() -> None:
    payload = {
        "assets": [
            {"name": "FortiGateAnalyzer-Setup.exe", "browser_download_url": "https://example.com/setup.exe"},
            {"name": "FortiGateAnalyzer-Setup.exe.sha256", "browser_download_url": "https://example.com/setup.exe.sha256"},
        ]
    }
    import json

    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = json.dumps(payload).encode()
    with patch("services.updater.urlopen", return_value=mock_resp):
        asset_url, checksum_url = fetch_latest_asset_urls("FortiGateAnalyzer-Setup.exe")
    assert asset_url == "https://example.com/setup.exe"
    assert checksum_url == "https://example.com/setup.exe.sha256"


def test_fetch_latest_asset_urls_raises_when_asset_missing() -> None:
    import json

    payload = {"assets": []}
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = json.dumps(payload).encode()
    with patch("services.updater.urlopen", return_value=mock_resp):
        with pytest.raises(RuntimeError, match="не найден файл"):
            fetch_latest_asset_urls("FortiGateAnalyzer-Setup.exe")


# ---------------------------------------------------------------------------
# fetch_asset_checksum (mocked network)
# ---------------------------------------------------------------------------

def test_fetch_asset_checksum_parses_sha256() -> None:
    digest = "a" * 64
    payload = f"{digest}  FortiGateAnalyzer-macOS.pkg\n"
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = payload.encode()
    with patch("services.updater.urlopen", return_value=mock_resp):
        result = fetch_asset_checksum("https://example.com/x.sha256", "FortiGateAnalyzer-macOS.pkg")
    assert result == digest
