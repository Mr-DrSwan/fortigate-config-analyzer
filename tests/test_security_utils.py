from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security_utils import ensure_under_root, parse_sha256_file, sanitize_spreadsheet_text


def test_ensure_under_root_allows_child(tmp_path: Path) -> None:
    root = tmp_path / "devices"
    root.mkdir()
    target = root / "dev1" / "a.conf"
    target.parent.mkdir()
    target.write_text("ok", encoding="utf-8")
    resolved = ensure_under_root(target, root, must_exist=True)
    assert resolved.exists()


def test_ensure_under_root_blocks_escape(tmp_path: Path) -> None:
    root = tmp_path / "devices"
    root.mkdir()
    outside = tmp_path / "other.txt"
    outside.write_text("bad", encoding="utf-8")
    with pytest.raises(ValueError):
        ensure_under_root(outside, root, must_exist=True)


def test_sanitize_spreadsheet_text_prefixes_formula() -> None:
    assert sanitize_spreadsheet_text("=2+2") == "'=2+2"
    assert sanitize_spreadsheet_text("+SUM(A1:A5)") == "'+SUM(A1:A5)"
    assert sanitize_spreadsheet_text("normal text") == "normal text"


def test_parse_sha256_file_reads_digest() -> None:
    payload = "3a7bd3e2360a3d80f682fbbe0f9f4b5f6a9e4f1f59d9f4a2f7f8e9c1c2d3e4f5  FortiGateAnalyzer-macOS.pkg"
    digest = parse_sha256_file(payload, expected_filename="FortiGateAnalyzer-macOS.pkg")
    assert digest == "3a7bd3e2360a3d80f682fbbe0f9f4b5f6a9e4f1f59d9f4a2f7f8e9c1c2d3e4f5"
