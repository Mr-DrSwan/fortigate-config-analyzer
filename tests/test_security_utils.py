import hashlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security_utils import (
    ensure_under_root,
    parse_sha256_file,
    sanitize_spreadsheet_text,
    sha256_file,
)


# ---------------------------------------------------------------------------
# ensure_under_root
# ---------------------------------------------------------------------------

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


def test_ensure_under_root_allows_root_itself(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    root.mkdir()
    resolved = ensure_under_root(root, root, must_exist=True)
    assert resolved == root.resolve()


def test_ensure_under_root_must_exist_false_accepts_nonexistent(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    root.mkdir()
    nonexistent = root / "ghost.conf"
    resolved = ensure_under_root(nonexistent, root, must_exist=False)
    assert "ghost.conf" in str(resolved)


def test_ensure_under_root_traversal_via_dotdot(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    root.mkdir()
    escape = root / ".." / "escape.txt"
    (tmp_path / "escape.txt").write_text("bad", encoding="utf-8")
    with pytest.raises(ValueError):
        ensure_under_root(escape, root, must_exist=True)


def test_ensure_under_root_nested_deeply(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    deep = root / "a" / "b" / "c"
    deep.mkdir(parents=True)
    target = deep / "file.txt"
    target.write_text("x", encoding="utf-8")
    resolved = ensure_under_root(target, root, must_exist=True)
    assert resolved.exists()


# ---------------------------------------------------------------------------
# sanitize_spreadsheet_text
# ---------------------------------------------------------------------------

def test_sanitize_spreadsheet_text_prefixes_formula() -> None:
    assert sanitize_spreadsheet_text("=2+2") == "'=2+2"
    assert sanitize_spreadsheet_text("+SUM(A1:A5)") == "'+SUM(A1:A5)"
    assert sanitize_spreadsheet_text("normal text") == "normal text"


def test_sanitize_spreadsheet_text_minus_prefix() -> None:
    assert sanitize_spreadsheet_text("-10") == "'-10"


def test_sanitize_spreadsheet_text_at_prefix() -> None:
    assert sanitize_spreadsheet_text("@user") == "'@user"


def test_sanitize_spreadsheet_text_tab_prefix() -> None:
    assert sanitize_spreadsheet_text("\tindented") == "'\tindented"


def test_sanitize_spreadsheet_text_empty_string() -> None:
    assert sanitize_spreadsheet_text("") == ""


def test_sanitize_spreadsheet_text_space_prefix_not_escaped() -> None:
    assert sanitize_spreadsheet_text(" leading space") == " leading space"


# ---------------------------------------------------------------------------
# sha256_file
# ---------------------------------------------------------------------------

def test_sha256_file_matches_hashlib(tmp_path: Path) -> None:
    content = b"hello fortigate"
    f = tmp_path / "test.bin"
    f.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(f) == expected


def test_sha256_file_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    expected = hashlib.sha256(b"").hexdigest()
    assert sha256_file(f) == expected


def test_sha256_file_large_content(tmp_path: Path) -> None:
    content = b"x" * (3 * 1024 * 1024)  # 3 MB — crosses chunk boundary
    f = tmp_path / "large.bin"
    f.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert sha256_file(f) == expected


def test_sha256_file_returns_hex_string(tmp_path: Path) -> None:
    f = tmp_path / "f.bin"
    f.write_bytes(b"data")
    result = sha256_file(f)
    assert len(result) == 64
    assert all(ch in "0123456789abcdef" for ch in result)


# ---------------------------------------------------------------------------
# parse_sha256_file
# ---------------------------------------------------------------------------

def test_parse_sha256_file_reads_digest() -> None:
    digest = "3a7bd3e2360a3d80f682fbbe0f9f4b5f6a9e4f1f59d9f4a2f7f8e9c1c2d3e4f5"
    payload = f"{digest}  FortiGateAnalyzer-macOS.pkg"
    result = parse_sha256_file(payload, expected_filename="FortiGateAnalyzer-macOS.pkg")
    assert result == digest


def test_parse_sha256_file_without_filename_filter() -> None:
    digest = "a" * 64
    payload = f"{digest}  anyfile.pkg"
    result = parse_sha256_file(payload)
    assert result == digest


def test_parse_sha256_file_skips_wrong_filename() -> None:
    digest = "b" * 64
    payload = f"{digest}  other.exe"
    with pytest.raises(ValueError):
        parse_sha256_file(payload, expected_filename="wanted.pkg")


def test_parse_sha256_file_raises_on_empty() -> None:
    with pytest.raises(ValueError):
        parse_sha256_file("")


def test_parse_sha256_file_raises_on_short_digest() -> None:
    with pytest.raises(ValueError):
        parse_sha256_file("abc123  file.pkg")


def test_parse_sha256_file_handles_star_prefix() -> None:
    digest = "c" * 64
    payload = f"{digest} *FortiGateAnalyzer-macOS.pkg"
    result = parse_sha256_file(payload, expected_filename="FortiGateAnalyzer-macOS.pkg")
    assert result == digest


def test_parse_sha256_file_multiline_picks_correct() -> None:
    good_digest = "d" * 64
    payload = f"notadigest  wrong.pkg\n{good_digest}  FortiGateAnalyzer-macOS.pkg"
    result = parse_sha256_file(payload, expected_filename="FortiGateAnalyzer-macOS.pkg")
    assert result == good_digest
