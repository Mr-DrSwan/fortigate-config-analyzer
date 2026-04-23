import hashlib
from pathlib import Path
from typing import Optional


SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def ensure_under_root(path: Path, root: Path, *, must_exist: bool = True) -> Path:
    resolved_root = root.resolve()
    resolved_path = path.resolve(strict=must_exist)
    if resolved_root == resolved_path or resolved_root in resolved_path.parents:
        return resolved_path
    raise ValueError(f"Path is outside allowed root: {path}")


def sanitize_spreadsheet_text(value: str) -> str:
    if value and value[0] in SPREADSHEET_FORMULA_PREFIXES:
        return "'" + value
    return value


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def parse_sha256_file(content: str, expected_filename: Optional[str] = None) -> str:
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        digest = parts[0].lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            continue
        if expected_filename and len(parts) > 1:
            file_token = parts[-1].lstrip("*")
            if file_token and file_token != expected_filename:
                continue
        return digest
    raise ValueError("Unable to parse SHA256 checksum payload.")
