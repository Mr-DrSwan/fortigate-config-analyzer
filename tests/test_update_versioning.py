from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import is_newer_version, parse_version


def test_parse_version_handles_prefix_and_short_versions() -> None:
    assert parse_version("v1.2.3") == (1, 2, 3)
    assert parse_version("2.5") == (2, 5, 0)
    assert parse_version("3") == (3, 0, 0)


def test_is_newer_version_compares_semver_order() -> None:
    assert is_newer_version("1.0.1", "1.0.0")
    assert is_newer_version("1.2.0", "1.1.9")
    assert not is_newer_version("1.0.0", "1.0.0")
    assert not is_newer_version("0.9.9", "1.0.0")
