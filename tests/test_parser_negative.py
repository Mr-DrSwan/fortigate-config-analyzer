"""Negative and edge-case tests for FortigateConfigParser."""

from pathlib import Path
import sys
from typing import Callable

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fortigate_analyzer import FortigateConfigParser


# ---------------------------------------------------------------------------
# File-level error handling
# ---------------------------------------------------------------------------

def test_parser_raises_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        FortigateConfigParser(str(tmp_path / "does_not_exist.conf"))


def test_parser_raises_on_directory_as_path(tmp_path: Path) -> None:
    with pytest.raises((IsADirectoryError, OSError)):
        FortigateConfigParser(str(tmp_path))


# ---------------------------------------------------------------------------
# Empty / minimal configs
# ---------------------------------------------------------------------------

def test_empty_config_produces_empty_dataframes(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("")
    parser.parse_all()
    for sheet in ("Локальные_пользователи", "Firewall_правила", "Адреса", "Группы_адресов"):
        assert sheet in parser.dataframes
        assert parser.dataframes[sheet].empty or len(parser.dataframes[sheet]) == 0


def test_whitespace_only_config_does_not_crash(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("   \n  \n  ")
    parser.parse_all()
    assert "Firewall_правила" in parser.dataframes


def test_config_without_relevant_sections_yields_empty_sheets(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config system global
    set hostname "FGT01"
end
""")
    parser.parse_firewall_rules()
    parser.parse_addresses()
    assert parser.dataframes["Firewall_правила"].empty or len(parser.dataframes["Firewall_правила"]) == 0
    assert len(parser.dataframes["Адреса"]) == 0


# ---------------------------------------------------------------------------
# Malformed structures
# ---------------------------------------------------------------------------

def test_unclosed_config_block_does_not_crash(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config firewall policy
    edit 1
        set name "Broken"
""")
    parser.parse_firewall_rules()
    assert "Firewall_правила" in parser.dataframes


def test_edit_without_next_still_returns_block(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config firewall address
    edit "ORPHAN"
        set subnet 10.0.0.1 255.255.255.255
end
""")
    parser.parse_addresses()
    addr_df = parser.dataframes["Адреса"]
    assert len(addr_df) == 1
    assert addr_df.iloc[0]["name"] == "ORPHAN"


def test_nested_config_blocks_are_skipped_without_crash(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config firewall policy
    edit 1
        set name "Outer"
        config srcaddr
            set member "all"
        end
    next
end
""")
    parser.parse_firewall_rules()
    df = parser.dataframes["Firewall_правила"]
    assert len(df) == 1
    assert df.iloc[0]["Имя_правила"] == "Outer"


# ---------------------------------------------------------------------------
# Value parsing edge cases
# ---------------------------------------------------------------------------

def test_set_value_without_quotes_is_parsed(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config firewall policy
    edit 1
        set policyid 1
        set action accept
    next
end
""")
    parser.parse_firewall_rules()
    row = parser.dataframes["Firewall_правила"].iloc[0]
    assert row["Действие"] == "Разрешить"


def test_set_value_with_multiple_quoted_tokens(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config firewall address
    edit "ADDR_A"
        set subnet 10.0.0.1 255.255.255.255
    next
end
config firewall addrgrp
    edit "GRP_ALL"
        set member "ADDR_A" "ADDR_B" "ADDR_C"
    next
end
""")
    parser.parse_addresses()
    grp_row = parser.dataframes["Группы_адресов"].iloc[0]
    assert "ADDR_A" in grp_row["member"]
    assert "ADDR_B" in grp_row["member"]
    assert "ADDR_C" in grp_row["member"]


def test_duplicate_policy_id_both_appear_in_output(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config firewall policy
    edit 1
        set policyid 1
        set name "First"
    next
    edit 2
        set policyid 2
        set name "Second"
    next
end
""")
    parser.parse_firewall_rules()
    df = parser.dataframes["Firewall_правила"]
    assert len(df) == 2
    names = list(df["Имя_правила"])
    assert "First" in names
    assert "Second" in names


# ---------------------------------------------------------------------------
# find_duplicate_addresses edge cases
# ---------------------------------------------------------------------------

def test_find_duplicates_empty_config(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("")
    result = parser.find_duplicate_addresses()
    assert result["total_entries"] == 0
    assert result["same_value_different_names"] == []


def test_find_duplicates_detects_same_value_different_names(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config firewall address
    edit "ADDR_A"
        set subnet 10.0.0.1 255.255.255.255
    next
    edit "ADDR_B"
        set subnet 10.0.0.1 255.255.255.255
    next
end
""")
    result = parser.find_duplicate_addresses()
    assert result["total_entries"] == 2
    assert len(result["same_value_different_names"]) == 1
    dup = result["same_value_different_names"][0]
    assert set(dup["names"]) == {"ADDR_A", "ADDR_B"}
