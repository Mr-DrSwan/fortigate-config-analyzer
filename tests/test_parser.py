from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fortigate_analyzer import FortigateConfigParser


def _make_parser(tmp_path: Path, content: str) -> FortigateConfigParser:
    cfg = tmp_path / "sample.conf"
    cfg.write_text(content, encoding="utf-8")
    return FortigateConfigParser(str(cfg))


def test_extract_blocks_reads_edit_sections(tmp_path: Path) -> None:
    parser = _make_parser(
        tmp_path,
        """
config user local
    edit "alice"
        set type password
        set email "alice@example.com"
    next
end
""",
    )
    users = parser._extract_blocks("user local")
    assert len(users) == 1
    assert users[0]["_name"] == "alice"
    assert users[0]["type"] == "password"
    assert users[0]["email"] == "alice@example.com"


def test_parse_firewall_rules_builds_translated_columns(tmp_path: Path) -> None:
    parser = _make_parser(
        tmp_path,
        """
config firewall policy
    edit 1
        set policyid 1
        set name "Allow HTTPS"
        set action accept
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set nat enable
        set status enable
    next
end
""",
    )
    parser.parse_firewall_rules()
    df = parser.dataframes["Firewall_правила"]
    assert len(df) == 1
    row = df.iloc[0]
    assert row["ID"] == "1"
    assert row["Имя_правила"] == "Allow HTTPS"
    assert row["NAT"] == "Включен"
    assert row["Статус"] == "Включено"


def test_parse_addresses_splits_tabs_and_sets_member_of(tmp_path: Path) -> None:
    parser = _make_parser(
        tmp_path,
        """
config firewall address
    edit "ADDR_WEB"
        set subnet 10.0.0.10 255.255.255.255
    next
    edit "ADDR_API"
        set fqdn "api.example.com"
    next
end
config firewall addrgrp
    edit "GRP_PROD"
        set member "ADDR_WEB" "ADDR_API"
    next
end
""",
    )
    parser.parse_addresses()

    assert "Адреса" in parser.dataframes
    assert "Группы_адресов" in parser.dataframes

    addr_df = parser.dataframes["Адреса"]
    group_df = parser.dataframes["Группы_адресов"]

    assert len(addr_df) == 2
    assert len(group_df) == 1

    web_row = addr_df[addr_df["name"] == "ADDR_WEB"].iloc[0]
    api_row = addr_df[addr_df["name"] == "ADDR_API"].iloc[0]
    group_row = group_df.iloc[0]

    assert web_row["member-of"] == "GRP_PROD"
    assert api_row["member-of"] == "GRP_PROD"
    assert group_row["name"] == "GRP_PROD"
    assert group_row["member"] == "ADDR_WEB ADDR_API"


def test_transfer_plan_excludes_duplicates_and_keeps_group_full(tmp_path: Path) -> None:
    parser = _make_parser(
        tmp_path,
        """
config firewall address
    edit "ADDR_WEB"
        set subnet 10.0.0.10 255.255.255.255
    next
    edit "ADDR_API"
        set fqdn "api.example.com"
    next
end
config firewall addrgrp
    edit "GRP_PROD"
        set member "ADDR_WEB" "ADDR_API"
        set comment "production"
    next
end
""",
    )
    parser.parse_addresses()
    existing = parser.parse_existing_object_names(
        """
config firewall address
    edit "ADDR_API"
    next
end
"""
    )
    plan = parser.build_transfer_plan(
        selected_addresses=set(),
        selected_groups={"GRP_PROD"},
        existing_names=existing,
        group_color_overrides={"GRP_PROD": 6},
    )
    assert plan["duplicate_addresses"] == ["ADDR_API"]
    assert plan["duplicate_groups"] == []
    assert "edit \"ADDR_WEB\"" in plan["commands_text"]
    assert "edit \"ADDR_API\"" not in plan["commands_text"]
    assert "edit \"GRP_PROD\"" in plan["commands_text"]
    assert "set color 6" in plan["commands_text"]
    assert "set member \"ADDR_WEB\" \"ADDR_API\"" in plan["commands_text"]
