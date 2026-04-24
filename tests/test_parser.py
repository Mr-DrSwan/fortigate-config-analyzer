from pathlib import Path
import sys
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fortigate_analyzer import FortigateConfigParser


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_extract_blocks_reads_edit_sections(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config user local
    edit "alice"
        set type password
        set email "alice@example.com"
    next
end
""")
    users = parser._extract_blocks("user local")
    assert len(users) == 1
    assert users[0]["_name"] == "alice"
    assert users[0]["type"] == "password"
    assert users[0]["email"] == "alice@example.com"


def test_parse_firewall_rules_builds_translated_columns(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
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
""")
    parser.parse_firewall_rules()
    df = parser.dataframes["Firewall_правила"]
    assert len(df) == 1
    row = df.iloc[0]
    assert row["ID"] == "1"
    assert row["Имя_правила"] == "Allow HTTPS"
    assert row["NAT"] == "Включен"
    assert row["Статус"] == "Включено"


def test_parse_addresses_splits_tabs_and_sets_member_of(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
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
""")
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


def test_transfer_plan_excludes_duplicates_and_keeps_group_full(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
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
""")
    parser.parse_addresses()
    existing = parser.parse_existing_object_names("""
config firewall address
    edit "ADDR_API"
    next
end
""")
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


def test_render_config_lines_public_api(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config firewall address
    edit "ADDR_ONE"
        set subnet 10.0.0.1 255.255.255.255
    next
end
config firewall addrgrp
    edit "GRP_ONE"
        set member "ADDR_ONE"
    next
end
""")
    parser.parse_addresses()
    addr_lines = parser.render_address_config_lines()
    grp_lines = parser.render_addrgrp_config_lines()
    assert addr_lines[0] == "config firewall address"
    assert grp_lines[0] == "config firewall addrgrp"
    assert any('edit "ADDR_ONE"' in line for line in addr_lines)
    assert any('edit "GRP_ONE"' in line for line in grp_lines)


def test_transfer_plan_recolors_existing_when_target_color_differs(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config firewall address
    edit "ADDR_WEB"
        set subnet 10.0.0.10 255.255.255.255
        set color 5
    next
end
""")
    parser.parse_addresses()
    target_cli = """
config firewall address
    edit "ADDR_WEB"
        set subnet 10.0.0.10 255.255.255.255
        set color 2
    next
end
"""
    existing_index = parser.parse_existing_object_index(target_cli)
    existing_names = parser.parse_existing_object_names(target_cli)
    plan = parser.build_transfer_plan(
        selected_addresses={"ADDR_WEB"},
        selected_groups=set(),
        existing_names=existing_names,
        existing_index=existing_index,
        address_color_overrides={"ADDR_WEB": 5},
    )
    assert plan["duplicate_addresses"] == ["ADDR_WEB"]
    assert plan["addresses_to_create"] == []
    assert plan["existing_addresses_to_recolor"] == ["ADDR_WEB"]
    assert "set color 5" in plan["commands_text"]


def test_transfer_plan_inherits_group_color_through_nested_groups(make_parser: Callable[[str], FortigateConfigParser]) -> None:
    parser = make_parser("""
config firewall address
    edit "ADDR_LEAF"
        set subnet 10.10.10.10 255.255.255.255
    next
end
config firewall addrgrp
    edit "GRP_ROOT"
        set member "GRP_CHILD"
        set color 11
    next
    edit "GRP_CHILD"
        set member "ADDR_LEAF"
    next
end
""")
    parser.parse_addresses()
    plan = parser.build_transfer_plan(
        selected_addresses=set(),
        selected_groups={"GRP_ROOT"},
        existing_names=set(),
    )
    assert "edit \"ADDR_LEAF\"" in plan["commands_text"]
    assert "set color 11" in plan["commands_text"]
