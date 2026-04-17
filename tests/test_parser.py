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
