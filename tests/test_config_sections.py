from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config_sections import replace_or_append_config_section


def test_replace_existing_section_body() -> None:
    source = """config firewall address
    edit "A"
        set subnet 10.0.0.1 255.255.255.255
    next
end
config firewall addrgrp
    edit "G"
    next
end
"""
    updated = replace_or_append_config_section(
        source,
        "firewall address",
        "\n".join(
            [
                "config firewall address",
                '    edit "B"',
                "        set fqdn example.com",
                "    next",
                "end",
            ]
        ),
    )
    assert 'edit "B"' in updated
    assert 'edit "A"' not in updated
    assert "config firewall addrgrp" in updated


def test_append_missing_section() -> None:
    source = """config firewall service custom
    edit "HTTPS"
    next
end
"""
    updated = replace_or_append_config_section(
        source,
        "firewall addrgrp",
        "\n".join(["config firewall addrgrp", '    edit "GRP1"', "    next", "end"]),
    )
    assert "config firewall service custom" in updated
    assert "config firewall addrgrp" in updated
    assert 'edit "GRP1"' in updated
