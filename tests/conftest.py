"""Shared pytest fixtures for FortiGate Analyzer tests."""

from pathlib import Path
import sys
from typing import Callable

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fortigate_analyzer import FortigateConfigParser


# ---------------------------------------------------------------------------
# Reusable config text blocks
# ---------------------------------------------------------------------------

POLICY_CONFIG_BLOCK = """\
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
"""

ADDRESS_CONFIG_BLOCK = """\
config firewall address
    edit "ADDR_WEB"
        set subnet 10.0.0.10 255.255.255.255
    next
end
config firewall addrgrp
    edit "GRP_WEB"
        set member "ADDR_WEB"
    next
end
"""

FULL_SAMPLE_CONFIG = """\
config user local
    edit "alice"
        set type password
    next
end
config user group
    edit "vpn-users"
        set member "alice"
    next
end
config firewall policy
    edit 10
        set policyid 10
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
config vpn ipsec phase1-interface
    edit "HQ"
        set interface "wan1"
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 10.0.0.1
    next
end
config firewall vip
    edit "vip-web"
        set extip 1.1.1.1
        set mappedip 10.0.0.10
        set status enable
    next
end
config firewall address
    edit "ADDR_WEB"
        set subnet 10.0.0.10 255.255.255.255
    next
end
config firewall addrgrp
    edit "GRP_WEB"
        set member "ADDR_WEB"
    next
end
config user peer
    edit "peer1"
        set passwd "secret"
    next
end
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def make_parser(tmp_path: Path) -> Callable[[str], FortigateConfigParser]:
    """Return a factory that writes *content* to a temp .conf and returns a parser."""
    def _factory(content: str) -> FortigateConfigParser:
        cfg = tmp_path / "test.conf"
        cfg.write_text(content, encoding="utf-8")
        return FortigateConfigParser(str(cfg))
    return _factory


@pytest.fixture
def full_config_path(tmp_path: Path) -> Path:
    """Write FULL_SAMPLE_CONFIG to a temp file and return its path."""
    path = tmp_path / "full_sample.conf"
    path.write_text(FULL_SAMPLE_CONFIG, encoding="utf-8")
    return path


@pytest.fixture
def full_parser(full_config_path: Path) -> FortigateConfigParser:
    """Return a FortigateConfigParser loaded with FULL_SAMPLE_CONFIG."""
    return FortigateConfigParser(str(full_config_path))
