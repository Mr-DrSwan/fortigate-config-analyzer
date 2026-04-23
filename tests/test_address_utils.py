from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from address_utils import (
    address_sort_key,
    get_address_display_value,
    normalize_iprange_value,
    normalize_subnet_value,
)


def test_normalize_subnet_accepts_cidr() -> None:
    assert normalize_subnet_value("10.10.30.5/24") == "10.10.30.5 255.255.255.0"


def test_normalize_iprange_accepts_dash_format() -> None:
    assert normalize_iprange_value("10.0.0.1-10.0.0.2") == "10.0.0.1 10.0.0.2"


def test_address_display_and_sort_key() -> None:
    objects = {
        "A": {"subnet": "10.0.0.0 255.255.255.0"},
        "B": {"fqdn": "api.example.com"},
    }
    assert get_address_display_value(objects, "A") == "10.0.0.0/24"
    assert get_address_display_value(objects, "B") == "api.example.com"
    assert address_sort_key(objects, "A")[0] == 0
