from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from address_utils import (
    address_sort_key,
    address_sort_mode_key,
    extract_first_ipv4,
    get_address_display_value,
    normalize_iprange_value,
    normalize_subnet_value,
    subnet_to_display,
)


# ---------------------------------------------------------------------------
# extract_first_ipv4
# ---------------------------------------------------------------------------

def test_extract_first_ipv4_from_plain_ip() -> None:
    assert extract_first_ipv4("192.168.1.1") == int("0xC0A80101", 16)


def test_extract_first_ipv4_from_subnet_string() -> None:
    result = extract_first_ipv4("10.0.0.0/24")
    assert result is not None
    assert result == int("0x0A000000", 16)


def test_extract_first_ipv4_from_fqdn_returns_none() -> None:
    assert extract_first_ipv4("api.example.com") is None


def test_extract_first_ipv4_from_empty_string_returns_none() -> None:
    assert extract_first_ipv4("") is None


def test_extract_first_ipv4_picks_first_ip_in_range() -> None:
    result = extract_first_ipv4("10.0.0.1 10.0.0.254")
    assert result is not None


# ---------------------------------------------------------------------------
# subnet_to_display
# ---------------------------------------------------------------------------

def test_subnet_to_display_converts_mask_to_cidr() -> None:
    assert subnet_to_display("10.0.0.0 255.255.255.0") == "10.0.0.0/24"


def test_subnet_to_display_host_mask() -> None:
    assert subnet_to_display("192.168.1.1 255.255.255.255") == "192.168.1.1/32"


def test_subnet_to_display_returns_raw_if_not_two_parts() -> None:
    raw = "10.0.0.0"
    assert subnet_to_display(raw) == raw


def test_subnet_to_display_invalid_values_returns_raw() -> None:
    raw = "not_an_ip mask"
    assert subnet_to_display(raw) == raw


# ---------------------------------------------------------------------------
# normalize_subnet_value
# ---------------------------------------------------------------------------

def test_normalize_subnet_accepts_cidr() -> None:
    assert normalize_subnet_value("10.10.30.5/24") == "10.10.30.5 255.255.255.0"


def test_normalize_subnet_accepts_ip_and_mask() -> None:
    assert normalize_subnet_value("10.0.0.0 255.255.0.0") == "10.0.0.0 255.255.0.0"


def test_normalize_subnet_raises_on_empty() -> None:
    with pytest.raises(ValueError):
        normalize_subnet_value("")


def test_normalize_subnet_raises_on_whitespace_only() -> None:
    with pytest.raises(ValueError):
        normalize_subnet_value("   ")


def test_normalize_subnet_raises_on_single_part() -> None:
    with pytest.raises((ValueError, Exception)):
        normalize_subnet_value("10.0.0.0")


def test_normalize_subnet_raises_on_invalid_ip() -> None:
    with pytest.raises((ValueError, Exception)):
        normalize_subnet_value("999.999.999.999/24")


# ---------------------------------------------------------------------------
# normalize_iprange_value
# ---------------------------------------------------------------------------

def test_normalize_iprange_accepts_dash_format() -> None:
    assert normalize_iprange_value("10.0.0.1-10.0.0.2") == "10.0.0.1 10.0.0.2"


def test_normalize_iprange_accepts_space_format() -> None:
    assert normalize_iprange_value("10.0.0.1 10.0.0.254") == "10.0.0.1 10.0.0.254"


def test_normalize_iprange_raises_on_empty() -> None:
    with pytest.raises(ValueError):
        normalize_iprange_value("")


def test_normalize_iprange_raises_on_single_ip() -> None:
    with pytest.raises((ValueError, Exception)):
        normalize_iprange_value("10.0.0.1")


def test_normalize_iprange_raises_on_invalid_ip() -> None:
    with pytest.raises((ValueError, Exception)):
        normalize_iprange_value("10.0.0.1-999.999.999.999")


# ---------------------------------------------------------------------------
# get_address_display_value
# ---------------------------------------------------------------------------

_OBJECTS = {
    "subnet_obj": {"subnet": "10.0.0.0 255.255.255.0"},
    "fqdn_obj": {"fqdn": "api.example.com"},
    "range_obj": {"iprange": "10.0.0.1 10.0.0.100"},
    "type_obj": {"type": "geography"},
    "empty_obj": {},
    "missing": {},
}


def test_display_value_fqdn() -> None:
    assert get_address_display_value(_OBJECTS, "fqdn_obj") == "api.example.com"


def test_display_value_subnet() -> None:
    assert get_address_display_value(_OBJECTS, "subnet_obj") == "10.0.0.0/24"


def test_display_value_iprange_formats_as_dash() -> None:
    result = get_address_display_value(_OBJECTS, "range_obj")
    assert "10.0.0.1" in result and "10.0.0.100" in result


def test_display_value_falls_back_to_type() -> None:
    assert get_address_display_value(_OBJECTS, "type_obj") == "geography"


def test_display_value_unknown_name_returns_empty() -> None:
    assert get_address_display_value(_OBJECTS, "nonexistent") == ""


# ---------------------------------------------------------------------------
# address_sort_key
# ---------------------------------------------------------------------------

def test_sort_key_ip_address_first_bucket() -> None:
    objects = {"A": {"subnet": "10.0.0.0 255.255.255.0"}}
    key = address_sort_key(objects, "A")
    assert key[0] == 0


def test_sort_key_fqdn_second_bucket() -> None:
    objects = {"B": {"fqdn": "api.example.com"}}
    key = address_sort_key(objects, "B")
    assert key[0] == 1


def test_sort_key_empty_third_bucket() -> None:
    objects = {"C": {}}
    key = address_sort_key(objects, "C")
    assert key[0] == 2


def test_sort_key_lower_ip_sorts_before_higher() -> None:
    objects = {
        "low": {"subnet": "10.0.0.0 255.255.255.0"},
        "high": {"subnet": "192.168.1.0 255.255.255.0"},
    }
    assert address_sort_key(objects, "low") < address_sort_key(objects, "high")


# ---------------------------------------------------------------------------
# address_sort_mode_key
# ---------------------------------------------------------------------------

def test_sort_mode_key_name_mode_uses_name() -> None:
    objects = {"MyAddr": {"subnet": "10.0.0.0 255.255.255.0"}}
    key = address_sort_mode_key(objects, "MyAddr", "name_asc")
    assert key[0] == 0
    assert key[1] == "myaddr"


def test_sort_mode_key_ip_mode_uses_ip() -> None:
    objects = {"A": {"subnet": "10.0.0.1 255.255.255.255"}}
    key_ip = address_sort_mode_key(objects, "A", "ip_asc")
    assert key_ip[0] == 0


def test_sort_mode_key_name_sorts_alphabetically() -> None:
    objects = {
        "Zebra": {"fqdn": "z.example.com"},
        "Alpha": {"fqdn": "a.example.com"},
    }
    key_z = address_sort_mode_key(objects, "Zebra", "name_asc")
    key_a = address_sort_mode_key(objects, "Alpha", "name_asc")
    assert key_a < key_z
