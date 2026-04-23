import ipaddress
import re
from typing import Dict, Optional, Tuple


def extract_first_ipv4(value: str) -> Optional[int]:
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", value)
    if not match:
        return None
    try:
        return int(ipaddress.ip_address(match.group(0)))
    except ValueError:
        return None


def subnet_to_display(subnet: str) -> str:
    parts = subnet.split()
    if len(parts) != 2:
        return subnet
    try:
        network = ipaddress.IPv4Network((parts[0], parts[1]), strict=False)
    except ValueError:
        return subnet
    return f"{parts[0]}/{network.prefixlen}"


def normalize_subnet_value(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        raise ValueError("Subnet не может быть пустым.")
    if "/" in value:
        iface = ipaddress.ip_interface(value)
        return f"{iface.ip} {iface.network.netmask}"
    parts = value.split()
    if len(parts) != 2:
        raise ValueError("Subnet должен быть в формате 10.0.0.0/24 или 10.0.0.0 255.255.255.0.")
    ipaddress.ip_address(parts[0])
    ipaddress.ip_address(parts[1])
    return f"{parts[0]} {parts[1]}"


def normalize_iprange_value(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        raise ValueError("IP range не может быть пустым.")
    if "-" in value:
        parts = [part.strip() for part in value.split("-", maxsplit=1)]
    else:
        parts = value.split()
    if len(parts) != 2:
        raise ValueError("IP range должен быть в формате 10.0.0.1-10.0.0.254.")
    ipaddress.ip_address(parts[0])
    ipaddress.ip_address(parts[1])
    return f"{parts[0]} {parts[1]}"


def get_address_display_value(address_objects: Dict[str, Dict[str, str]], address_name: str) -> str:
    obj = address_objects.get(address_name, {})
    fqdn_value = obj.get("fqdn", "").strip()
    if fqdn_value:
        return fqdn_value
    iprange_value = obj.get("iprange", "").strip()
    if iprange_value:
        parts = iprange_value.split()
        if len(parts) >= 2:
            return f"{parts[0]} - {parts[1]}"
        return iprange_value
    subnet_value = obj.get("subnet", "").strip()
    if subnet_value:
        return subnet_to_display(subnet_value)
    return obj.get("type", "").strip()


def address_sort_key(address_objects: Dict[str, Dict[str, str]], address_name: str) -> Tuple[int, object, str]:
    display = get_address_display_value(address_objects, address_name)
    numeric_ip = extract_first_ipv4(display)
    if numeric_ip is not None:
        return (0, numeric_ip, address_name.lower())
    if display:
        return (1, display.lower(), address_name.lower())
    return (2, address_name.lower(), address_name.lower())


def address_sort_mode_key(
    address_objects: Dict[str, Dict[str, str]],
    address_name: str,
    sort_mode: str,
) -> Tuple[int, object, str]:
    if sort_mode.startswith("name_"):
        return (0, address_name.lower(), address_name.lower())
    return address_sort_key(address_objects, address_name)
