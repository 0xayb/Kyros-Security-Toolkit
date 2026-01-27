"""
Input validation utilities for network parameters.
"""

import re
import ipaddress
from typing import Tuple, Optional


def validate_ip_address(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validate an IPv4 or IPv6 address.

    Args:
        ip_str: IP address string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        ipaddress.ip_address(ip_str)
        return True, None
    except ValueError:
        return False, f"Invalid IP address: {ip_str}"


def validate_network(network_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a network in CIDR notation.

    Args:
        network_str: Network string (e.g., "192.168.1.0/24")

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        ipaddress.ip_network(network_str, strict=False)
        return True, None
    except ValueError:
        return False, f"Invalid network notation: {network_str}"


def validate_port(port_input: str) -> Tuple[bool, Optional[str]]:
    """
    Validate port number or range.

    Args:
        port_input: Port string (e.g., "80", "1-1024")

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check for port range
    if '-' in port_input:
        try:
            start, end = port_input.split('-')
            start_port = int(start.strip())
            end_port = int(end.strip())

            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                return False, "Port numbers must be between 1 and 65535"

            if start_port > end_port:
                return False, "Start port must be less than end port"

            return True, None
        except ValueError:
            return False, f"Invalid port range: {port_input}"

    # Check for comma-separated ports
    if ',' in port_input:
        ports = port_input.split(',')
        for port in ports:
            valid, msg = validate_port(port.strip())
            if not valid:
                return False, msg
        return True, None

    # Single port
    try:
        port_num = int(port_input)
        if 1 <= port_num <= 65535:
            return True, None
        return False, "Port must be between 1 and 65535"
    except ValueError:
        return False, f"Invalid port number: {port_input}"


def validate_mac_address(mac_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validate MAC address format.

    Args:
        mac_str: MAC address string

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Match XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'

    if re.match(pattern, mac_str):
        return True, None
    return False, f"Invalid MAC address format: {mac_str}"


def validate_protocol(protocol: str) -> Tuple[bool, Optional[str]]:
    """
    Validate network protocol name.

    Args:
        protocol: Protocol name (tcp, udp, icmp, etc.)

    Returns:
        Tuple of (is_valid, error_message)
    """
    valid_protocols = ['tcp', 'udp', 'icmp', 'all']

    if protocol.lower() in valid_protocols:
        return True, None
    return False, f"Invalid protocol. Must be one of: {', '.join(valid_protocols)}"


def validate_interface_name(interface: str) -> Tuple[bool, Optional[str]]:
    """
    Validate network interface name.

    Args:
        interface: Interface name (e.g., eth0, wlan0)

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Basic validation - alphanumeric with possible hyphens
    pattern = r'^[a-zA-Z][a-zA-Z0-9\-]*$'

    if re.match(pattern, interface):
        return True, None
    return False, f"Invalid interface name: {interface}"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing dangerous characters.

    Args:
        filename: Input filename

    Returns:
        Sanitized filename
    """
    # Remove path traversal attempts
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')

    # Remove or replace special characters
    filename = re.sub(r'[^\w\-.]', '_', filename)

    # Limit length
    if len(filename) > 200:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:195] + ('.' + ext if ext else '')

    return filename
