"""
General utility functions used across the application.
"""

import os
import sys
import subprocess
import psutil
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime


def check_root() -> bool:
    """Check if the program is running with root privileges."""
    return os.geteuid() == 0


def require_root():
    """Exit if not running as root."""
    if not check_root():
        print("Error: This operation requires root privileges.")
        print("Please run with sudo.")
        sys.exit(1)


def clear_screen():
    """Clear the terminal screen."""
    os.system('clear' if os.name != 'nt' else 'cls')


def check_command_exists(command: str) -> bool:
    """
    Check if a command exists in the system PATH.

    Args:
        command: Command name to check

    Returns:
        True if command exists, False otherwise
    """
    try:
        subprocess.run(
            ['which', command],
            capture_output=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def get_network_interfaces() -> List[str]:
    """
    Get list of available network interfaces.

    Returns:
        List of interface names
    """
    return list(psutil.net_if_addrs().keys())


def get_wireless_interfaces() -> List[str]:
    """
    Get list of wireless network interfaces.

    Returns:
        List of wireless interface names
    """
    wireless = []
    try:
        interfaces = os.listdir('/sys/class/net/')
        for iface in interfaces:
            # Check if wireless directory exists
            wireless_path = f'/sys/class/net/{iface}/wireless'
            if os.path.exists(wireless_path):
                wireless.append(iface)
            # Also check for common wireless naming patterns
            elif iface.startswith(('wlan', 'wlp', 'wlx')):
                wireless.append(iface)
    except OSError:
        pass

    return wireless


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Format a timestamp for display.

    Args:
        dt: datetime object, defaults to current time

    Returns:
        Formatted timestamp string
    """
    if dt is None:
        dt = datetime.now()
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def format_file_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Format a timestamp for use in filenames.

    Args:
        dt: datetime object, defaults to current time

    Returns:
        Formatted timestamp string safe for filenames
    """
    if dt is None:
        dt = datetime.now()
    return dt.strftime('%Y%m%d_%H%M%S')


def ensure_directory(path: Path) -> None:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path
    """
    path.mkdir(parents=True, exist_ok=True)


def get_file_size_mb(filepath: Path) -> float:
    """
    Get file size in megabytes.

    Args:
        filepath: Path to file

    Returns:
        File size in MB
    """
    if not filepath.exists():
        return 0.0
    return filepath.stat().st_size / (1024 * 1024)


def run_command(cmd: List[str], timeout: int = 300) -> Dict:
    """
    Run a system command and capture output.

    Args:
        cmd: Command and arguments as list
        timeout: Command timeout in seconds

    Returns:
        Dict with 'success', 'stdout', 'stderr', 'returncode'
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'stdout': '',
            'stderr': 'Command timed out',
            'returncode': -1
        }
    except Exception as e:
        return {
            'success': False,
            'stdout': '',
            'stderr': str(e),
            'returncode': -1
        }


def bytes_to_human_readable(num_bytes: int) -> str:
    """
    Convert bytes to human readable format.

    Args:
        num_bytes: Number of bytes

    Returns:
        Human readable string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"


def parse_ports(port_str: str) -> List[int]:
    """
    Parse port string into list of port numbers.

    Args:
        port_str: Port string (e.g., "80", "80,443", "1-100")

    Returns:
        List of port numbers
    """
    ports = []

    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports))
