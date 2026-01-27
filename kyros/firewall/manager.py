# Firewall management with iptables

import subprocess
from typing import List, Dict, Optional

from ..core.logger import setup_logger
from ..core.utils import check_root, run_command
from ..core.validators import validate_ip_address, validate_port, validate_protocol


class FirewallManager:

    def __init__(self):
        self.logger = setup_logger('firewall')

        if not check_root():
            raise PermissionError("Firewall manager requires root privileges")

    def block_ip(self, ip_address: str) -> bool:
        # Block an IP address
        valid, msg = validate_ip_address(ip_address)
        if not valid:
            self.logger.error(msg)
            return False

        cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
        result = run_command(cmd)

        if result['success']:
            self.logger.info(f"Blocked IP: {ip_address}")
            return True
        else:
            self.logger.error(f"Failed to block IP: {result['stderr']}")
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        # Remove IP from block list
        valid, msg = validate_ip_address(ip_address)
        if not valid:
            self.logger.error(msg)
            return False

        cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
        result = run_command(cmd)

        if result['success']:
            self.logger.info(f"Unblocked IP: {ip_address}")
            return True
        else:
            self.logger.error(f"Failed to unblock IP: {result['stderr']}")
            return False

    def block_port(self, port: str, protocol: str = 'tcp') -> bool:
        """
        Block a port.

        Args:
            port: Port number
            protocol: Protocol (tcp/udp)

        Returns:
            True if successful, False otherwise
        """
        valid_port, msg_port = validate_port(port)
        valid_proto, msg_proto = validate_protocol(protocol)

        if not valid_port:
            self.logger.error(msg_port)
            return False
        if not valid_proto:
            self.logger.error(msg_proto)
            return False

        cmd = ['sudo', 'iptables', '-A', 'INPUT', '-p', protocol, '--dport', port, '-j', 'DROP']
        result = run_command(cmd)

        if result['success']:
            self.logger.info(f"Blocked port: {port}/{protocol.upper()}")
            return True
        else:
            self.logger.error(f"Failed to block port: {result['stderr']}")
            return False

    def unblock_port(self, port: str, protocol: str = 'tcp') -> bool:
        """Unblock a port."""
        valid_port, msg_port = validate_port(port)
        valid_proto, msg_proto = validate_protocol(protocol)

        if not valid_port:
            self.logger.error(msg_port)
            return False
        if not valid_proto:
            self.logger.error(msg_proto)
            return False

        cmd = ['sudo', 'iptables', '-D', 'INPUT', '-p', protocol, '--dport', port, '-j', 'DROP']
        result = run_command(cmd)

        if result['success']:
            self.logger.info(f"Unblocked port: {port}/{protocol.upper()}")
            return True
        else:
            self.logger.error(f"Failed to unblock port: {result['stderr']}")
            return False

    def block_protocol(self, protocol: str) -> bool:
        """Block an entire protocol."""
        valid, msg = validate_protocol(protocol)
        if not valid:
            self.logger.error(msg)
            return False

        cmd = ['sudo', 'iptables', '-A', 'INPUT', '-p', protocol, '-j', 'DROP']
        result = run_command(cmd)

        if result['success']:
            self.logger.info(f"Blocked protocol: {protocol.upper()}")
            return True
        else:
            self.logger.error(f"Failed to block protocol: {result['stderr']}")
            return False

    def unblock_protocol(self, protocol: str) -> bool:
        """Unblock a protocol."""
        valid, msg = validate_protocol(protocol)
        if not valid:
            self.logger.error(msg)
            return False

        cmd = ['sudo', 'iptables', '-D', 'INPUT', '-p', protocol, '-j', 'DROP']
        result = run_command(cmd)

        if result['success']:
            self.logger.info(f"Unblocked protocol: {protocol.upper()}")
            return True
        else:
            self.logger.error(f"Failed to unblock protocol: {result['stderr']}")
            return False

    def list_rules(self) -> List[str]:
        """List all current iptables rules."""
        cmd = ['sudo', 'iptables', '-L', 'INPUT', '-n', '-v']
        result = run_command(cmd)

        if result['success']:
            return result['stdout'].split('\n')
        else:
            self.logger.error("Failed to list rules")
            return []

    def save_rules(self) -> bool:
        """Save current iptables rules to persist across reboots."""
        cmd = ['sudo', 'iptables-save']
        result = run_command(cmd)

        if result['success']:
            try:
                with open('/etc/iptables/rules.v4', 'w') as f:
                    f.write(result['stdout'])
                self.logger.info("Rules saved successfully")
                return True
            except Exception as e:
                self.logger.error(f"Failed to save rules: {e}")
                return False
        else:
            self.logger.error("Failed to save rules")
            return False

    def flush_rules(self) -> bool:
        """Clear all iptables rules (use with caution)."""
        self.logger.warning("Flushing all iptables rules")
        cmd = ['sudo', 'iptables', '-F', 'INPUT']
        result = run_command(cmd)

        if result['success']:
            self.logger.info("All rules flushed")
            return True
        else:
            self.logger.error("Failed to flush rules")
            return False
