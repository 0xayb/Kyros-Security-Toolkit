# Configuration management

import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class Config:

    DEFAULT_CONFIG = {
        'app': {
            'name': 'Kyros',
            'version': '1.0.0',
            'author': 'Ayoub Serarfi'
        },
        'paths': {
            'data_dir': 'data',
            'logs_dir': 'data/logs',
            'reports_dir': 'data/reports'
        },
        'ids': {
            'syn_flood_threshold': 100,
            'udp_flood_threshold': 1000,
            'icmp_flood_threshold': 100,
            'port_scan_threshold': 20,
            'alert_cooldown': 5,
            'max_packets_buffer': 1000,
            'dns_cache_ttl': 300
        },
        'firewall': {
            'iptables_path': '/usr/sbin/iptables',
            'confirm_dangerous_ops': True
        },
        'display': {
            'max_table_rows': 30,
            'refresh_rate': 1
        }
    }

    def __init__(self, config_file: Optional[Path] = None):
        self._config = self.DEFAULT_CONFIG.copy()

        if config_file and config_file.exists():
            self._load_from_file(config_file)

    def _load_from_file(self, config_file: Path):
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    self._deep_update(self._config, user_config)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")

    def _deep_update(self, base: Dict, update: Dict) -> Dict:
        """Deep update nested dictionary."""
        for key, value in update.items():
            if isinstance(value, dict) and key in base:
                self._deep_update(base[key], value)
            else:
                base[key] = value
        return base

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            key_path: Configuration key path (e.g., 'ids.syn_flood_threshold')
            default: Default value if key not found

        Returns:
            Configuration value
        """
        keys = key_path.split('.')
        value = self._config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def set(self, key_path: str, value: Any):
        """
        Set configuration value using dot notation.

        Args:
            key_path: Configuration key path
            value: Value to set
        """
        keys = key_path.split('.')
        config = self._config

        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]

        config[keys[-1]] = value

    def save(self, config_file: Path):
        """
        Save configuration to YAML file.

        Args:
            config_file: Path to save configuration
        """
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w') as f:
            yaml.dump(self._config, f, default_flow_style=False)

    @property
    def all(self) -> Dict:
        """Get entire configuration dictionary."""
        return self._config.copy()


# Global config instance
_config_instance = None


def get_config() -> Config:
    """Get global configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance
