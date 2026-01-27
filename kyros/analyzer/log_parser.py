# Log parsing and analysis

import re
from pathlib import Path
from typing import Dict, List, Optional
from collections import Counter
from datetime import datetime

from ..core.logger import setup_logger


class LogParser:

    # Regex patterns
    IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    TIMESTAMP_PATTERN = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')

    # Attack keywords to search for
    ATTACK_KEYWORDS = {
        'ARP_Spoof': ['arp spoof', 'arp spoofing'],
        'DNS_Spoof': ['dns spoof', 'dns spoofing'],
        'SYN_Flood': ['syn flood'],
        'UDP_Flood': ['udp flood'],
        'ICMP_Flood': ['icmp flood'],
        'Port_Scan': ['port scan'],
        'Deauth': ['deauth'],
        'BeaconFlood': ['beacon flood', 'fake ap'],
        'WPA_Handshake': ['wpa handshake']
    }

    def __init__(self):
        self.logger = setup_logger('analyzer')

    def parse_file(self, log_file: Path) -> Dict:
        # Parse log file and get stats
        if not log_file.exists():
            self.logger.error(f"Log file not found: {log_file}")
            return {}

        result = {
            'file': str(log_file),
            'total_lines': 0,
            'protocols': Counter(),
            'attack_types': Counter(),
            'ips': Counter(),
            'timestamps': [],
            'sample_lines': []
        }

        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    result['total_lines'] += 1

                    # Extract timestamps
                    ts_match = self.TIMESTAMP_PATTERN.search(line)
                    if ts_match:
                        try:
                            dt = datetime.strptime(ts_match.group(1), '%Y-%m-%d %H:%M:%S')
                            result['timestamps'].append(dt)
                        except:
                            pass

                    # Extract IPs
                    ips = self.IP_PATTERN.findall(line)
                    for ip in ips:
                        result['ips'][ip] += 1

                    # Detect protocols
                    line_lower = line.lower()
                    for proto in ['tcp', 'udp', 'arp', 'dns', 'icmp']:
                        if proto in line_lower:
                            result['protocols'][proto.upper()] += 1

                    # Detect attacks
                    for attack_type, keywords in self.ATTACK_KEYWORDS.items():
                        for keyword in keywords:
                            if keyword in line_lower:
                                result['attack_types'][attack_type] += 1
                                break

                    # Keep sample lines
                    if len(result['sample_lines']) < 20:
                        result['sample_lines'].append((line_num, line))

        except Exception as e:
            self.logger.error(f"Error parsing log file: {e}")
            return {}

        # Calculate time range
        if result['timestamps']:
            result['first_timestamp'] = min(result['timestamps'])
            result['last_timestamp'] = max(result['timestamps'])
            result['duration'] = result['last_timestamp'] - result['first_timestamp']

        return result

    def search_logs(self, log_file: Path, keyword: str, max_results: int = 100) -> List[tuple]:
        """
        Search log file for keyword.

        Args:
            log_file: Path to log file
            keyword: Search keyword
            max_results: Maximum number of results

        Returns:
            List of (line_number, line_text) tuples
        """
        results = []
        keyword_lower = keyword.lower()

        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if keyword_lower in line.lower():
                        results.append((line_num, line.strip()))
                        if len(results) >= max_results:
                            break
        except Exception as e:
            self.logger.error(f"Error searching log file: {e}")

        return results

    def find_anomalies(self, log_file: Path) -> Dict:
        """
        Detect anomalies and suspicious patterns in logs.

        Args:
            log_file: Path to log file

        Returns:
            Dict with anomaly information
        """
        anomalies = {
            'attack_lines': [],
            'attack_counts': Counter(),
            'suspicious_ips': Counter()
        }

        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line_lower = line.lower()

                    # Check for attack keywords
                    detected_attacks = []
                    for attack_type, keywords in self.ATTACK_KEYWORDS.items():
                        for keyword in keywords:
                            if keyword in line_lower:
                                detected_attacks.append(attack_type)
                                anomalies['attack_counts'][attack_type] += 1
                                break

                    if detected_attacks:
                        anomalies['attack_lines'].append((line_num, line.strip(), detected_attacks))

                        # Extract IPs from attack lines
                        ips = self.IP_PATTERN.findall(line)
                        for ip in ips:
                            anomalies['suspicious_ips'][ip] += 1

        except Exception as e:
            self.logger.error(f"Error finding anomalies: {e}")

        return anomalies
