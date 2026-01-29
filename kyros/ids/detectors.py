# Attack detection for network threats

import time
from collections import defaultdict, Counter
from typing import Dict, Set, Optional, List
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Deauth, Dot11Elt
from scapy.layers.eap import EAPOL

from ..core.config import get_config


class AttackDetector:
    # Base detector class

    def __init__(self):
        self.config = get_config()
        self.alerts = []
        self.last_alert_time = defaultdict(float)

    def should_alert(self, alert_key: str) -> bool:
        # Check cooldown to avoid spam
        cooldown = self.config.get('ids.alert_cooldown', 5)
        current_time = time.time()

        if current_time - self.last_alert_time[alert_key] >= cooldown:
            self.last_alert_time[alert_key] = current_time
            return True
        return False

    def log_alert(self, attack_type: str, message: str):
        # Save alert if cooldown passed
        alert_key = f"{attack_type}:{message}"
        if self.should_alert(alert_key):
            self.alerts.append({
                'time': time.time(),
                'type': attack_type,
                'message': message
            })

    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        return self.alerts[-limit:]


class ARPSpoofDetector(AttackDetector):
    # Detects ARP spoofing

    def __init__(self):
        super().__init__()
        self.arp_table = {}  # Track IP -> MAC mappings

    def analyze(self, packet) -> Optional[str]:
        # Check for ARP spoofing attacks
        if not packet.haslayer(ARP) or packet[ARP].op != 2:
            return None

        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        if src_ip in self.arp_table:
            if self.arp_table[src_ip] != src_mac:
                msg = f"ARP Spoofing detected! IP {src_ip} changed MAC from {self.arp_table[src_ip]} to {src_mac}"
                self.log_alert('ARP_Spoof', msg)
                return msg
        else:
            self.arp_table[src_ip] = src_mac

        return None


class DNSSpoofDetector(AttackDetector):
    """Detects DNS spoofing attacks."""

    def __init__(self):
        super().__init__()
        self.dns_cache = {}  # domain -> {response: sources}
        self.cache_ttl = get_config().get('ids.dns_cache_ttl', 300)
        self.trusted_resolvers = self._load_system_resolvers()

    def _load_system_resolvers(self) -> Set[str]:
        # Get DNS servers from resolv.conf
        resolvers = set()
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        parts = line.split()
                        if len(parts) >= 2:
                            resolvers.add(parts[1])
        except Exception:
            pass
        return resolvers

    def analyze(self, packet) -> Optional[str]:
        # Check for DNS spoofing
        if not packet.haslayer(DNSRR):
            return None

        try:
            rr = packet[DNSRR]
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

            # Get query name
            if packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            else:
                qname = str(rr.rrname)

            rdata = str(rr.rdata) if hasattr(rr, 'rdata') else str(rr)

            # Check cache for conflicts
            if qname in self.dns_cache:
                cached = self.dns_cache[qname]

                # Check for conflicting responses
                if rdata not in cached:
                    # Trusted resolver vs untrusted source
                    if any(src in self.trusted_resolvers for src in cached.values()):
                        if src_ip not in self.trusted_resolvers:
                            msg = f"DNS Spoofing detected! Domain {qname} has conflicting responses"
                            self.log_alert('DNS_Spoof', msg)
                            return msg

            # Update cache
            self.dns_cache[qname] = {rdata: src_ip}

        except Exception:
            pass

        return None


class FloodDetector(AttackDetector):
    # Detects flood attacks (SYN, UDP, ICMP)

    def __init__(self, local_ip: str = None):
        super().__init__()
        self.syn_packets = defaultdict(list)
        self.udp_packets = defaultdict(list)
        self.icmp_packets = defaultdict(list)

        # Track last alert time to prevent spam
        self.last_alert = defaultdict(lambda: {'syn': 0, 'udp': 0, 'icmp': 0})
        self.alert_cooldown = 10  # seconds between alerts for same IP

        # Ignore floods from local IP (outbound traffic)
        self.local_ip = local_ip

        self.syn_threshold = get_config().get('ids.syn_flood_threshold', 100)
        self.udp_threshold = get_config().get('ids.udp_flood_threshold', 1000)
        self.icmp_threshold = get_config().get('ids.icmp_flood_threshold', 100)

    def _clean_old_packets(self, packet_dict: Dict, window: int = 5):
        # Remove old packets outside time window
        current_time = time.time()
        for src_ip in list(packet_dict.keys()):
            packet_dict[src_ip] = [
                t for t in packet_dict[src_ip]
                if current_time - t < window
            ]

    def analyze(self, packet) -> Optional[str]:
        current_time = time.time()

        # SYN Flood
        if packet.haslayer(TCP) and packet.haslayer(IP):
            if packet[TCP].flags & 0x02:  # SYN flag
                src_ip = packet[IP].src

                # Ignore outbound traffic from local machine
                if self.local_ip and src_ip == self.local_ip:
                    return None

                self.syn_packets[src_ip].append(current_time)
                self._clean_old_packets(self.syn_packets)

                if len(self.syn_packets[src_ip]) > self.syn_threshold:
                    # Check cooldown to prevent alert spam
                    if current_time - self.last_alert[src_ip]['syn'] > self.alert_cooldown:
                        self.last_alert[src_ip]['syn'] = current_time
                        msg = f"SYN Flood detected from {src_ip} ({len(self.syn_packets[src_ip])} packets)"
                        self.log_alert('SYN_Flood', msg)
                        return msg

        # UDP Flood
        if packet.haslayer(UDP) and packet.haslayer(IP):
            src_ip = packet[IP].src

            # Ignore outbound traffic from local machine
            if self.local_ip and src_ip == self.local_ip:
                return None

            self.udp_packets[src_ip].append(current_time)
            self._clean_old_packets(self.udp_packets, window=1)

            if len(self.udp_packets[src_ip]) > self.udp_threshold:
                # Check cooldown to prevent alert spam
                if current_time - self.last_alert[src_ip]['udp'] > self.alert_cooldown:
                    self.last_alert[src_ip]['udp'] = current_time
                    msg = f"UDP Flood detected from {src_ip} ({len(self.udp_packets[src_ip])} packets)"
                    self.log_alert('UDP_Flood', msg)
                    return msg

        # ICMP Flood
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            src_ip = packet[IP].src

            # Ignore outbound traffic from local machine
            if self.local_ip and src_ip == self.local_ip:
                return None

            self.icmp_packets[src_ip].append(current_time)
            self._clean_old_packets(self.icmp_packets, window=1)

            if len(self.icmp_packets[src_ip]) > self.icmp_threshold:
                # Check cooldown to prevent alert spam
                if current_time - self.last_alert[src_ip]['icmp'] > self.alert_cooldown:
                    self.last_alert[src_ip]['icmp'] = current_time
                    msg = f"ICMP Flood detected from {src_ip} ({len(self.icmp_packets[src_ip])} packets)"
                    self.log_alert('ICMP_Flood', msg)
                    return msg

        return None


class PortScanDetector(AttackDetector):
    # Detects port scanning

    def __init__(self):
        super().__init__()
        self.scan_attempts = defaultdict(lambda: {'ports': set(), 'start_time': time.time()})
        self.threshold = get_config().get('ids.port_scan_threshold', 20)

    def analyze(self, packet) -> Optional[str]:
        # Look for port scan patterns
        if not (packet.haslayer(TCP) and packet.haslayer(IP)):
            return None

        # Only SYN packets
        if not (packet[TCP].flags & 0x02):
            return None

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()

        self.scan_attempts[src_ip]['ports'].add(dst_port)

        time_window = current_time - self.scan_attempts[src_ip]['start_time']

        if len(self.scan_attempts[src_ip]['ports']) > self.threshold and time_window < 10:
            msg = f"Port Scan detected from {src_ip} ({len(self.scan_attempts[src_ip]['ports'])} ports)"
            self.log_alert('Port_Scan', msg)
            self.scan_attempts[src_ip] = {'ports': set(), 'start_time': current_time}
            return msg

        # Reset if window expired
        if time_window > 10:
            self.scan_attempts[src_ip] = {'ports': set(), 'start_time': current_time}

        return None


class WirelessAttackDetector(AttackDetector):
    """Detects wireless-specific attacks."""

    def __init__(self):
        super().__init__()
        self.beacon_cache = {}  # SSID -> BSSID
        self.probe_count = Counter()
        self.handshake_count = Counter()

    def detect_deauth(self, packet) -> Optional[str]:
        """Detect deauthentication attacks."""
        if packet.haslayer(Dot11Deauth):
            src = packet.addr2 or "unknown"
            dst = packet.addr1 or "broadcast"
            msg = f"Deauth attack detected! {src} -> {dst}"
            self.log_alert('Deauth', msg)
            return msg
        return None

    def detect_beacon_flood(self, packet) -> Optional[str]:
        """Detect beacon flooding / fake AP."""
        if not packet.haslayer(Dot11Beacon):
            return None

        ssid = self._extract_ssid(packet) or "<hidden>"
        bssid = (packet.addr2 or "").lower()

        if ssid in self.beacon_cache:
            if self.beacon_cache[ssid] != bssid:
                msg = f"Beacon Flood / Fake AP detected! SSID: {ssid}"
                self.log_alert('BeaconFlood', msg)
                return msg
        else:
            self.beacon_cache[ssid] = bssid

        return None

    def detect_probe_flood(self, packet) -> Optional[str]:
        """Detect probe request flooding."""
        if not packet.haslayer(Dot11ProbeReq):
            return None

        src = (packet.addr2 or "").lower()
        self.probe_count[src] += 1

        if self.probe_count[src] > 50:
            msg = f"Probe Request Flood from {src} (count={self.probe_count[src]})"
            self.log_alert('ProbeFlood', msg)
            return msg

        return None

    def detect_handshake(self, packet) -> Optional[str]:
        """Detect WPA handshake captures."""
        if packet.haslayer(EAPOL):
            src = (packet.addr2 or "").lower()
            self.handshake_count[src] += 1

            if self.handshake_count[src] >= 2:
                msg = f"WPA Handshake detected from {src}"
                self.log_alert('WPA_Handshake', msg)
                return msg

        return None

    def _extract_ssid(self, packet) -> Optional[str]:
        """Extract SSID from packet."""
        if packet.haslayer(Dot11Elt):
            elt = packet[Dot11Elt]
            while isinstance(elt, Dot11Elt):
                if elt.ID == 0 and elt.info:  # SSID element
                    try:
                        return elt.info.decode('utf-8', errors='ignore')
                    except:
                        pass
                elt = elt.payload
        return None

    def analyze(self, packet) -> Optional[str]:
        """Analyze packet for wireless attacks."""
        # Try all wireless detection methods
        for detect_method in [self.detect_deauth, self.detect_beacon_flood,
                              self.detect_probe_flood, self.detect_handshake]:
            result = detect_method(packet)
            if result:
                return result
        return None
