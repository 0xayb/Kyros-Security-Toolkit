# IDS packet capture and threat detection

import os
import time
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import Optional, List
from collections import defaultdict

from scapy.all import AsyncSniffer, wrpcap, conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich import box

from ..core.logger import setup_logger
from ..core.utils import get_wireless_interfaces
from .detectors import (
    ARPSpoofDetector, DNSSpoofDetector, FloodDetector,
    PortScanDetector, WirelessAttackDetector
)


class IDSMonitor:

    def __init__(self, interface: str, output_dir: Path = Path('data/logs')):
        self.interface = interface
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Create log file with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = self.output_dir / f'ids_monitor_{timestamp}.log'
        self.logger = setup_logger('ids', log_file=str(self.log_file))

        # State
        self.running = False
        self.sniffer = None
        self.packets = []
        self.alerts = []
        self.lock = threading.Lock()

        # Stats
        self.stats = defaultdict(int)

        # Output queues
        self.write_queue = queue.Queue()
        self.pcap_queue = queue.Queue()

        # Attack detectors
        self.arp_detector = ARPSpoofDetector()
        self.dns_detector = DNSSpoofDetector()
        self.flood_detector = FloodDetector()
        self.portscan_detector = PortScanDetector()
        self.wireless_detector = WirelessAttackDetector()

        # Console output
        self.console = Console()

        # Configure scapy to be quiet
        conf.verb = 0
        conf.use_pcap = True

    def _is_wireless(self) -> bool:
        wireless = get_wireless_interfaces()
        return self.interface in wireless

    def _packet_handler(self, packet):
        """Handle captured packets."""
        if not packet:
            return

        try:
            # Update statistics
            with self.lock:
                self.stats['total'] += 1

                if packet.haslayer(TCP):
                    self.stats['tcp'] += 1
                elif packet.haslayer(UDP):
                    self.stats['udp'] += 1
                elif packet.haslayer(ARP):
                    self.stats['arp'] += 1

            # Run detectors
            detectors = [
                self.arp_detector,
                self.dns_detector,
                self.flood_detector,
                self.portscan_detector
            ]

            if self._is_wireless():
                detectors.append(self.wireless_detector)

            for detector in detectors:
                alert = detector.analyze(packet)
                if alert:
                    with self.lock:
                        self.alerts.append({
                            'time': datetime.now(),
                            'message': alert
                        })
                    # Log the alert to file
                    self.logger.warning(f"ALERT: {alert}")

            # Store packet info
            packet_info = self._extract_packet_info(packet)
            with self.lock:
                self.packets.append(packet_info)
                if len(self.packets) > 1000:  # Keep last 1000
                    self.packets.pop(0)

        except Exception as e:
            self.logger.debug(f"Error processing packet: {e}")

    def _extract_packet_info(self, packet) -> dict:
        # Extract packet info for display
        info = {
            'time': datetime.now().strftime('%H:%M:%S'),
            'proto': 'OTHER',
            'src': 'N/A',
            'dst': 'N/A',
            'sport': '-',
            'dport': '-',
            'info': ''
        }

        if packet.haslayer(Ether):
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst

        if packet.haslayer(IP):
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst

            if packet.haslayer(TCP):
                info['proto'] = 'TCP'
                info['sport'] = str(packet[TCP].sport)
                info['dport'] = str(packet[TCP].dport)
            elif packet.haslayer(UDP):
                info['proto'] = 'UDP'
                info['sport'] = str(packet[UDP].sport)
                info['dport'] = str(packet[UDP].dport)

        elif packet.haslayer(ARP):
            info['proto'] = 'ARP'
            info['src'] = packet[ARP].psrc
            info['dst'] = packet[ARP].pdst

        if packet.haslayer(DNS):
            info['proto'] = 'DNS'

        return info

    def _render_table(self) -> Table:
        # Build the live traffic table
        stats_text = f"TCP: {self.stats['tcp']} | UDP: {self.stats['udp']} | ARP: {self.stats['arp']} | Total: {self.stats['total']}"

        table = Table(
            title=f"Live Network Traffic [{stats_text}]",
            expand=True,
            box=box.SQUARE,
            border_style="cyan"
        )

        table.add_column("Time", style="cyan", no_wrap=True)
        table.add_column("Proto", style="green")
        table.add_column("Src IP", style="yellow")
        table.add_column("Dst IP", style="yellow")
        table.add_column("Src Port", style="magenta")
        table.add_column("Dst Port", style="magenta")

        with self.lock:
            recent = self.packets[-30:]  # Last 30 packets
            for pkt in recent:
                table.add_row(
                    pkt['time'],
                    pkt['proto'],
                    pkt['src'],
                    pkt['dst'],
                    pkt['sport'],
                    pkt['dport']
                )

        return table

    def start(self, duration: Optional[int] = None, save_pcap: bool = False):
        """
        Start monitoring traffic.

        Args:
            duration: Optional duration in seconds
            save_pcap: Whether to save PCAP file
        """
        self.logger.info(f"Starting IDS monitor on {self.interface}")
        self.logger.info(f"Logging to: {self.log_file}")

        if save_pcap:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            pcap_file = self.output_dir / f"capture_{timestamp}.pcap"
            pcap_packets = []

        self.running = True

        try:
            # Start sniffer
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._packet_handler,
                store=False
            )
            self.sniffer.start()

            # Live display
            start_time = time.time()
            with Live(self._render_table(), refresh_per_second=2, console=self.console) as live:
                while self.running:
                    live.update(self._render_table())

                    # Check duration
                    if duration and (time.time() - start_time) >= duration:
                        break

                    # Collect packets for PCAP
                    if save_pcap:
                        try:
                            while not self.pcap_queue.empty():
                                pcap_packets.append(self.pcap_queue.get_nowait())
                        except queue.Empty:
                            pass

                    time.sleep(0.5)

        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")

        finally:
            self.stop()

            # Save PCAP if requested
            if save_pcap and pcap_packets:
                wrpcap(str(pcap_file), pcap_packets)
                self.logger.info(f"PCAP saved to: {pcap_file}")

            # Print alert summary
            self._print_alert_summary()

            # Log session summary
            self.logger.info("=" * 50)
            self.logger.info("IDS Monitoring Session Summary")
            self.logger.info(f"Interface: {self.interface}")
            self.logger.info(f"Total packets captured: {len(self.packets)}")
            self.logger.info(f"Total alerts: {len(self.alerts)}")
            self.logger.info(f"Log file: {self.log_file}")
            self.logger.info("=" * 50)

    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.sniffer:
            self.sniffer.stop()

    def _print_alert_summary(self):
        """Print summary of detected alerts."""
        if not self.alerts:
            self.console.print("\n[green]No security alerts detected[/green]")
            return

        self.console.print(f"\n[red bold]Security Alerts Detected: {len(self.alerts)}[/red bold]\n")

        for alert in self.alerts[-20:]:  # Show last 20
            time_str = alert['time'].strftime('%H:%M:%S')
            self.console.print(f"[yellow]{time_str}[/yellow] - [red]{alert['message']}[/red]")

    def get_statistics(self) -> dict:
        """Get current statistics."""
        return dict(self.stats)
