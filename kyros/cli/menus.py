# Interactive menu system

import os
from pathlib import Path
from colorama import Fore, Style, init

from ..core.utils import clear_screen, get_network_interfaces
from ..core.validators import sanitize_filename
from ..ids import IDSMonitor
from ..analyzer import LogParser, ReportGenerator
from ..firewall import FirewallManager

init(autoreset=True)


class MenuSystem:
    """Interactive menu system."""

    def __init__(self):
        """Initialize menu system."""
        self.running = True

    def display_banner(self):
        """Display application banner."""
        banner = f"""{Fore.CYAN}{Style.BRIGHT}
╭───────────────────────────────────────────────────────────────────╮
│                                                                   │
│   ░██     ░██ ░██     ░██ ░█████████    ░██████     ░██████       │
│   ░██    ░██   ░██   ░██  ░██     ░██  ░██   ░██   ░██   ░██      │
│   ░██   ░██     ░██ ░██   ░██     ░██ ░██     ░██ ░██             │
│   ░███████       ░████    ░█████████  ░██     ░██  ░████████      │
│   ░██   ░██       ░██     ░██   ░██   ░██     ░██         ░██     │
│   ░██    ░██      ░██     ░██    ░██   ░██   ░██   ░██   ░██      │
│   ░██     ░██     ░██     ░██     ░██   ░██████     ░██████       │
│                                                                   │
│               Professional Security Toolkit v1.0                  │
│                    Created by Ayoub Serarfi                       │
╰───────────────────────────────────────────────────────────────────╯
{Style.RESET_ALL}"""
        print(banner)

    def main_menu(self):
        """Display and handle main menu."""
        while self.running:
            clear_screen()
            self.display_banner()

            print(f"\n{Fore.YELLOW}[1]{Style.RESET_ALL} Intrusion Detection System")
            print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} Log Analyzer")
            print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} Firewall Manager")
            print(f"{Fore.YELLOW}[0]{Style.RESET_ALL} Exit")

            choice = input(f"\n{Fore.CYAN}Select an option: {Style.RESET_ALL}").strip()

            if choice == '1':
                self.ids_menu()
            elif choice == '2':
                self.analyzer_menu()
            elif choice == '3':
                self.firewall_menu()
            elif choice == '0':
                self.running = False
                print(f"\n{Fore.GREEN}Thank you for using Kyros!{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
                input("Press Enter to continue...")

    def ids_menu(self):
        """IDS submenu."""
        print(f"\n{Fore.CYAN}=== Intrusion Detection System ==={Style.RESET_ALL}\n")

        # Get available interfaces
        interfaces = get_network_interfaces()
        print("Available interfaces:")
        for idx, iface in enumerate(interfaces, 1):
            print(f"  [{idx}] {iface}")

        iface_choice = input(f"\n{Fore.CYAN}Select interface number: {Style.RESET_ALL}").strip()

        try:
            iface_idx = int(iface_choice) - 1
            if 0 <= iface_idx < len(interfaces):
                interface = interfaces[iface_idx]
            else:
                print(f"{Fore.RED}Invalid selection!{Style.RESET_ALL}")
                input("Press Enter to continue...")
                return
        except ValueError:
            print(f"{Fore.RED}Invalid input!{Style.RESET_ALL}")
            input("Press Enter to continue...")
            return

        save_choice = input(f"{Fore.CYAN}Save PCAP file? (y/n): {Style.RESET_ALL}").strip().lower()
        save_pcap = save_choice == 'y'

        print(f"\n{Fore.GREEN}Starting IDS monitor on {interface}...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Press Ctrl+C to stop monitoring{Style.RESET_ALL}\n")

        try:
            monitor = IDSMonitor(interface)
            monitor.start(save_pcap=save_pcap)
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

        input("\nPress Enter to continue...")

    def analyzer_menu(self):
        """Log analyzer submenu."""
        log_dir = Path('data/logs')

        while True:
            clear_screen()
            print(f"\n{Fore.CYAN}=== Log Analyzer ==={Style.RESET_ALL}\n")

            # List available log files
            if log_dir.exists():
                log_files = list(log_dir.glob('*.log'))
                if log_files:
                    print("Available log files:")
                    for idx, log_file in enumerate(log_files, 1):
                        print(f"  [{idx}] {log_file.name}")
                else:
                    print(f"{Fore.YELLOW}No log files found{Style.RESET_ALL}")
                    input("Press Enter to continue...")
                    return
            else:
                print(f"{Fore.YELLOW}No log directory found{Style.RESET_ALL}")
                input("Press Enter to continue...")
                return

            print(f"\n{Fore.YELLOW}[0]{Style.RESET_ALL} Back to Main Menu")

            choice = input(f"\n{Fore.CYAN}Select log file: {Style.RESET_ALL}").strip()

            if choice == '0':
                break

            try:
                log_idx = int(choice) - 1
                if 0 <= log_idx < len(log_files):
                    log_file = log_files[log_idx]
                    self.analyze_log_file(log_file)
                else:
                    print(f"{Fore.RED}Invalid selection!{Style.RESET_ALL}")
                    input("Press Enter to continue...")
            except ValueError:
                print(f"{Fore.RED}Invalid input!{Style.RESET_ALL}")
                input("Press Enter to continue...")

    def analyze_log_file(self, log_file: Path):
        """Analyze a specific log file."""
        clear_screen()
        print(f"\n{Fore.CYAN}=== Analyzing: {log_file.name} ==={Style.RESET_ALL}\n")

        parser = LogParser()
        reporter = ReportGenerator()

        print(f"{Fore.YELLOW}Parsing log file...{Style.RESET_ALL}")
        parsed_data = parser.parse_file(log_file)

        print(f"{Fore.YELLOW}Finding anomalies...{Style.RESET_ALL}")
        anomalies = parser.find_anomalies(log_file)

        reporter.print_summary(parsed_data)

        # Ask to save report
        save_choice = input(f"\n{Fore.CYAN}Save detailed report? (y/n): {Style.RESET_ALL}").strip().lower()
        if save_choice == 'y':
            report_file = Path('data/reports') / f"{log_file.stem}_report.txt"
            reporter.generate_text_report(parsed_data, anomalies, report_file)
            print(f"{Fore.GREEN}Report saved to: {report_file}{Style.RESET_ALL}")

        input("\nPress Enter to continue...")

    def firewall_menu(self):
        """Firewall manager submenu."""
        try:
            fw = FirewallManager()
        except PermissionError:
            print(f"{Fore.RED}Firewall manager requires root privileges!{Style.RESET_ALL}")
            input("Press Enter to continue...")
            return

        while True:
            clear_screen()
            print(f"\n{Fore.CYAN}=== Firewall Manager ==={Style.RESET_ALL}\n")

            print(f"{Fore.YELLOW}[1]{Style.RESET_ALL} Block IP Address")
            print(f"{Fore.YELLOW}[2]{Style.RESET_ALL} Unblock IP Address")
            print(f"{Fore.YELLOW}[3]{Style.RESET_ALL} Block Port")
            print(f"{Fore.YELLOW}[4]{Style.RESET_ALL} Unblock Port")
            print(f"{Fore.YELLOW}[5]{Style.RESET_ALL} List Rules")
            print(f"{Fore.YELLOW}[6]{Style.RESET_ALL} Save Rules")
            print(f"{Fore.YELLOW}[0]{Style.RESET_ALL} Back to Main Menu")

            choice = input(f"\n{Fore.CYAN}Select option: {Style.RESET_ALL}").strip()

            if choice == '0':
                break
            elif choice == '1':
                ip = input(f"{Fore.CYAN}Enter IP to block: {Style.RESET_ALL}").strip()
                if fw.block_ip(ip):
                    print(f"{Fore.GREEN}IP blocked successfully!{Style.RESET_ALL}")
                input("Press Enter to continue...")
            elif choice == '2':
                ip = input(f"{Fore.CYAN}Enter IP to unblock: {Style.RESET_ALL}").strip()
                if fw.unblock_ip(ip):
                    print(f"{Fore.GREEN}IP unblocked successfully!{Style.RESET_ALL}")
                input("Press Enter to continue...")
            elif choice == '3':
                port = input(f"{Fore.CYAN}Enter port to block: {Style.RESET_ALL}").strip()
                proto = input(f"{Fore.CYAN}Protocol (tcp/udp) [tcp]: {Style.RESET_ALL}").strip() or 'tcp'
                if fw.block_port(port, proto):
                    print(f"{Fore.GREEN}Port blocked successfully!{Style.RESET_ALL}")
                input("Press Enter to continue...")
            elif choice == '4':
                port = input(f"{Fore.CYAN}Enter port to unblock: {Style.RESET_ALL}").strip()
                proto = input(f"{Fore.CYAN}Protocol (tcp/udp) [tcp]: {Style.RESET_ALL}").strip() or 'tcp'
                if fw.unblock_port(port, proto):
                    print(f"{Fore.GREEN}Port unblocked successfully!{Style.RESET_ALL}")
                input("Press Enter to continue...")
            elif choice == '5':
                rules = fw.list_rules()
                print(f"\n{Fore.YELLOW}Current Rules:{Style.RESET_ALL}")
                for rule in rules:
                    print(rule)
                input("\nPress Enter to continue...")
            elif choice == '6':
                if fw.save_rules():
                    print(f"{Fore.GREEN}Rules saved successfully!{Style.RESET_ALL}")
                input("Press Enter to continue...")
