# Report generation from log analysis

from pathlib import Path
from typing import Dict
from datetime import datetime
from colorama import Fore, Style

from ..core.logger import setup_logger


class ReportGenerator:

    def __init__(self):
        self.logger = setup_logger('reporter')

    def generate_text_report(self, parsed_data: Dict, anomalies: Dict, output_file: Path):
        # Generate text report from parsed logs
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("Kyros Log Analysis Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 70 + "\n\n")

                # File information
                f.write(f"Log File: {parsed_data.get('file', 'Unknown')}\n")
                f.write(f"Total Lines: {parsed_data.get('total_lines', 0)}\n\n")

                # Time range
                if 'first_timestamp' in parsed_data:
                    f.write(f"Time Range: {parsed_data['first_timestamp']} to {parsed_data['last_timestamp']}\n")
                    f.write(f"Duration: {parsed_data.get('duration', 'Unknown')}\n\n")

                # Protocol statistics
                f.write("=" * 70 + "\n")
                f.write("Protocol Statistics\n")
                f.write("=" * 70 + "\n")
                protocols = parsed_data.get('protocols', {})
                if protocols:
                    for proto, count in protocols.most_common():
                        f.write(f"  {proto}: {count}\n")
                else:
                    f.write("  No protocol data found\n")
                f.write("\n")

                # Attack statistics
                f.write("=" * 70 + "\n")
                f.write("Detected Attacks\n")
                f.write("=" * 70 + "\n")
                attack_types = parsed_data.get('attack_types', {})
                if attack_types:
                    for attack, count in attack_types.most_common():
                        f.write(f"  {attack}: {count} occurrences\n")
                else:
                    f.write("  No attacks detected\n")
                f.write("\n")

                # Top IPs
                f.write("=" * 70 + "\n")
                f.write("Top IP Addresses\n")
                f.write("=" * 70 + "\n")
                ips = parsed_data.get('ips', {})
                if ips:
                    for ip, count in ips.most_common(20):
                        f.write(f"  {ip}: {count} occurrences\n")
                else:
                    f.write("  No IPs found\n")
                f.write("\n")

                # Suspicious IPs
                suspicious = anomalies.get('suspicious_ips', {})
                if suspicious:
                    f.write("=" * 70 + "\n")
                    f.write("Suspicious IP Addresses (found in attack logs)\n")
                    f.write("=" * 70 + "\n")
                    for ip, count in suspicious.most_common(20):
                        f.write(f"  {ip}: {count} attack-related occurrences\n")
                    f.write("\n")

                # Sample attack lines
                attack_lines = anomalies.get('attack_lines', [])
                if attack_lines:
                    f.write("=" * 70 + "\n")
                    f.write("Sample Attack Log Entries (first 30)\n")
                    f.write("=" * 70 + "\n")
                    for line_num, text, attacks in attack_lines[:30]:
                        f.write(f"[Line {line_num}] {attacks}\n")
                        f.write(f"  {text}\n\n")

            self.logger.info(f"Report saved to: {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return False

    def print_summary(self, parsed_data: Dict):
        """
        Print a summary of parsed data to console.

        Args:
            parsed_data: Data from LogParser.parse_file()
        """
        print("\n" + f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Log Analysis Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total Lines:{Style.RESET_ALL} {Fore.WHITE}{parsed_data.get('total_lines', 0)}{Style.RESET_ALL}")

        if 'first_timestamp' in parsed_data:
            print(f"{Fore.YELLOW}Time Range:{Style.RESET_ALL} {Fore.WHITE}{parsed_data['first_timestamp']} to {parsed_data['last_timestamp']}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Protocols:{Style.RESET_ALL}")
        for proto, count in parsed_data.get('protocols', {}).most_common():
            print(f"  {Fore.GREEN}{proto}:{Style.RESET_ALL} {Fore.WHITE}{count}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Attacks Detected:{Style.RESET_ALL}")
        attacks = parsed_data.get('attack_types', {})
        if attacks:
            for attack, count in attacks.most_common():
                print(f"  {Fore.RED}{attack}:{Style.RESET_ALL} {Fore.WHITE}{count}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}No attacks detected{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Top IPs:{Style.RESET_ALL}")
        for ip, count in parsed_data.get('ips', {}).most_common(10):
            print(f"  {Fore.CYAN}{ip}:{Style.RESET_ALL} {Fore.WHITE}{count}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")
