"""
Main entry point for Kyros CLI application.
"""

import sys
import os

from ..core.utils import check_root
from ..core.logger import setup_logger
from .menus import MenuSystem


def main():
    """Main application entry point."""
    logger = setup_logger('kyros')

    # Check if running as root
    if os.geteuid() != 0:
        print("Warning: Many features require root privileges.")
        print("Please run with: sudo kyros")
        response = input("\nContinue anyway? (y/n): ").strip().lower()
        if response != 'y':
            sys.exit(0)

    try:
        menu = MenuSystem()
        menu.main_menu()
    except KeyboardInterrupt:
        print("\n\nExiting Kyros...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
