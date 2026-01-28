# Allow running as python -m kyros

import sys
import os
from pathlib import Path

# Add parent directory to path to import from kyros.py
parent_dir = Path(__file__).parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

# Import and run main from kyros.py
from kyros import main

if __name__ == '__main__':
    main()
