#/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KittySploit Environment Setup
"""

import os
import sys
from pathlib import Path

def setup_environment():
    """Setup KittySploit environment"""
    print("Setting up KittySploit environment...")
    # Add current directory to Python path
    current_dir = Path(__file__).parent.absolute()
    if str(current_dir) not in sys.path:
        sys.path.insert(0, str(current_dir))
    from core.version import VERSION
    # Set environment variables
    os.environ['KITTYSPLOIT_HOME'] = str(current_dir)
    os.environ['KITTYSPLOIT_VERSION'] = VERSION
    print(f"KittySploit home: {current_dir}")
    print("Environment setup complete")

if __name__ == "__main__":
    setup_environment()
