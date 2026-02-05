#!/usr/bin/env python3
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
    # Add project root to Python path (install/ is one level below root)
    root_dir = Path(__file__).parent.parent.absolute()
    if str(root_dir) not in sys.path:
        sys.path.insert(0, str(root_dir))
    from core.version import VERSION
    # Set environment variables (KITTYSPLOIT_HOME = project root)
    os.environ['KITTYSPLOIT_HOME'] = str(root_dir)
    os.environ['KITTYSPLOIT_VERSION'] = VERSION
    print(f"KittySploit home: {root_dir}")
    print("Environment setup complete!")

if __name__ == "__main__":
    setup_environment()
