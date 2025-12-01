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
Commande ECHO disabled.
    # Add current directory to Python path
    current_dir = Path(__file__).parent.absolute()
    if str(current_dir) not in sys.path:
        sys.path.insert(0, str(current_dir))
Commande ECHO disabled.
    # Set environment variables
    os.environ['KITTYSPLOIT_HOME'] = str(current_dir)
    os.environ['KITTYSPLOIT_VERSION'] = '1.0.0'
Commande ECHO disabled.
    print(f"KittySploit home: {current_dir}")
    print("Environment setup complete!")

if __name__ == "__main__":
    setup_environment()
