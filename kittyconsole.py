#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Add project root to path for imports (before importing venv_helper)
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure we're using the project's venv if it exists
from core.utils.venv_helper import ensure_venv
ensure_venv(__file__)

from core.entry_console import main

if __name__ == "__main__":
    main()