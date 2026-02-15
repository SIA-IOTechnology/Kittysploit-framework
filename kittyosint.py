#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

# Add parent directory to PYTHONPATH before importing venv helper.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure we're using the project's venv if it exists.
from core.utils.venv_helper import ensure_venv
ensure_venv(__file__)

if __name__ == "__main__":
    from interfaces.kittyosint import main
    main()
