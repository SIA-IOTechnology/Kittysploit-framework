#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run KittyRelay from a git checkout without pip install."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lib.relay.kittyrelay import main

if __name__ == "__main__":
    raise SystemExit(main())
