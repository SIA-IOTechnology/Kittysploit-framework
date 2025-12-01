#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from core.output_handler import print_error

import os
import ctypes
import sys

def is_root():
    return os.geteuid() == 0

def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin() != 0

def check_privileges():
    if os.name == "nt":
        return is_admin()
    if not is_root():
        print_error("This program must be run with administrative privileges.")
        sys.exit(1)

    
    