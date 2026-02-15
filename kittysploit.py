# -*- coding: utf-8 -*-

"""
KittySploit - Core Exports
This file exposes the main classes and functions for modules to import easily.
Example: from kittysploit import *
"""

import sys
import os

# Add core to path if not already there
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Import key components
from core.framework.module import Auxiliary, Exploit, Payload, Post
from core.framework.option import OptString, OptInteger, OptBool, OptPort, OptIP
from core.output_handler import print_info, print_success, print_error, print_warning, print_status, print_table

# Export all
__all__ = [
    'Auxiliary', 'Exploit', 'Payload', 'Post',
    'OptString', 'OptInteger', 'OptBool', 'OptPort', 'OptIP',
    'print_info', 'print_success', 'print_error', 'print_warning', 'print_status', 'print_table'
]
