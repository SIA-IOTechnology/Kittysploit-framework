#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KittySploit Framework - Main module exports
"""

import os
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add the project root to Python path for imports
current_dir = Path(__file__).parent.parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

# Import all module types
from core.framework import (
    Auxiliary,
    Exploit,
    Payload,
    Listener,
    DockerEnvironment,
    Post,
    Backdoor,
    BrowserAuxiliary,
    Plugin,
    ModuleArgumentParser,
    BrowserExploit,
    Workflow,
    Scanner,
    Shortcut,
    fail)

from core.framework.encoder import Encoder

# Import all option types
from core.framework.option import (
    OptString,
    OptInteger,
    OptPort,
    OptBool,
    OptIP,
    OptChoice,
    OptFile,
    OptFloat
)

# Import base module class
from core.framework.base_module import BaseModule

# Import framework class
from core.framework.framework import Framework

# Import utility classes
from core.output_handler import (
    print_info,
    print_empty,
    print_success,
    print_error,
    print_warning,
    print_debug,
    print_status,
    print_table,
    color_green,
    color_red,
    color_yellow,
    color_blue
)

# Import enums
from core.framework.enums import (
    Handler,
    SessionType,
    Protocol,
    Arch,
    Platform,
    ServiceType,
    PayloadCategory,
    Browser,
    Type
)

# Import remote connection function
from core.lib import remote

from core.framework.failure import fail, Fail, ProcedureError, ErrorDescription

# Make everything available for "from kittysploit import *"
__all__ = [
    # Module types
    'Auxiliary',
    'Exploit', 
    'BrowserAuxiliary',
    'Payload',  
    'Listener',
    'DockerEnvironment',
    'Post',
    'Backdoor',
    'Encoder',
    'BaseModule',
    'Framework',
    'Plugin',
    'ModuleArgumentParser',
    'BrowserExploit',
    'Workflow',
    'Scanner',
    'Shortcut',
    'fail',
    'Fail',
    'ProcedureError',
    'ErrorDescription',
    # Option types
    'OptString',
    'OptInteger',
    'OptPort',
    'OptBool',
    'OptIP',
    'OptChoice',
    'OptFile',
    'OptFloat',
    # Output functions
    'print_info',
    'print_empty',
    'print_success',
    'print_error',
    'print_warning',
    'print_debug',
    'print_status',
    'print_table',
    'color_green',
    'color_red',
    'color_yellow',
    'color_blue',
    # Enums
    'Handler',
    'SessionType',
    'Protocol',
    'Arch',
    'Platform',
    'ServiceType',
    'PayloadCategory',
    'Browser',
    'Type',
    
    # Connection functions
    'remote'
]
