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
    VagrantEnvironment,
    Post,
    Backdoor,
    BrowserAuxiliary,
    Plugin,
    ModuleArgumentParser,
    BrowserExploit,
    Workflow,
    Scanner,
    Shortcut,
    Analysis,
    fail)

from core.framework.encoder import Encoder
from core.framework.transform import Transform, Obfuscator

from core.framework.exploit_base import ExploitBase
from core.framework.option.option_payload import OptPayload

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
    Type,
    PayloadType
)

# Import remote connection function
from core.lib import remote

from core.framework.failure import fail, Fail, FailureType, ProcedureError, ErrorDescription

# Make everything available for "from kittysploit import *"
__all__ = [
    # Module types
    'Auxiliary',
    'Exploit', 
    'ExploitBase',
    'BrowserAuxiliary',
    'Payload',  
    'Listener',
    'DockerEnvironment',
    'VagrantEnvironment',
    'Post',
    'Backdoor',
    'Encoder',
    'Transform',
    'Obfuscator',
    'BaseModule',
    'Framework',
    'Plugin',
    'ModuleArgumentParser',
    'BrowserExploit',
    'Workflow',
    'Scanner',
    'Shortcut',
    'Analysis',
    'fail',
    'Fail',
    'ProcedureError',
    'FailureType',
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
    'OptPayload',
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
    'PayloadType',
    # Connection functions
    'remote'
]
