#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shell framework for KittySploit
Provides modular shell implementations for different session types
"""

from .base_shell import BaseShell
from .shell_manager import ShellManager
from .classic_shell import ClassicShell
from .javascript_shell import JavaScriptShell
from .ssh_shell import SSHShell

__all__ = [
    'BaseShell',
    'ShellManager', 
    'ClassicShell',
    'JavaScriptShell',
    'SSHShell'
]
