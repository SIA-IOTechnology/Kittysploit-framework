#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Virtual Environment Helper
Automatically detects and uses venv if it exists and we're not already in one.
This module should be imported at the very beginning of entry point scripts.
"""

import os
import sys
import subprocess
from pathlib import Path


def ensure_venv(script_path=None):
    """
    Ensure we're running in the project's virtual environment.
    
    If not already in a venv and a venv exists in the project root,
    this function will relaunch the script with the venv's Python interpreter.
    
    Args:
        script_path: Path to the script being executed. If None, uses sys.argv[0].
    
    Returns:
        None if relaunching, or True if already in venv or no venv exists.
    """
    # If already in a virtual environment, do nothing
    if os.environ.get('VIRTUAL_ENV'):
        return True
    
    # Determine script directory
    if script_path is None:
        # Use sys.argv[0] which contains the script path
        script_path = sys.argv[0]
    
    # Convert to absolute path
    if not os.path.isabs(script_path):
        script_path = os.path.abspath(script_path)
    
    script_dir = Path(script_path).parent.absolute()
    
    # Determine venv Python path based on platform
    if sys.platform == 'win32':
        venv_python = script_dir / 'venv' / 'Scripts' / 'python.exe'
    else:
        venv_python = script_dir / 'venv' / 'bin' / 'python'
    
    # Check if venv exists
    if not venv_python.exists():
        return True  # No venv, continue with current Python
    
    # Relaunch with venv Python
    try:
        # Use the script path
        script_to_run = str(Path(script_path).absolute())
        
        # Relaunch with venv Python, preserving all arguments
        args = [str(venv_python), script_to_run] + sys.argv[1:]
        sys.exit(subprocess.call(args))
    except Exception:
        # If relaunch fails, continue with current Python
        # This can happen if there are permission issues or other problems
        return True
