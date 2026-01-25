#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    
    # Check if we are already running from the project's venv (even if not "activated")
    if hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix:
        # We are in some venv. Let's check if it's the project venv.
        if script_path is None:
            script_path = sys.argv[0]
        if not os.path.isabs(script_path):
            script_path = os.path.abspath(script_path)
        script_dir = Path(script_path).parent.absolute()
        venv_dir = script_dir / 'venv'
        if Path(sys.prefix).resolve() == venv_dir.resolve():
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
        try:
            venv_python = script_dir / 'venv' / 'bin' / 'python3'
        except:
            venv_python = script_dir / 'venv' / 'bin' / 'python'
    
    # Check if venv exists
    venv_dir = script_dir / 'venv'
    if not venv_python.exists():
        # No venv found, continue with current Python
        # This is normal if the user hasn't run the installer yet
        # Optionally, we could create it here, but it's better to use the installer
        return True
    
    # Venv exists, relaunch with venv Python
    try:
        # Use the script path - make sure it's absolute
        if not os.path.isabs(script_path):
            script_to_run = str(Path(script_path).absolute())
        else:
            script_to_run = script_path

        # Relaunch with venv Python, preserving all arguments
        args = [str(venv_python), script_to_run] + sys.argv[1:]
        # Use subprocess.call which will execute the script with venv Python
        # This ensures we're using the venv's Python and all its packages
        try:
            result = subprocess.call(args)
            sys.exit(result)
        except KeyboardInterrupt:
            # User stopped the child (e.g. Ctrl+C). Exit cleanly without traceback.
            sys.exit(0)
    except Exception as e:
        return True
