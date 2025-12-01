#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os


def pythonize_path(path):
    """
    Convert a module path (e.g., "payloads/stagers/linux/x64/reverse_tcp") 
    to a Python import path (e.g., "payloads.stagers.linux.x64.reverse_tcp").
    
    Args:
        path: Module path with slashes or backslashes
        
    Returns:
        str: Python import path with dots
    """
    if not path:
        return ""
    
    # Normalize path separators
    normalized = path.replace("\\", "/")
    
    # Remove leading/trailing slashes
    normalized = normalized.strip("/")
    
    # Convert slashes to dots for Python import
    python_path = normalized.replace("/", ".")
    
    # Remove any leading dots
    if python_path.startswith("."):
        python_path = python_path[1:]
    
    return python_path

