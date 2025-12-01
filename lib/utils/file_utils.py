#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File utility functions for KittySploit
Provides common file operations and utilities
"""

import os
from typing import List, Optional


def read_file_lines(file_path: str) -> List[str]:
    """
    Read a file and return its contents as a list of lines.
    
    Args:
        file_path: Path to the file to read
        
    Returns:
        List of lines from the file
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        IOError: If the file cannot be read
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.readlines()


def read_file(file_path: str) -> str:
    """
    Read a file and return its contents as a string.
    
    Args:
        file_path: Path to the file to read
        
    Returns:
        Contents of the file as a string
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        IOError: If the file cannot be read
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()


def file_exists(file_path: str) -> bool:
    """
    Check if a file exists.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if the file exists, False otherwise
    """
    return os.path.exists(file_path) and os.path.isfile(file_path)


def get_file_size(file_path: str) -> Optional[int]:
    """
    Get the size of a file in bytes.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Size of the file in bytes, or None if the file doesn't exist
    """
    if not file_exists(file_path):
        return None
    return os.path.getsize(file_path)

