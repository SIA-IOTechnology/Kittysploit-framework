#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Syscall data access module
Provides easy access to syscall information for different architectures
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any

class SyscallDatabase:
    """Database for syscall information"""
    
    def __init__(self, data_dir: Optional[str] = None):
        """
        Initialize the syscall database
        
        Args:
            data_dir: Directory containing syscall data (default: current directory)
        """
        if data_dir is None:
            data_dir = Path(__file__).parent
        else:
            data_dir = Path(data_dir)
        
        self.data_dir = data_dir
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._load_all()
    
    def _load_all(self):
        """Load all syscall data files"""
        json_file = self.data_dir / 'syscalls.json'
        if json_file.exists():
            with open(json_file, 'r', encoding='utf-8') as f:
                self._cache = json.load(f)
        else:
            # Load individual files
            for arch in ['x86_64', 'x86', 'arm64', 'arm32']:
                arch_file = self.data_dir / f'{arch}.json'
                if arch_file.exists():
                    with open(arch_file, 'r', encoding='utf-8') as f:
                        self._cache[arch] = json.load(f)
    
    def get_architectures(self) -> List[str]:
        """Get list of available architectures"""
        return list(self._cache.keys())
    
    def get_syscalls(self, architecture: str) -> List[Dict[str, Any]]:
        """
        Get all syscalls for an architecture
        
        Args:
            architecture: Architecture name (x86_64, x86, arm64, arm32)
            
        Returns:
            List of syscall dictionaries
        """
        if architecture not in self._cache:
            return []
        
        arch_data = self._cache[architecture]
        if isinstance(arch_data, dict) and 'syscalls' in arch_data:
            return arch_data['syscalls']
        return []
    
    def get_syscall_by_number(self, architecture: str, number: int) -> Optional[Dict[str, Any]]:
        """
        Get a syscall by its number
        
        Args:
            architecture: Architecture name
            number: Syscall number
            
        Returns:
            Syscall dictionary or None if not found
        """
        syscalls = self.get_syscalls(architecture)
        for syscall in syscalls:
            if syscall.get('number') == number:
                return syscall
        return None
    
    def get_syscall_by_name(self, architecture: str, name: str) -> Optional[Dict[str, Any]]:
        """
        Get a syscall by its name
        
        Args:
            architecture: Architecture name
            name: Syscall name
            
        Returns:
            Syscall dictionary or None if not found
        """
        syscalls = self.get_syscalls(architecture)
        for syscall in syscalls:
            if syscall.get('name') == name or syscall.get('name', '').endswith('_' + name):
                return syscall
        return None
    
    def search_syscalls(self, architecture: str, query: str) -> List[Dict[str, Any]]:
        """
        Search syscalls by name
        
        Args:
            architecture: Architecture name
            query: Search query
            
        Returns:
            List of matching syscalls
        """
        syscalls = self.get_syscalls(architecture)
        query_lower = query.lower()
        results = []
        for syscall in syscalls:
            name = syscall.get('name', '').lower()
            if query_lower in name:
                results.append(syscall)
        return results
    
    def get_syscall_count(self, architecture: str) -> int:
        """
        Get the number of syscalls for an architecture
        
        Args:
            architecture: Architecture name
            
        Returns:
            Number of syscalls
        """
        return len(self.get_syscalls(architecture))
    
    def get_architecture_info(self, architecture: str) -> Optional[Dict[str, Any]]:
        """
        Get information about an architecture
        
        Args:
            architecture: Architecture name
            
        Returns:
            Architecture information dictionary
        """
        if architecture not in self._cache:
            return None
        
        arch_data = self._cache[architecture]
        if isinstance(arch_data, dict):
            return {
                'architecture': arch_data.get('architecture', architecture),
                'count': arch_data.get('count', len(arch_data.get('syscalls', [])))
            }
        return None

# Global instance
_db_instance: Optional[SyscallDatabase] = None

def get_database() -> SyscallDatabase:
    """Get the global syscall database instance"""
    global _db_instance
    if _db_instance is None:
        _db_instance = SyscallDatabase()
    return _db_instance

# Convenience functions
def get_syscall(architecture: str, number: Optional[int] = None, name: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Get a syscall by number or name
    
    Args:
        architecture: Architecture name
        number: Syscall number (optional)
        name: Syscall name (optional)
        
    Returns:
        Syscall dictionary or None
    """
    db = get_database()
    if number is not None:
        return db.get_syscall_by_number(architecture, number)
    elif name is not None:
        return db.get_syscall_by_name(architecture, name)
    return None

def list_syscalls(architecture: str) -> List[Dict[str, Any]]:
    """
    List all syscalls for an architecture
    
    Args:
        architecture: Architecture name
        
    Returns:
        List of syscall dictionaries
    """
    return get_database().get_syscalls(architecture)

def search_syscalls(architecture: str, query: str) -> List[Dict[str, Any]]:
    """
    Search syscalls by name
    
    Args:
        architecture: Architecture name
        query: Search query
        
    Returns:
        List of matching syscalls
    """
    return get_database().search_syscalls(architecture, query)

