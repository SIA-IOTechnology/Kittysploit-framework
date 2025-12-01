#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base shell class for all shell implementations
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from core.output_handler import print_info, print_error, print_success

class BaseShell(ABC):
    """Base class for all shell implementations"""
    
    def __init__(self, session_id: str, session_type: str = "unknown"):
        self.session_id = session_id
        self.session_type = session_type
        self.is_active = True
        self.command_history: List[str] = []
        self.current_directory = "/"
        self.environment_vars: Dict[str, str] = {}
        self.username = "user"
        self.hostname = "localhost"
        self.is_root = False
        
    @property
    @abstractmethod
    def shell_name(self) -> str:
        """Name of the shell type"""
        pass
    
    @property
    @abstractmethod
    def prompt_template(self) -> str:
        """Template for the shell prompt"""
        pass
    
    @abstractmethod
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        pass
    
    @abstractmethod
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command in the shell"""
        pass
    
    @abstractmethod
    def get_available_commands(self) -> List[str]:
        """Get list of available commands for this shell"""
        pass
    
    def add_to_history(self, command: str):
        """Add command to history"""
        if command.strip():
            self.command_history.append(command.strip())
    
    def get_history(self, limit: int = 50) -> List[str]:
        """Get command history"""
        return self.command_history[-limit:] if limit > 0 else self.command_history
    
    def clear_history(self):
        """Clear command history"""
        self.command_history.clear()
    
    def set_environment_var(self, key: str, value: str):
        """Set an environment variable"""
        self.environment_vars[key] = value
    
    def get_environment_var(self, key: str, default: str = "") -> str:
        """Get an environment variable"""
        return self.environment_vars.get(key, default)
    
    def set_user_info(self, username: str, hostname: str, is_root: bool = False):
        """Set user information"""
        self.username = username
        self.hostname = hostname
        self.is_root = is_root
    
    def set_current_directory(self, directory: str):
        """Set current working directory"""
        self.current_directory = directory
    
    def get_current_directory(self) -> str:
        """Get current working directory"""
        return self.current_directory
    
    def is_command_available(self, command: str) -> bool:
        """Check if a command is available"""
        return command in self.get_available_commands()
    
    def get_shell_info(self) -> Dict[str, Any]:
        """Get shell information"""
        return {
            'shell_name': self.shell_name,
            'session_id': self.session_id,
            'session_type': self.session_type,
            'is_active': self.is_active,
            'username': self.username,
            'hostname': self.hostname,
            'is_root': self.is_root,
            'current_directory': self.current_directory,
            'command_count': len(self.command_history),
            'available_commands': len(self.get_available_commands())
        }
    
    def activate(self):
        """Activate the shell"""
        self.is_active = True
    
    def deactivate(self):
        """Deactivate the shell"""
        self.is_active = False
    
    def __str__(self) -> str:
        return f"{self.shell_name} shell (session: {self.session_id})"
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(session_id='{self.session_id}', active={self.is_active})>"
