#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base class for all commands in KittySploit
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from core.utils.exceptions import KittyException
from core.output_handler import print_info, print_error, print_success, print_warning

class BaseCommand(ABC):
    """Base class for all commands"""
    
    def __init__(self, framework, session, output_handler):
        self.framework = framework
        self.session = session
        self.output_handler = output_handler
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Command name (without 'command_' prefix)"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Command description"""
        pass
    
    @property
    def usage(self) -> str:
        """Command usage string"""
        return f"{self.name} [options]"
    
    @property
    def help_text(self) -> str:
        """Detailed help text"""
        return f"{self.description}\nUsage: {self.usage}"
    
    @abstractmethod
    def execute(self, args: List[str], **kwargs) -> bool:
        """
        Execute the command
        
        Args:
            args: Command arguments
            **kwargs: Additional keyword arguments
            
        Returns:
            bool: True if command executed successfully, False otherwise
        """
        pass
    
    def validate_args(self, args: List[str], min_args: int = 0, max_args: int = None) -> bool:
        """
        Validate command arguments
        
        Args:
            args: Command arguments
            min_args: Minimum number of arguments required
            max_args: Maximum number of arguments allowed (None for no limit)
            
        Returns:
            bool: True if arguments are valid, False otherwise
        """
        if len(args) < min_args:
            print_error(f"Command '{self.name}' requires at least {min_args} arguments")
            return False
        
        if max_args is not None and len(args) > max_args:
            print_error(f"Command '{self.name}' accepts at most {max_args} arguments")
            return False
        
        return True
    
    def show_help(self):
        """Show command help"""
        print_info(self.help_text)
    
    def show_usage(self):
        """Show command usage"""
        print_info(f"Usage: {self.usage}")
    
    def print_success(self, message: str):
        """Print success message"""
        from core.output_handler import print_success as _print_success
        _print_success(message)
    
    def print_error(self, message: str):
        """Print error message"""
        from core.output_handler import print_error as _print_error
        _print_error(message)
    
    def print_warning(self, message: str):
        """Print warning message"""
        from core.output_handler import print_warning as _print_warning
        _print_warning(message)
    
    def print_info(self, message: str):
        """Print info message"""
        from core.output_handler import print_info as _print_info
        _print_info(message)
