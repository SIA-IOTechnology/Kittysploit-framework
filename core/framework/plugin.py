#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Plugin system for KittySploit
"""

import shlex
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from core.output_handler import print_info, print_success, print_error, print_warning

class ModuleArgumentParser:
    """Simple argument parser for plugins"""
    
    def __init__(self, description="", prog=""):
        self.description = description
        self.prog = prog
        self.arguments = []
        self.parsed_args = {}
        
        # Add default help option
        self.add_argument('-h', '--help', dest='help', action='store_true', help='Show this help message')
    
    def add_argument(self, *args, **kwargs):
        """Add an argument to the parser"""
        # Standardize help options
        if '--help' in args or '-h' in args:
            # Ensure help is always available as -h, --help
            if '--help' not in args:
                args = args + ('--help',)
            if '-h' not in args:
                args = ('-h',) + args
        
        arg_info = {
            'args': args,
            'kwargs': kwargs
        }
        self.arguments.append(arg_info)
    
    def add_standard_options(self):
        """Add standard options that are commonly used"""
        # Verbose option
        self.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        
        # Quiet option
        self.add_argument('-q', '--quiet', action='store_true', help='Suppress output')
        
        # Force option
        self.add_argument('-f', '--force', action='store_true', help='Force action without confirmation')
        
        # Yes option
        self.add_argument('-y', '--yes', action='store_true', help='Answer yes to all prompts')
    
    def parse_args(self, args_list):
        """Parse arguments from a list"""
        # Simple argument parsing
        parsed = {}
        i = 0
        while i < len(args_list):
            arg = args_list[i]
            # Find matching argument definition
            for arg_def in self.arguments:
                if arg in arg_def['args']:
                    # Get the destination
                    dest = arg_def['kwargs'].get('dest', arg.lstrip('-'))
                    # Get the value
                    if arg_def['kwargs'].get('action') == 'store_true':
                        parsed[dest] = True
                    else:
                        if i + 1 < len(args_list) and not args_list[i + 1].startswith('-'):
                            value = args_list[i + 1]
                            # Type conversion
                            arg_type = arg_def['kwargs'].get('type', str)
                            try:
                                parsed[dest] = arg_type(value)
                                i += 1  # Skip the value
                            except ValueError:
                                parsed[dest] = value
                                i += 1
                        else:
                            # No value provided, use default or True for store_true
                            if arg_def['kwargs'].get('action') == 'store_true':
                                parsed[dest] = True
                            else:
                                parsed[dest] = arg_def['kwargs'].get('default', None)
                    break
            i += 1
        
        # Create a class with all parsed arguments as attributes
        class ParsedArgs:
            def __init__(self, arguments, **kwargs):
                # Set default values for all arguments first
                for arg_def in arguments:
                    dest = arg_def['kwargs'].get('dest', arg_def['args'][0].lstrip('-'))
                    default_value = arg_def['kwargs'].get('default', False if arg_def['kwargs'].get('action') == 'store_true' else None)
                    setattr(self, dest, default_value)
                
                # Then set the parsed values
                for key, value in kwargs.items():
                    setattr(self, key, value)
        
        return ParsedArgs(self.arguments, **parsed)
    
    def print_help(self):
        """Print help information"""
        print_info(f"Usage: {self.prog} [options]")
        if self.description:
            print_info(f"Description: {self.description}")
        print_info("Options:")
        for arg_def in self.arguments:
            args_str = ", ".join(arg_def['args'])
            help_text = arg_def['kwargs'].get('help', '')
            print_info(f"  {args_str:<20} {help_text}")

class Plugin(ABC):
    """Base class for all plugins"""
    
    __info__ = {
        "name": "Unknown",
        "description": "No description",
        "version": "1.0.0",
        "author": "Unknown",
        "dependencies": []
    }
    
    def __init__(self, framework=None):
        self.framework = framework
        self.name = self.__info__.get("name", "Unknown")
        self.description = self.__info__.get("description", "No description")
        self.version = self.__info__.get("version", "1.0.0")
        self.author = self.__info__.get("author", "Unknown")
        self.dependencies = self.__info__.get("dependencies", [])
    
    @abstractmethod
    def run(self, *args, **kwargs):
        """
        Main execution method for the plugin
        
        Args:
            *args: Command line arguments
            **kwargs: Additional keyword arguments
        """
        pass
    
    def check_dependencies(self):
        """Check if all dependencies are available"""
        missing_deps = []
        for dep in self.dependencies:
            try:
                __import__(dep)
            except ImportError:
                missing_deps.append(dep)
        
        if missing_deps:
            print_error(f"Missing dependencies for plugin '{self.name}': {', '.join(missing_deps)}")
            return False
        return True
    
    def get_info(self):
        """Get plugin information"""
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'author': self.author,
            'dependencies': self.dependencies
        }
    
    def help(self):
        """Show plugin help"""
        print_info(f"Plugin: {self.name}")
        print_info(f"Description: {self.description}")
        print_info(f"Version: {self.version}")
        print_info(f"Author: {self.author}")
        if self.dependencies:
            print_info(f"Dependencies: {', '.join(self.dependencies)}")
    
    def __str__(self):
        return f"Plugin({self.name})"
    
    def __repr__(self):
        return f"Plugin(name='{self.name}', version='{self.version}')"
