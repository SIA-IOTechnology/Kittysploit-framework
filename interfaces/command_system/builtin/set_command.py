#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Set command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error

class SetCommand(BaseCommand):
    """Command to set module options"""
    
    @property
    def name(self) -> str:
        return "set"
    
    @property
    def description(self) -> str:
        return "Set module option values"
    
    @property
    def usage(self) -> str:
        return "set <option> <value>"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command sets the value of a module option.

Examples:
    set target 192.168.1.100     # Set target IP
    set ports 80,443,22          # Set ports to scan
    set timeout 30               # Set timeout value
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the set command"""
        if len(args) < 2:
            print_error("Usage: set <option> <value>")
            return False
        
        if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
            print_error("No module selected. Use 'use <module>' first.")
            return False
        
        option_name = args[0]
        option_value = " ".join(args[1:])  # Join remaining args in case value has spaces
        
        try:
            module = self.framework.current_module
            
            # Check if option exists (case-insensitive search)
            options = module.get_options()
            # Find matching option (case-insensitive)
            matching_option = None
            for opt_name in options.keys():
                if opt_name.lower() == option_name.lower():
                    matching_option = opt_name
                    break
            
            if matching_option is None:
                print_error(f"Unknown option: {option_name}")
                print_info("Use 'show options' to see available options")
                return False
            
            # Set the option value using the correct case
            success = module.set_option(matching_option, option_value)
            
            if success:
                # Display with the correct case from the module
                print_success(f"{matching_option} => {option_value}")
            else:
                print_error(f"Failed to set option {option_name}")
                return False
            
            return True
            
        except Exception as e:
            print_error(f"Error setting option: {str(e)}")
            return False
