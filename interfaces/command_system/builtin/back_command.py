#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Back command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error

class BackCommand(BaseCommand):
    """Command to go back to previous context or exit current module"""
    
    @property
    def name(self) -> str:
        return "back"
    
    @property
    def description(self) -> str:
        return "Go back to previous context or exit current module"
    
    @property
    def usage(self) -> str:
        return "back"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command allows you to go back to the previous context. If you are
currently using a module, it will exit the module and return to the
main command prompt.

Examples:
    back                    # Exit current module and return to main prompt
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the back command"""
        try:
            # Check if we have a current module
            if hasattr(self.framework, 'current_module') and self.framework.current_module:
                module_name = self.framework.current_module.name
                
                # Clear the current module
                self.framework.current_module = None
                
                print_success(f"Exited module: {module_name}")
                print_info("Returned to main command prompt")
                
                return True
            else:
                print_info("No active module to exit")
                print_info("You are already at the main command prompt")
                
                return True
                
        except Exception as e:
            print_error(f"Error executing back command: {str(e)}")
            return False
