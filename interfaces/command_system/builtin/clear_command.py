#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Clear command implementation
"""

import os
import sys
from interfaces.command_system.base_command import BaseCommand

class ClearCommand(BaseCommand):
    """Command to clear the screen"""
    
    @property
    def name(self) -> str:
        return "clear"
    
    @property
    def description(self) -> str:
        return "Clear the terminal screen"
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the clear command"""
        try:
            # Clear screen based on OS
            if os.name == 'nt':  # Windows
                os.system('cls')
            else:  # Unix/Linux/Mac
                os.system('clear')
            
            return True
        except Exception as e:
            self.print_error(f"Failed to clear screen: {str(e)}")
            return False
