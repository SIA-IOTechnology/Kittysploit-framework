#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exit command implementation
"""

import sys
import random
from interfaces.command_system.base_command import BaseCommand
from core.utils.bye import EXIT_MESSAGES
from core.output_handler import print_info

class ExitCommand(BaseCommand):
    """Command to exit the framework"""
    
    @property
    def name(self) -> str:
        return "exit"
    
    @property
    def description(self) -> str:
        return "Exit the KittySploit framework"
    
    @property
    def usage(self) -> str:
        return "exit [--force]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command exits the KittySploit framework. If there are active sessions
or unsaved work, you may be prompted to confirm the exit.

Options:
    --force    Force exit without confirmation

Examples:
    exit                    # Exit with confirmation if needed
    exit --force           # Force exit immediately
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the exit command"""
        force = "--force" in args
        
        if not force:
            # Check for active sessions or unsaved work
            has_active_sessions = False
            has_unsaved_work = False
            
            # Check for active sessions
            if hasattr(self.framework, 'session_manager'):
                try:
                    sessions = self.framework.session_manager.get_all_sessions()
                    if isinstance(sessions, dict) and 'browser' in sessions:
                        has_active_sessions = len(sessions['browser']) > 0
                except:
                    pass
            
            # Check for unsaved work (current module with options)
            if hasattr(self.framework, 'current_module') and self.framework.current_module:
                has_unsaved_work = True
            
            if has_active_sessions or has_unsaved_work:
                self.print_warning("You have active sessions or unsaved work.")
                self.print_info("Use 'exit --force' to exit without confirmation.")
                # Return True because the command executed successfully (it just refused to exit for safety)
                return True
        
        # Exit the framework
        print_info()
        print_info(random.choice(EXIT_MESSAGES))
        print_info()
        
        # Use sys.exit to properly exit
        sys.exit(0)
        
        return True  # This line will never be reached
