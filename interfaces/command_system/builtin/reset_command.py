#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reset command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_status

class ResetCommand(BaseCommand):
    """Command to reset the framework to first startup state"""
    
    @property
    def name(self) -> str:
        return "reset"
    
    @property
    def description(self) -> str:
        return "Reset the framework to first startup state"
    
    @property
    def usage(self) -> str:
        return "reset [--database] [--force]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

This command will:
  - Reset encryption (delete encryption files)
  - Reset charter acceptance
  - Optionally reset database (--database)

WARNING: This will make all encrypted data unreadable!

Usage: {self.usage}

Options:
    --database    Also delete the database file
    --force       Skip confirmation prompt

Examples:
    reset                    # Reset encryption and charter only
    reset --database         # Also reset database
    reset --force            # Skip confirmation
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the reset command"""
        reset_database = False
        force = False
        
        # Parse arguments
        for arg in args:
            if arg == '--database':
                reset_database = True
            elif arg == '--force':
                force = True
            elif arg in ['-h', '--help', 'help']:
                print_info(self.help_text)
                return True
            else:
                print_error(f"Unknown option: {arg}")
                print_info(f"Use '{self.name} --help' for usage information")
                return False
        
        # Show warning
        print_warning("WARNING: This will reset the framework to first startup state!")
        print_warning("All encrypted data will become unreadable!")
        if reset_database:
            print_warning("Database will be deleted!")
        
        # Ask for confirmation unless --force
        if not force:
            try:
                response = input("\nAre you sure you want to proceed? (yes/no): ").strip().lower()
                if response not in ['yes', 'y', 'oui', 'o']:
                    print_warning("Operation cancelled.")
                    return True
            except KeyboardInterrupt:
                print_error("Operation cancelled.")
                return True
            except EOFError:
                print_error("Operation cancelled.")
                return True
        
        # Execute reset
        print_info()
        if self.framework.reset_framework(
            reset_database=reset_database
        ):
            print_success("Framework reset completed successfully!")
            print_status("You can now restart KittySploit to go through the first startup process.")
            return True
        else:
            print_error("Framework reset failed. Please check the errors above.")
            return False

