#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interpreter command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error

class InterpreterCommand(BaseCommand):
    """Command to start the KittyPy interactive interpreter"""
    
    @property
    def name(self) -> str:
        return "interpreter"
    
    @property
    def description(self) -> str:
        return "Start the KittyPy interactive interpreter"
    
    @property
    def usage(self) -> str:
        return "interpreter"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command starts the KittyPy interactive interpreter, which allows you to
execute Python code in the context of the KittySploit framework. You can
access framework objects, modules, and utilities directly.

Examples:
    interpreter                    # Start the interactive interpreter
    
Once in the interpreter, you can use:
    - framework                    # Access the main framework object
    - current_module              # Access the current module (if any)
    - print_info(), print_error() # Use framework output functions
    - All Python built-ins and standard library
    
To exit the interpreter, type 'exit()' or press Ctrl+C.
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the interpreter command"""
        try:
            print_success("Starting KittyPy interactive interpreter...")
            print_info("Type 'exit()' to return to the main prompt")
            print_info("=" * 50)
            
            # Import and start the interpreter
            from core.interpreter import start_interpreter
            start_interpreter(self.framework)
            
            print_info("=" * 50)
            print_success("Returned to main command prompt")
            
            return True
            
        except ImportError as e:
            print_error(f"Failed to import interpreter: {str(e)}")
            return False
        except Exception as e:
            print_error(f"Error starting interpreter: {str(e)}")
            return False
