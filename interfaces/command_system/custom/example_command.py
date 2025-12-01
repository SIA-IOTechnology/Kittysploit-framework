#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example custom command implementation with argument parsing
"""

import argparse
from interfaces.command_system.base_command import BaseCommand
from core.utils.exceptions import KittyException
from core.output_handler import print_info, print_success, print_error

class ExampleCommand(BaseCommand):
    """Example custom command that demonstrates argument parsing"""
    
    @property
    def name(self) -> str:
        return "example"
    
    @property
    def description(self) -> str:
        return "Example custom command with multiple arguments and options"
    
    @property
    def usage(self) -> str:
        return "example [options] [message]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command demonstrates how to handle multiple arguments and options
in the new command system, similar to the old ModuleArgumentParser.

Options:
    -v, --verbose         Enable verbose output
    -c, --count COUNT     Number of times to repeat the message
    -f, --file FILE       Output to file instead of console
    -h, --help           Show this help message

Examples:
    example                           # Show default message
    example "Hello World"             # Show custom message
    example -v "Debug message"        # Show with verbose output
    example -c 3 "Repeat me"          # Repeat message 3 times
    example -f output.txt "Save me"   # Save message to file
        """
    
    def _create_parser(self):
        """Create argument parser for this command"""
        parser = argparse.ArgumentParser(
            prog=self.name,
            description=self.description,
            add_help=False  # We'll handle help manually
        )
        
        parser.add_argument(
            "-v", "--verbose", 
            action="store_true", 
            help="Enable verbose output"
        )
        
        parser.add_argument(
            "-c", "--count", 
            type=int, 
            default=1, 
            help="Number of times to repeat the message"
        )
        
        parser.add_argument(
            "-f", "--file", 
            type=str, 
            help="Output to file instead of console"
        )
        
        parser.add_argument(
            "-h", "--help", 
            action="store_true", 
            help="Show help message"
        )
        
        parser.add_argument(
            "message", 
            nargs="*", 
            help="Message to display"
        )
        
        return parser
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the example command with argument parsing"""
        parser = self._create_parser()
        
        try:
            # Parse arguments
            parsed_args, unknown_args = parser.parse_known_args(args)
            
            # Handle help
            if parsed_args.help:
                print_info(self.help_text)
                return True
            
            # Handle unknown arguments
            if unknown_args:
                print_error(f"Unknown arguments: {' '.join(unknown_args)}")
                print_info("Use 'example --help' for usage information")
                return False
            
            # Get message
            if parsed_args.message:
                message = " ".join(parsed_args.message)
            else:
                message = "This is an example custom command!"
            
            # Handle verbose output
            if parsed_args.verbose:
                print_info("Verbose mode enabled")
                print_info(f"Parsed arguments: {parsed_args}")
            
            # Handle count
            count = max(1, parsed_args.count)  # Ensure at least 1
            
            # Handle file output
            if parsed_args.file:
                try:
                    with open(parsed_args.file, 'w') as f:
                        for i in range(count):
                            f.write(f"Example command output {i+1}: {message}\n")
                    print_success(f"Message written to file: {parsed_args.file}")
                except Exception as e:
                    print_error(f"Failed to write to file: {e}")
                    return False
            else:
                # Console output
                for i in range(count):
                    if count > 1:
                        print_success(f"Example command executed ({i+1}/{count}): {message}")
                    else:
                        print_success(f"Example command executed: {message}")
            
            # Demonstrate access to framework components
            if parsed_args.verbose:
                if hasattr(self.framework, 'version'):
                    print_info(f"Framework version: {self.framework.version}")
                
                if hasattr(self.framework, 'current_workspace'):
                    print_info(f"Current workspace: {self.framework.current_workspace}")
            
            return True
            
        except Exception as e:
            print_error(f"Error parsing arguments: {e}")
            print_info("Use 'example --help' for usage information")
            return False
