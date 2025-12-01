#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command argument parser utility for the new command system
Similar to ModuleArgumentParser but adapted for the new command system
"""

import argparse
from core.utils.exceptions import KittyException
from core.output_handler import print_info

class CommandArgumentParser(argparse.ArgumentParser):
    """
    Custom argument parser for commands in the new command system
    Similar to ModuleArgumentParser but adapted for the new architecture
    """
    
    def __init__(self, *args, **kwargs):
        # Set default formatter for better help display
        kwargs.setdefault('formatter_class', argparse.ArgumentDefaultsHelpFormatter)
        super().__init__(*args, **kwargs)
    
    def parse_known_args(self, args=None, namespace=None):
        """
        Override method to prevent -h from printing then calling sys.exit()
        """
        try:
            return super().parse_known_args(args, namespace)
        except SystemExit:
            # Prevent argparse from calling sys.exit() on help or error
            pass
        return None, None
    
    def error(self, message):
        """
        Override method to prevent argparse from calling sys.exit()
        """
        self.print_usage()
        raise KittyException(f"Argument parsing error: {message}")
    
    def _print_message(self, message, file=None):
        """
        Override to use our output handler
        """
        print_info(message)

class CommandParserHelper:
    """
    Helper class to create common argument patterns for commands
    """
    
    @staticmethod
    def create_basic_parser(prog_name, description=""):
        """
        Create a basic parser with common options
        
        Args:
            prog_name: Program name
            description: Description of the command
            
        Returns:
            CommandArgumentParser: Configured parser
        """
        parser = CommandArgumentParser(
            prog=prog_name,
            description=description,
            add_help=False
        )
        
        # Add common options
        parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Enable verbose output"
        )
        
        parser.add_argument(
            "-h", "--help",
            action="store_true",
            help="Show help message"
        )
        
        return parser
    
    @staticmethod
    def create_file_parser(prog_name, description=""):
        """
        Create a parser with file-related options
        
        Args:
            prog_name: Program name
            description: Description of the command
            
        Returns:
            CommandArgumentParser: Configured parser
        """
        parser = CommandParserHelper.create_basic_parser(prog_name, description)
        
        parser.add_argument(
            "-f", "--file",
            type=str,
            help="Input file path"
        )
        
        parser.add_argument(
            "-o", "--output",
            type=str,
            help="Output file path"
        )
        
        parser.add_argument(
            "--overwrite",
            action="store_true",
            help="Overwrite existing files"
        )
        
        return parser
    
    @staticmethod
    def create_network_parser(prog_name, description=""):
        """
        Create a parser with network-related options
        
        Args:
            prog_name: Program name
            description: Description of the command
            
        Returns:
            CommandArgumentParser: Configured parser
        """
        parser = CommandParserHelper.create_basic_parser(prog_name, description)
        
        parser.add_argument(
            "-H", "--host",
            type=str,
            default="127.0.0.1",
            help="Host address"
        )
        
        parser.add_argument(
            "-p", "--port",
            type=int,
            help="Port number"
        )
        
        parser.add_argument(
            "-t", "--timeout",
            type=int,
            default=30,
            help="Connection timeout in seconds"
        )
        
        return parser
    
    @staticmethod
    def create_subcommand_parser(prog_name, description=""):
        """
        Create a parser with subcommands support
        
        Args:
            prog_name: Program name
            description: Description of the command
            
        Returns:
            tuple: (main_parser, subparsers)
        """
        parser = CommandParserHelper.create_basic_parser(prog_name, description)
        
        subparsers = parser.add_subparsers(
            dest="action",
            help="Action to perform"
        )
        
        return parser, subparsers
    
    @staticmethod
    def add_common_subcommands(subparsers):
        """
        Add common subcommands to subparsers
        
        Args:
            subparsers: Subparsers object from argparse
        """
        # List subcommand
        list_parser = subparsers.add_parser(
            "list",
            help="List items"
        )
        list_parser.add_argument(
            "-s", "--sort",
            choices=["name", "date", "size"],
            default="name",
            help="Sort by field"
        )
        
        # Show subcommand
        show_parser = subparsers.add_parser(
            "show",
            help="Show details"
        )
        show_parser.add_argument(
            "name",
            help="Name of item to show"
        )
        
        # Delete subcommand
        delete_parser = subparsers.add_parser(
            "delete",
            help="Delete item"
        )
        delete_parser.add_argument(
            "name",
            help="Name of item to delete"
        )
        delete_parser.add_argument(
            "-f", "--force",
            action="store_true",
            help="Force deletion"
        )
