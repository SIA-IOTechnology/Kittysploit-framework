#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Search command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error

class SearchCommand(BaseCommand):
    """Command to search for modules"""
    
    @property
    def name(self) -> str:
        return "search"
    
    @property
    def description(self) -> str:
        return "Search for modules by keyword"
    
    @property
    def usage(self) -> str:
        return "search <keyword>"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command searches for modules by keyword in their name, description,
or type.

Examples:
    search scanner              # Find all scanner modules
    search http                 # Find modules related to HTTP
    search auxiliary            # Find all auxiliary modules
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the search command"""
        if len(args) == 0:
            print_error("Usage: search <keyword>")
            return False
        
        keyword = args[0].lower()
        
        try:
            # Use database search for better performance
            matches = self.framework.search_modules_db(query=keyword, limit=50)
            
            if not matches:
                print_info(f"No modules found matching '{keyword}'")
                return True
            
            # Display results
            print_success(f"Found {len(matches)} module(s) matching '{keyword}':")
            print_info("=" * 60)
            
            for module in matches:
                print_info(f"{module['path']:<30} {module.get('name', 'Unknown')}")
                if module.get('description'):
                    print_info(f"{'':30} {module['description']}")
                if module.get('type'):
                    print_info(f"{'':30} Type: {module['type']}")
                print_info("")
            
            return True
            
        except Exception as e:
            print_error(f"Error searching modules: {str(e)}")
            return False
