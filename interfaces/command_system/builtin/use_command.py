#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Use command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_table
from core.framework.option.base_option import Option as BaseOption
from core.utils.privileges import is_root, is_admin
import os

class UseCommand(BaseCommand):
    """Command to select and use a module"""
    
    @property
    def name(self) -> str:
        return "use"
    
    @property
    def description(self) -> str:
        return "Select a module for use"
    
    @property
    def usage(self) -> str:
        return "use <module_path>"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command selects a module for use. Once selected, you can configure
its options and execute it.

Examples:
    use auxiliary/example              # Use the example auxiliary module
    use exploits/http_scanner          # Use an HTTP scanner exploit
    use scanners/port_scanner          # Use a port scanner module
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the use command"""
        if len(args) == 0:
            print_error("Usage: use <module_path>")
            print_info("Use 'search' to find available modules")
            return False
        
        module_path = args[0]
        
        try:
            # Load the module
            module = self.framework.module_loader.load_module(module_path, framework=self.framework)
            
            if not module:
                # Error message should already be displayed by module_loader
                # But provide additional context if needed
                print_error(f"Failed to load module '{module_path}'")
                print_info("Check the error message above for details")
                return False
            
            # Check if module requires root/administrator privileges
            if module.requires_root:
                # Check if user has required privileges
                has_privileges = False
                if os.name == 'nt':  # Windows
                    has_privileges = is_admin()
                    if not has_privileges:
                        print_error("This module requires administrator privileges")
                        print_error("Please run KittySploit as administrator")
                        print_error("Module not loaded")
                        return False
                else:  # Unix/Linux
                    has_privileges = is_root()
                    if not has_privileges:
                        print_error("This module requires root privileges")
                        print_error("Please run KittySploit with sudo or as root")
                        print_error("Module not loaded")
                        return False
                
                # User has required privileges
                print_success("Root/administrator privileges confirmed")
            
            # Set as current module
            self.framework.current_module = module
            
            print_success(f"Using module: {module.name}")
            print_info(f"Description: {module.description}")
            print_info(f"Author: {module.author}")
            
            # Show module options (excluding advanced by default)
            options = module.get_options()
            if options:
                # Filter out advanced options
                filtered_options = {}
                advanced_count = 0
                for name, option_data in options.items():
                    if len(option_data) >= 4:
                        default, required, description, advanced = option_data[:4]
                        if not advanced:
                            filtered_options[name] = option_data
                        else:
                            advanced_count += 1
                
                if filtered_options:
                    # Prepare table data
                    headers = ["Name", "Current Setting", "Required", "Description"]
                    rows = []
                    
                    for name, option_data in filtered_options.items():
                        if len(option_data) >= 4:
                            default, required, description, advanced = option_data[:4]
                            # Get option object from class to avoid triggering __get__ for OptFile
                            option_descriptor = getattr(type(module), name, None)
                            if option_descriptor and isinstance(option_descriptor, BaseOption):
                                # Use to_dict to get display_value without triggering __get__
                                option_dict = option_descriptor.to_dict(module)
                                current_value = option_dict.get('display_value', '')
                            else:
                                # Fallback to old method for non-Option attributes
                                option_obj = getattr(module, name, default)
                                if hasattr(option_obj, 'value'):
                                    current_value = option_obj.value
                                elif hasattr(option_obj, 'display_value'):
                                    current_value = option_obj.display_value
                                else:
                                    current_value = option_obj
                            
                            # Format current value - handle booleans and None correctly
                            if current_value is None:
                                value_str = ""
                            elif isinstance(current_value, bool):
                                # Always display boolean values as True/False
                                value_str = str(current_value)
                            elif current_value == "":
                                value_str = ""
                            else:
                                value_str = str(current_value)
                            
                            # Format required
                            req_text = "yes" if required else "no"
                            
                            rows.append([name, value_str, req_text, description])
                    
                    # Display table
                    print_info("")
                    print_info("Module options:")
                    print_info("=" * 120)
                    # Use larger max_width to allow full descriptions to be displayed
                    print_table(headers, rows, max_width=120)
                    print_info("=" * 120)
                
                if advanced_count > 0:
                    print_info("")
                    print_info(f"({advanced_count} advanced option(s) hidden - use 'show advanced' to view)")
            
            return True
            
        except Exception as e:
            print_error(f"Error loading module '{module_path}': {str(e)}")
            return False
