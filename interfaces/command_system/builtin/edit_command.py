#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Edit command implementation
"""

import os
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class EditCommand(BaseCommand):
    """Command to edit the current module's source code"""
    
    @property
    def name(self) -> str:
        return "edit"
    
    @property
    def description(self) -> str:
        return "Edit the current module's source code"
    
    @property
    def usage(self) -> str:
        return "edit"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command opens an interactive editor to modify the source code of the currently selected module.
The editor supports syntax highlighting for Python code and provides a multi-line editing interface.

Features:
    - Syntax highlighting for Python code
    - Multi-line editing support
    - Confirmation before saving changes
    - Ctrl+D to finish editing

Note: This command only works when a module is selected.
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the edit command"""
        try:
            # Check if a module is selected
            if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
                print_error("No module selected. Use 'use <module>' first.")
                return False
            
            # Get the current module
            current_module = self.framework.current_module

            # Module loader is required for editing
            module_loader = getattr(self.framework, 'module_loader', None)
            if not module_loader:
                print_error("Module loader is not available in this context.")
                return False
            
            # Try to find the module path by searching through the module loader cache
            module_path = None
            discovered_modules = None
            modules_cache = getattr(module_loader, 'modules_cache', {})
            for cached_path, cached_module in modules_cache.items():
                if cached_module == current_module:
                    module_path = cached_path
                    break
            
            # If not found in cache, try to find by module name
            if not module_path:
                if discovered_modules is None:
                    try:
                        discovered_modules = module_loader.discover_modules()
                    except Exception as e:
                        print_error(f"Could not discover modules automatically: {e}")
                        return False
                for path, file_path in discovered_modules.items():
                    try:
                        # Load module temporarily to check if it's the same
                        temp_module = module_loader.load_module(path, load_only=True)
                        if temp_module and temp_module.name == current_module.name:
                            module_path = path
                            break
                    except:
                        continue
            
            if not module_path:
                print_error("Could not determine the module path. Please use 'use <module>' again.")
                return False
            
            # Get the actual file path from discovered modules
            if discovered_modules is None:
                try:
                    discovered_modules = module_loader.discover_modules()
                except Exception:
                    discovered_modules = {}

            module_file_path = None
            if module_path in discovered_modules:
                module_file_path = discovered_modules[module_path]
            else:
                # Convert Python format (dots) to file format (slashes)
                file_format_path = module_path.replace('.', '/')
                if file_format_path in discovered_modules:
                    module_file_path = discovered_modules[file_format_path]
                else:
                    # Construct the file path manually
                    module_file_path = f"modules/{file_format_path}.py"
            
            # Check if the file exists
            if not os.path.exists(module_file_path):
                print_error(f"Module file not found: {module_file_path}")
                return False
            
            # Try to import required dependencies
            try:
                from prompt_toolkit import PromptSession
                from prompt_toolkit.shortcuts import confirm
                from prompt_toolkit.lexers import PygmentsLexer
                from prompt_toolkit.key_binding import KeyBindings
                from pygments.lexers.python import PythonLexer
            except ImportError as e:
                print_error(f"Required dependencies not available: {e}")
                print_info("Please install prompt_toolkit and pygments:")
                print_info("pip install prompt_toolkit pygments")
                return False
            
            # Set up key bindings
            bindings = KeyBindings()

            # When you press Ctrl+D
            @bindings.add("c-d")
            def _(event):
                event.app.exit(result=session.default_buffer.document.text)

            # Create prompt session with syntax highlighting
            session = PromptSession(
                lexer=PygmentsLexer(PythonLexer), 
                key_bindings=bindings
            )

            # Read the current module code
            try:
                with open(module_file_path, 'r', encoding='utf-8') as file:
                    code = file.read()
            except Exception as e:
                print_error(f"Error reading module file: {e}")
                return False

            print_info(f"Editing module: {current_module.name}")
            print_info("Press Ctrl+D when done editing")
            print_warning("Warning: Make sure you understand the module structure before making changes!")

            # Edit the code
            try:
                new_code = session.prompt(
                    "Edit the code (press Ctrl+D when done):\n", 
                    multiline=True, 
                    default=code
                )
            except KeyboardInterrupt:
                print_info("Edit cancelled by user.")
                return False
            except Exception as e:
                print_error(f"Error during editing: {e}")
                return False

            # Check if code was actually changed
            if new_code.strip() == code.strip():
                print_info("No changes detected. File not modified.")
                return True

            # Ask for confirmation before saving
            try:
                if confirm("Do you want to save the changes?"):
                    # Create backup
                    backup_path = f"{module_file_path}.backup"
                    with open(backup_path, 'w', encoding='utf-8') as backup_file:
                        backup_file.write(code)
                    print_info(f"Backup created: {backup_path}")
                    
                    # Save the new code
                    with open(module_file_path, 'w', encoding='utf-8') as file:
                        file.write(new_code)
                    
                    print_success(f"Module '{current_module.name}' has been updated successfully!")
                    print_info(f"File saved: {module_file_path}")
                    
                    # Suggest reloading the module
                    print_warning("Note: You may need to reload the module to see changes:")
                    print_info(f"  use {current_module._module_path}")
                    
                    return True
                else:
                    print_info("Changes not saved.")
                    return True
            except Exception as e:
                print_error(f"Error saving file: {e}")
                return False
            
        except Exception as e:
            print_error(f"Error editing module: {str(e)}")
            return False
