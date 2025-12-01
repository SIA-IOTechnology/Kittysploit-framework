#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Plugin command implementation
"""

import os
import ast
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class PluginCommand(BaseCommand):
    """Command to manage plugins"""
    
    @property
    def name(self) -> str:
        return "plugin"
    
    @property
    def description(self) -> str:
        return "Manage and execute plugins"
    
    @property
    def usage(self) -> str:
        return "plugin [list|load|unload|reload|info|run|create|search] [options]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command allows you to manage and execute plugins in KittySploit.

Subcommands:
    list                           List all loaded plugins
    load <plugin_name>             Load a plugin
    unload <plugin_name>           Unload a plugin
    reload <plugin_name>           Reload a plugin
    info <plugin_name>             Show plugin information
    run <plugin_name> [args]       Execute a plugin with arguments
    create <plugin_name>           Create a new plugin template
    search <term>                  Search for plugins
    help                           Show this help message

Examples:
    plugin list                    # List all loaded plugins
    plugin load ngrok              # Load ngrok plugin
    plugin run ngrok -c 8080      # Run ngrok plugin to create tunnel on port 8080
    plugin info ngrok              # Show ngrok plugin information
    plugin create myplugin         # Create a new plugin template
    plugin search tunnel           # Search for plugins containing "tunnel"

Note: Plugins are automatically loaded from the plugins/ directory.
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the plugin command"""
        if not args:
            return self._list_plugins()
        
        # Handle help flags
        if args[0].lower() in ['-h', '--help', 'help']:
            return self._show_help()
        
        subcommand = args[0].lower()
        
        try:
            if subcommand == "list":
                return self._list_plugins()
            elif subcommand == "load":
                if len(args) < 2:
                    print_error("Plugin name required for load command")
                    print_info("Usage: plugin load <plugin_name>")
                    return False
                return self._load_plugin(args[1])
            elif subcommand == "unload":
                if len(args) < 2:
                    print_error("Plugin name required for unload command")
                    print_info("Usage: plugin unload <plugin_name>")
                    return False
                return self._unload_plugin(args[1])
            elif subcommand == "reload":
                if len(args) < 2:
                    print_error("Plugin name required for reload command")
                    print_info("Usage: plugin reload <plugin_name>")
                    return False
                return self._reload_plugin(args[1])
            elif subcommand == "info":
                if len(args) < 2:
                    print_error("Plugin name required for info command")
                    print_info("Usage: plugin info <plugin_name>")
                    return False
                return self._show_plugin_info(args[1])
            elif subcommand == "run":
                if len(args) < 2:
                    print_error("Plugin name required for run command")
                    print_info("Usage: plugin run <plugin_name> [args]")
                    return False
                plugin_args = args[2:] if len(args) > 2 else []
                return self._run_plugin(args[1], plugin_args)
            elif subcommand == "create":
                if len(args) < 2:
                    print_error("Plugin name required for create command")
                    print_info("Usage: plugin create <plugin_name>")
                    return False
                description = args[2] if len(args) > 2 else ""
                return self._create_plugin(args[1], description)
            elif subcommand == "search":
                if len(args) < 2:
                    print_error("Search term required for search command")
                    print_info("Usage: plugin search <term>")
                    return False
                return self._search_plugins(args[1])
            elif subcommand == "help":
                return self._show_help()
            else:
                print_error(f"Unknown subcommand: {subcommand}")
                print_info("Available subcommands: list, load, unload, reload, info, run, create, search, help")
                return False
                
        except Exception as e:
            print_error(f"Error executing plugin command: {str(e)}")
            return False
    
    def _get_plugin_manager(self):
        """Get the plugin manager from the framework"""
        if not hasattr(self.framework, 'plugin_manager'):
            print_error("Plugin manager not available")
            return None
        return self.framework.plugin_manager
    
    def _extract_plugin_info_from_file(self, plugin_path: str) -> dict:
        """Extract __info__ from plugin file without importing it"""
        try:
            with open(plugin_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse the file as AST
            tree = ast.parse(content)
            
            # Find the class that inherits from Plugin
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    # Check if it has __info__ attribute
                    for item in node.body:
                        if isinstance(item, ast.Assign):
                            for target in item.targets:
                                if isinstance(target, ast.Name) and target.id == '__info__':
                                    # Extract the dictionary
                                    if isinstance(item.value, ast.Dict):
                                        info_dict = {}
                                        keys = item.value.keys
                                        values = item.value.values
                                        for key, value in zip(keys, values):
                                            if isinstance(key, ast.Constant):
                                                key_str = key.value
                                            elif isinstance(key, ast.Str):  # Python < 3.8
                                                key_str = key.s
                                            else:
                                                continue
                                            
                                            if isinstance(value, ast.Constant):
                                                val = value.value
                                            elif isinstance(value, ast.Str):  # Python < 3.8
                                                val = value.s
                                            else:
                                                continue
                                            
                                            info_dict[key_str] = val
                                        return info_dict
        except Exception as e:
            # If parsing fails, return default info
            pass
        
        return {}

    def _list_plugins(self) -> bool:
        """List all available plugins without loading them"""
        try:
            plugin_manager = self._get_plugin_manager()
            if not plugin_manager:
                return False
            
            plugins = plugin_manager.list_plugins()
            
            if not plugins:
                print_info("No plugins available")
                return True
            
            # Extract plugin info from files without loading them
            rows = []
            for plugin_name in plugins:
                plugin_file = os.path.join(plugin_manager.plugins_dir, f"{plugin_name}.py")
                if os.path.exists(plugin_file):
                    plugin_info = self._extract_plugin_info_from_file(plugin_file)
                    if plugin_info:
                        name = plugin_info.get('name', plugin_name)
                        version = plugin_info.get('version', 'Unknown')
                        description = plugin_info.get('description', 'No description')
                        rows.append([name, version, description])
                    else:
                        # Fallback if parsing fails
                        rows.append([plugin_name, 'Unknown', 'No description'])
            
            if rows:
                print_info("Available Plugins:")
                print_info("=" * 100)
                # Calculate column widths
                name_width = max(len("Name"), max(len(row[0]) for row in rows))
                version_width = max(len("Version"), max(len(row[1]) for row in rows))
                desc_width = max(len("Description"), max(len(row[2]) for row in rows))
                
                # Print header
                print_info(f"{'Name':<{name_width}} {'Version':<{version_width}} {'Description'}")
                print_info("-" * 100)
                
                # Print rows with full descriptions
                for row in rows:
                    name, version, description = row
                    print_info(f"{name:<{name_width}} {version:<{version_width}} {description}")
                
                print_info("=" * 100)
                print_info(f"Total: {len(rows)} plugins")
            else:
                print_info("No plugins available")
            
            return True
            
        except Exception as e:
            print_error(f"Error listing plugins: {str(e)}")
            return False
    
    def _load_plugin(self, plugin_name: str) -> bool:
        """Load a plugin"""
        try:
            plugin_manager = self._get_plugin_manager()
            if not plugin_manager:
                return False
            
            success = plugin_manager.load_plugin(plugin_name)
            if success:
                print_success(f"Plugin '{plugin_name}' loaded successfully")
            else:
                print_error(f"Failed to load plugin '{plugin_name}'")
            return success
            
        except Exception as e:
            print_error(f"Error loading plugin: {str(e)}")
            return False
    
    def _unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        try:
            plugin_manager = self._get_plugin_manager()
            if not plugin_manager:
                return False
            
            success = plugin_manager.unload_plugin(plugin_name)
            return success
            
        except Exception as e:
            print_error(f"Error unloading plugin: {str(e)}")
            return False
    
    def _reload_plugin(self, plugin_name: str) -> bool:
        """Reload a plugin"""
        try:
            plugin_manager = self._get_plugin_manager()
            if not plugin_manager:
                return False
            
            success = plugin_manager.reload_plugin(plugin_name)
            if success:
                print_success(f"Plugin '{plugin_name}' reloaded successfully")
            else:
                print_error(f"Failed to reload plugin '{plugin_name}'")
            return success
            
        except Exception as e:
            print_error(f"Error reloading plugin: {str(e)}")
            return False
    
    def _show_plugin_info(self, plugin_name: str) -> bool:
        """Show plugin information"""
        try:
            plugin_manager = self._get_plugin_manager()
            if not plugin_manager:
                return False
            
            plugin_info = plugin_manager.get_plugin_info(plugin_name)
            if not plugin_info:
                print_error(f"Plugin '{plugin_name}' not found")
                return False
            
            print_info(f"Plugin Information: {plugin_name}")
            print_info("=" * 50)
            print_info(f"Name: {plugin_info.get('name', 'Unknown')}")
            print_info(f"Description: {plugin_info.get('description', 'No description')}")
            print_info(f"Version: {plugin_info.get('version', 'Unknown')}")
            print_info(f"Author: {plugin_info.get('author', 'Unknown')}")
            
            dependencies = plugin_info.get('dependencies', [])
            if dependencies:
                print_info(f"Dependencies: {', '.join(dependencies)}")
            else:
                print_info("Dependencies: None")
            
            return True
            
        except Exception as e:
            print_error(f"Error showing plugin info: {str(e)}")
            return False
    
    def _run_plugin(self, plugin_name: str, plugin_args: list) -> bool:
        """Run a plugin with arguments"""
        try:
            plugin_manager = self._get_plugin_manager()
            if not plugin_manager:
                return False
            
            success = plugin_manager.execute_plugin(plugin_name, plugin_args)
            return success
            
        except Exception as e:
            print_error(f"Error running plugin: {str(e)}")
            return False
    
    def _create_plugin(self, plugin_name: str, description: str) -> bool:
        """Create a new plugin template"""
        try:
            plugin_manager = self._get_plugin_manager()
            if not plugin_manager:
                return False
            
            success = plugin_manager.create_plugin_template(plugin_name, description)
            return success
            
        except Exception as e:
            print_error(f"Error creating plugin: {str(e)}")
            return False
    
    def _search_plugins(self, search_term: str) -> bool:
        """Search for plugins"""
        try:
            plugin_manager = self._get_plugin_manager()
            if not plugin_manager:
                return False
            
            matching_plugins = plugin_manager.search_plugins(search_term)
            
            if not matching_plugins:
                print_info(f"No plugins found matching '{search_term}'")
                return True
            
            print_info(f"Plugins matching '{search_term}':")
            for plugin_name in matching_plugins:
                plugin_info = plugin_manager.get_plugin_info(plugin_name)
                if plugin_info:
                    print_info(f"  {plugin_name}: {plugin_info.get('description', 'No description')}")
            
            return True
            
        except Exception as e:
            print_error(f"Error searching plugins: {str(e)}")
            return False
    
    def _show_help(self) -> bool:
        """Show detailed help for the plugin command"""
        try:
            print_info(self.help_text)
            return True
        except Exception as e:
            print_error(f"Error showing help: {str(e)}")
            return False
