#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Plugin Manager for KittySploit
"""

import os
import sys
import importlib
import inspect
from typing import Dict, List, Type, Any, Optional
from core.framework.plugin import Plugin
from core.output_handler import print_info, print_success, print_error, print_warning

class PluginManager:
    """Manager for loading and executing plugins"""
    
    def __init__(self, framework=None):
        self.framework = framework
        self.plugins: Dict[str, Plugin] = {}
        self.plugin_classes: Dict[str, Type[Plugin]] = {}
        self.plugins_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'plugins')
        self.plugins_loaded = False
        
        # Create plugins directory if it doesn't exist
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir)
        
        # Don't load plugins automatically - wait for authentication
    
    def load_plugins(self):
        """Load all plugins from the plugins directory"""
        if self.plugins_loaded:
            return
            
        if not os.path.exists(self.plugins_dir):
            return
        
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                plugin_name = filename[:-3]  # Remove .py extension
                try:
                    self.load_plugin(plugin_name)
                except Exception as e:
                    print_warning(f"Failed to load plugin '{plugin_name}': {e}")
        
        self.plugins_loaded = True
    
    def load_plugin(self, plugin_name: str) -> bool:
        """Load a specific plugin"""
        try:
            # Add plugins directory to Python path
            if self.plugins_dir not in sys.path:
                sys.path.insert(0, self.plugins_dir)
            
            # Import the plugin module
            module = importlib.import_module(plugin_name)
            
            # Find plugin classes in the module
            plugin_classes = []
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, Plugin) and 
                    obj != Plugin):
                    plugin_classes.append(obj)
            
            if not plugin_classes:
                print_warning(f"No plugin classes found in {plugin_name}")
                return False
            
            # Register each plugin class
            for plugin_class in plugin_classes:
                plugin_instance = plugin_class(self.framework)
                
                # Check dependencies
                if not plugin_instance.check_dependencies():
                    print_warning(f"Plugin '{plugin_instance.name}' has missing dependencies")
                    continue
                
                # Register the plugin
                self.plugin_classes[plugin_instance.name] = plugin_class
                self.plugins[plugin_instance.name] = plugin_instance
                print_success(f"Loaded plugin: {plugin_instance.name} v{plugin_instance.version}")
            
            return True
            
        except Exception as e:
            print_error(f"Error loading plugin '{plugin_name}': {e}")
            return False
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        if plugin_name in self.plugins:
            del self.plugins[plugin_name]
            if plugin_name in self.plugin_classes:
                del self.plugin_classes[plugin_name]
            print_success(f"Unloaded plugin: {plugin_name}")
            return True
        else:
            print_warning(f"Plugin '{plugin_name}' not found")
            return False
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a plugin"""
        if plugin_name in self.plugins:
            self.unload_plugin(plugin_name)
        return self.load_plugin(plugin_name)
    
    def get_plugin(self, plugin_name: str) -> Optional[Plugin]:
        """Get a plugin instance"""
        return self.plugins.get(plugin_name)
    
    def list_plugins(self) -> List[str]:
        """List all available plugins (without loading them)"""
        if not os.path.exists(self.plugins_dir):
            return []
        
        plugins = []
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                plugin_name = filename[:-3]  # Remove .py extension
                plugins.append(plugin_name)
        
        return plugins
    
    def execute_plugin(self, plugin_name: str, args: List[str] = None, **kwargs) -> bool:
        """Execute a plugin (loads it on demand if not already loaded)"""
        # Load the specific plugin if not already loaded
        if plugin_name not in self.plugins:
            if not self.load_plugin(plugin_name):
                print_error(f"Plugin '{plugin_name}' not found or failed to load")
                return False
        
        plugin = self.plugins[plugin_name]
        
        try:
            # Execute the plugin
            if args is None:
                args = []
            
            # Join args into a single string for plugin compatibility
            args_string = " ".join(args) if args else ""
            result = plugin.run(args_string, **kwargs)
            return result is not False  # Return True unless explicitly False
            
        except Exception as e:
            print_error(f"Error executing plugin '{plugin_name}': {e}")
            return False
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get plugin information (loads plugin on demand if not already loaded)"""
        # Load the specific plugin if not already loaded
        if plugin_name not in self.plugins:
            if not self.load_plugin(plugin_name):
                return None
        
        return self.plugins[plugin_name].get_info()
    
    def search_plugins(self, search_term: str) -> List[str]:
        """Search for plugins by name (searches available plugins without loading them)"""
        available_plugins = self.list_plugins()
        search_term = search_term.lower()
        matching_plugins = []
        
        for plugin_name in available_plugins:
            if search_term in plugin_name.lower():
                matching_plugins.append(plugin_name)
        
        return matching_plugins
    
    def create_plugin_template(self, plugin_name: str, description: str = "") -> bool:
        """Create a plugin template file"""
        try:
            plugin_file = os.path.join(self.plugins_dir, f"{plugin_name}.py")
            
            if os.path.exists(plugin_file):
                print_warning(f"Plugin file '{plugin_file}' already exists")
                return False
            
            template = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
{plugin_name.title()} Plugin for KittySploit
"""

from kittysploit import *
from core.framework.plugin import Plugin
import shlex

class {plugin_name.title()}Plugin(Plugin):
    """{description or f"{plugin_name.title()} plugin"}"""
    
    __info__ = {{
        "name": "{plugin_name}",
        "description": "{description or f"{plugin_name.title()} plugin"}",
        "version": "1.0.0",
        "author": "Your Name",
        "dependencies": []
    }}
    
    def __init__(self, framework=None):
        super().__init__(framework)
    
    def run(self, *args, **kwargs):
        """Main execution method"""
        parser = ModuleArgumentParser(description=self.__doc__, prog="{plugin_name}")
        parser.add_argument("-e", "--example", dest="example", help="Example argument", metavar="<value>", type=str)
        # Help is automatically added by ModuleArgumentParser
        # You can add standard options with: parser.add_standard_options()
        
        if not args or not args[0]:
            parser.print_help()
            return True
        
        try:
            pargs = parser.parse_args(shlex.split(args[0]))
            
            if getattr(pargs, 'help', False):
                parser.print_help()
                return True
            
            # Your plugin logic here
            print_success(f"{{self.name}} plugin executed!")
            print_info(f"Example value: {{getattr(pargs, 'example', 'None')}}")
            
            return True
            
        except Exception as e:
            print_error(f"Error in {{self.name}} plugin: {{e}}")
            return False
'''
            
            with open(plugin_file, 'w', encoding='utf-8') as f:
                f.write(template)
            
            print_success(f"Created plugin template: {plugin_file}")
            return True
            
        except Exception as e:
            print_error(f"Error creating plugin template: {e}")
            return False
