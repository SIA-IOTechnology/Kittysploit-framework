#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import shlex

class RouterPlugin(Plugin):
    """Plugin to load and start all modules tagged with 'router'"""
    
    __info__ = {
        "name": "router",
        "description": "The router plugin loads and starts all modules with the 'router' tag",
        "version": "1.0.0",
        "author": "KittySploit Team",
        "dependencies": []
    }
    
    def __init__(self, framework=None):
        super().__init__(framework)
        self.modules = {}
        self.router_modules = []
    
    def list_modules(self):
        """List all modules with the 'router' tag"""
        list_router = {}
        
        # Get module loader from framework
        if not self.framework:
            print_error("Framework not available")
            return []
        
        # Discover all modules
        self.modules = self.framework.module_loader.discover_modules()
        
        # Iterate through all modules
        for module_path in self.modules:
            try:
                # Load the module to get its info
                module = self.framework.module_loader.load_module(module_path, load_only=True, framework=self.framework)
                
                if module and hasattr(module, '__info__'):
                    info = module.__info__
                    
                    # Check for 'tags' or 'plugins' field in __info__
                    tags = []
                    if 'tags' in info:
                        tags = info['tags'] if isinstance(info['tags'], list) else [info['tags']]
                    elif 'plugins' in info:
                        tags = info['plugins'] if isinstance(info['plugins'], list) else [info['plugins']]
                    
                    # Check if 'router' is in the tags
                    if "router" in tags:
                        list_router[module_path] = tags
                        
            except Exception as e:
                # Silently skip modules that can't be loaded
                continue
        
        # Sort by tags
        self.router_modules = sorted(list_router.items(), key=lambda t: str(t[1]))
        return self.router_modules
    
    def run(self, *args, **kwargs):
        """Main execution method for the router plugin"""
        parser = ModuleArgumentParser(description=self.__doc__, prog="router")
        parser.add_argument("-l", "--list", action="store_true", dest="list", help="List all modules with the 'router' tag")
        parser.add_argument("-t", "--target", dest="target", help="Target to use when starting router modules", metavar="<target>")
        
        # Handle empty args
        if not args or not args[0]:
            parser.print_help()
            return True
        
        try:
            # Parse arguments - args[0] should be a string
            args_string = args[0] if isinstance(args[0], str) else " ".join(args)
            pargs = parser.parse_args(shlex.split(args_string))
            
            if getattr(pargs, 'help', False):
                parser.print_help()
                return True
            
            if pargs.list:
                print_success("Loading modules with 'router' tag...")
                router_list = self.list_modules()
                
                if not router_list:
                    print_warning("No modules found with the 'router' tag")
                    return True
                
                print_info(f"\nFound {len(router_list)} module(s) with 'router' tag:\n")
                
                for module_path, tags in router_list:
                    try:
                        module = self.framework.module_loader.load_module(module_path, load_only=True, framework=self.framework)
                        if module:
                            print_status(f"  {module_path}")
                            if hasattr(module, 'name') and module.name:
                                print_info(f"    Name: {module.name}")
                            if hasattr(module, 'description') and module.description:
                                print_info(f"    Description: {module.description}")
                            print_info(f"    Tags: {', '.join(tags) if isinstance(tags, list) else tags}")
                    except Exception as e:
                        print_warning(f"  {module_path} (error loading: {str(e)})")
                
                print_status(f"\nTotal: {len(router_list)} module(s) found")
                return True
            
            if pargs.target:
                print_success(f"Starting all modules with 'router' tag against target: {pargs.target}")
                router_list = self.list_modules()
                
                if not router_list:
                    print_warning("No modules found with the 'router' tag")
                    return True
                
                for module_path, tags in router_list:
                    try:
                        print_info(f"\nStarting module: {module_path}")
                        module = self.framework.module_loader.load_module(module_path, load_only=False, framework=self.framework)
                        
                        if module:
                            # Set target
                            if hasattr(module, 'rhost'):
                                module.set_option('rhost', pargs.target)
                            elif hasattr(module, 'target'):
                                module.set_option('target', pargs.target)
                            
                            # Check if module has required options
                            if hasattr(module, 'check_options'):
                                if not module.check_options():
                                    print_warning(f"  Module {module_path} is missing required options, skipping...")
                                    continue
                            
                            # Run the module
                            if hasattr(module, 'run'):
                                result = module.run()
                                if result:
                                    print_success(f"Module {module_path} executed successfully")
                                else:
                                    print_warning(f"Module {module_path} execution returned False")
                            else:
                                print_warning(f"Module {module_path} does not have a run() method")
                        else:
                            print_error(f"Failed to load module {module_path}")
                    except Exception as e:
                        print_error(f"  Error starting module {module_path}: {str(e)}")
                
                return True
            
            # If no action specified, show help
            parser.print_help()
            return True
            
        except Exception as e:
            print_error(f"An error occurred: {e}")
            import traceback
            print_debug(traceback.format_exc())
            return False

