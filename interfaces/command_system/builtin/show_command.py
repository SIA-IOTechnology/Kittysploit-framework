#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Show command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_table, print_empty
from core.framework.option.base_option import Option as BaseOption
import os
import logging
from typing import Optional, List

class ShowCommand(BaseCommand):
    """Command to show module information"""
    
    MODULE_TYPE_ALIASES = {
        "module": None,
        "modules": None,
        "exploit": "exploit",
        "exploits": "exploit",
        "aux": "auxiliary",
        "auxiliary": "auxiliary",
        "payload": "payload",
        "payloads": "payload",
        "post": "post",
        "listener": "listener",
        "listeners": "listener",
        "encoder": "encoder",
        "encoders": "encoder",
        "workflow": "workflow",
        "workflows": "workflow",
        "docker": "docker_environment",
        "environment": "docker_environment",
        "environments": "docker_environment",
        "docker_environment": "docker_environment",
        "docker_environments": "docker_environment",
    }
    
    MODULE_PATH_PREFIXES = [
        ("exploits/", "exploit"),
        ("auxiliary/", "auxiliary"),
        ("payloads/", "payload"),
        ("post/", "post"),
        ("listeners/", "listener"),
        ("encoders/", "encoder"),
        ("workflow/", "workflow"),
        ("docker_environments/", "docker_environment"),
        ("browser_exploits/", "browser_exploit"),
        ("browser_auxiliary/", "browser_auxiliary"),
        ("backdoors/", "backdoor"),
    ]
    
    @property
    def name(self) -> str:
        return "show"
    
    @property
    def description(self) -> str:
        return "Show module information and options"
    
    @property
    def usage(self) -> str:
        return "show [options|advanced|info|modules|exploits|auxiliary|payloads|post|listeners|docker]"
    
    def get_subcommands(self) -> List[str]:
        """Get available subcommands for auto-completion"""
        subcommands = [
            "info",
            "modules",
            "exploits",
            "auxiliary",
            "aux",  # alias
            "payloads",
            "payload",  # alias
            "post",
            "postmodules",  # alias
            "listeners",
            "listener",  # alias
            "encoders",
            "encoder",  # alias
            "workflows",
            "workflow",  # alias
            "docker",
            "environment",  # alias
            "environments",  # alias
            "nops",
            "workspaces",
        ]
        
        # Add module-specific options if a module is loaded
        if hasattr(self.framework, 'current_module') and self.framework.current_module:
            subcommands.insert(0, "options")
            subcommands.insert(1, "advanced")
        
        return subcommands
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command shows information about modules, listeners, and other framework components.

Arguments:
    options        Show current module options
    advanced       Show only advanced module options
    info           Show current module information (default)
    modules        Show all available modules
    exploits       Show exploit modules
    auxiliary      Show auxiliary modules
    payloads       Show payload modules
    post           Show post-exploitation modules
    listeners      Show available listeners
    docker         Show Docker environment modules
    nops           Show available NOP types
    workspaces     Show available workspaces

Examples:
    show                    # Show current module information
    show options            # Show current module options
    show advanced           # Show only advanced options
    show modules            # List all available modules
    show exploits           # List exploit modules
    show docker             # List Docker environments
    show listeners          # List all available listeners
    show nops               # Show available NOP types
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the show command"""
        show_type = args[0] if args else "info"
        
        try:
            show_type = show_type.lower()
            if show_type == "options":
                if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
                    print_error("No module selected. Use 'use <module>' first.")
                    return False
                self._show_options(self.framework.current_module, show_advanced=False)
            elif show_type == "advanced":
                if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
                    print_error("No module selected. Use 'use <module>' first.")
                    return False
                self._show_advanced_options(self.framework.current_module)
            elif show_type == "info":
                if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
                    print_error("No module selected. Use 'use <module>' first.")
                    return False
                self._show_info(self.framework.current_module)
            elif show_type == "modules":
                self._show_modules()
            elif show_type in ("exploit", "exploits"):
                self._show_modules_by_category("Exploit", "exploit")
            elif show_type in ("aux", "auxiliary"):
                self._show_modules_by_category("Auxiliary", "auxiliary")
            elif show_type in ("payload", "payloads"):
                self._show_modules_by_category("Payload", "payload")
            elif show_type in ("post", "postmodules"):
                self._show_modules_by_category("Post-exploitation", "post")
            elif show_type in ("listener", "listeners"):
                self._show_listeners()
            elif show_type in ("encoder", "encoders"):
                self._show_modules_by_category("Encoder", "encoder")
            elif show_type in ("workflow", "workflows"):
                self._show_modules_by_category("Workflow", "workflow")
            elif show_type in ("docker", "environment", "environments"):
                self._show_modules_by_category("Docker environment", "docker_environment")
            elif show_type == "nops":
                self._show_nops()
            elif show_type == "workspaces":
                self._show_workspaces()
            else:
                print_error(f"Unknown show type: {show_type}")
                print_info("Use 'show options', 'show advanced', 'show info', 'show modules', 'show listeners', 'show nops', or 'show workspaces'")
                return False
            
            return True
            
        except Exception as e:
            print_error(f"Error showing information: {str(e)}")
            return False
    
    def _show_info(self, module):
        """Show module information"""
        print_info(f"Module: {module.name}")
        module_type = getattr(module, 'type', getattr(module, '_type', 'module'))
        print_info(f"Type: {module_type}")
        print_info(f"Description: {module.description}")
        print_info(f"Author: {module.author}")
        
        if module.references:
            print_info(f"References: {', '.join(module.references)}")
        
        if module.requires_root:
            print_warning("This module requires root privileges")
        
        if hasattr(module, 'cve') and module.cve:
            print_info(f"CVE: {module.cve}")
        
        # Try to load and display doc.md if available
        doc_content = self._load_module_doc(module)
        if doc_content:
            print_empty()
            print_info("=" * 70)
            print_info("Documentation:")
            print_info("=" * 70)
            print_info(doc_content)
            print_info("=" * 70)
    
    def _load_module_doc(self, module) -> Optional[str]:
        """Load doc.md for a module"""
        try:
            # Get module path
            module_path = getattr(module, 'name', '')
            if not module_path:
                return None
            
            # Check if it's a marketplace module
            if module_path.startswith("modules/marketplace/"):
                return self._load_extension_doc(module_path)
            
            # For regular modules, look in modules directory
            module_file = os.path.join("modules", module_path.replace("/", os.sep) + ".py")
            if os.path.exists(module_file):
                module_dir = os.path.dirname(module_file)
                doc_file = os.path.join(module_dir, "doc.md")
                if os.path.exists(doc_file):
                    with open(doc_file, 'r', encoding='utf-8') as f:
                        return f.read()
            
            return None
        except Exception as e:
            logging.debug(f"Could not load doc.md: {e}")
            return None
    
    def _load_extension_doc(self, module_path: str) -> Optional[str]:
        """Load doc.md for a marketplace module"""
        try:
            # Check if this is a marketplace module (modules/marketplace/<type>/<module_id>)
            if not module_path.startswith("modules/marketplace/"):
                return None
            
            # Extract module path components
            rel_path = module_path.replace("modules/marketplace/", "")
            parts = rel_path.split("/")
            
            if len(parts) < 2:
                return None
            
            module_type = parts[0]
            module_id = parts[1]
            
            # Build path to module directory
            module_dir = os.path.join("modules", "marketplace", module_type, module_id)
            
            if not os.path.exists(module_dir):
                return None
            
            # Look for latest version or any version
            version_dirs = []
            for item in os.listdir(module_dir):
                item_path = os.path.join(module_dir, item)
                if os.path.isdir(item_path):
                    version_dirs.append((item, item_path))
            
            version_dirs.sort(key=lambda x: (x[0] != "latest", x[0]))
            
            if not version_dirs:
                version_dirs = [("", module_dir)]
            
            # Try each version directory
            for version_name, version_dir in version_dirs:
                doc_file = os.path.join(version_dir, "doc.md")
                if os.path.exists(doc_file):
                    with open(doc_file, 'r', encoding='utf-8') as f:
                        return f.read()
            
            return None
        except Exception as e:
            logging.debug(f"Could not load marketplace module doc.md: {e}")
            return None
    
    def _show_options(self, module, show_advanced=False):
        """Show module options (excluding advanced by default)"""
        options = module.get_options()
        
        if not options:
            print_info("No options available for this module")
            return
        
        # Filter out advanced options if not requested
        filtered_options = {}
        advanced_count = 0
        for name, option_data in options.items():
            if len(option_data) >= 4:
                default, required, description, advanced = option_data[:4]
                if not advanced or show_advanced:
                    filtered_options[name] = option_data
                elif advanced:
                    advanced_count += 1
        
        if not filtered_options:
            print_info("No options available for this module")
            if advanced_count > 0:
                print_info(f"({advanced_count} advanced option(s) hidden - use 'show advanced' to view)")
            return
        
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
                
                # Format description (add advanced marker if needed)
                desc_text = description
                if advanced:
                    desc_text += " (advanced)"
                
                # Name should never be truncated - it's needed for 'set' command
                rows.append([name, value_str, req_text, desc_text])
        
        # Display table
        print_info()
        print_info("Module options:")
        print_info("=" * 120)
        # Use larger max_width to allow full descriptions to be displayed
        print_table(headers, rows, max_width=120)
        print_info("=" * 120)
        
        if advanced_count > 0 and not show_advanced:
            print_info()
            print_info(f"({advanced_count} advanced option(s) hidden - use 'show advanced' to view)")
        
        print_info()
        print_info("Use 'set <option> <value>' to set option values")
    
    def _show_advanced_options(self, module):
        """Show only advanced module options"""
        options = module.get_options()
        
        if not options:
            print_info("No options available for this module")
            return
        
        # Filter for advanced options only
        advanced_options = {}
        for name, option_data in options.items():
            if len(option_data) >= 4:
                default, required, description, advanced = option_data[:4]
                if advanced:  # Only include advanced options
                    advanced_options[name] = option_data
        
        if not advanced_options:
            print_info("No advanced options available for this module")
            print_info("Use 'show options' to see all options")
            return
        
        # Prepare table data
        headers = ["Name", "Current Setting", "Required", "Description"]
        rows = []
        
        for name, option_data in advanced_options.items():
            if len(option_data) >= 4:
                default, required, description, advanced = option_data[:4]
                # Get option object from class to avoid triggering __get__ for OptFile and OptPayload
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
        print_info("Advanced module options:")
        print_info("=" * 120)
        # Use larger max_width to allow full descriptions to be displayed
        print_table(headers, rows, max_width=120)
        print_info("=" * 120)
        print_info("")
        print_info("Use 'set <option> <value>' to set option values")
    
    def _show_modules(self):
        """Show all available modules"""
        modules = self._get_modules()
        if not modules:
            print_info("No modules found")
            return
        
        # Organize modules by type
        categories = {}
        for module in modules:
            module_type = self._normalize_module_type(module.get('type', 'other')) or 'other'
            if module_type not in categories:
                categories[module_type] = []
            categories[module_type].append(module)
        
        for category in sorted(categories.keys()):
            heading = f"[{category.upper()}] ({len(categories[category])})"
            self._print_module_table(categories[category], heading)

    def _show_modules_by_category(self, label: str, module_type: str):
        """Show modules filtered by a specific category"""
        normalized_type = self._normalize_module_type(module_type)
        modules = self._get_modules(normalized_type)
        
        if not modules:
            print_info(f"No {label.lower()} modules found")
            return
        
        heading = f"{label} modules ({len(modules)})"
        self._print_module_table(modules, heading, include_type=False)
    
    def _get_modules(self, module_type: str = None):
        """Retrieve modules from DB or filesystem with optional type filtering"""
        normalized_type = self._normalize_module_type(module_type)
        modules = []
        try:
            modules = self.framework.search_modules_db(
                module_type=normalized_type or "",
                limit=1000
            )
        except Exception as e:
            print_info(f"Database search failed: {e}")
            modules = []
        
        if not modules:
            modules = self._search_modules_filesystem(normalized_type)
        elif normalized_type:
            modules = [m for m in modules if self._module_matches_type(m, normalized_type)]
        
        return modules or []
    
    def _search_modules_filesystem(self, module_type_filter: str = None):
        """Search modules from filesystem as fallback"""
        modules = []
        try:
            discovered_modules = self.framework.module_loader.discover_modules()
            
            for module_path, file_path in discovered_modules.items():
                module_type = self._detect_module_type(module_path)
                if module_type_filter and not self._type_matches(module_type, module_type_filter):
                    continue
                
                # Try to get module info (silently to avoid error spam during discovery)
                try:
                    module_info = self.framework.module_loader.get_module_info(module_path, silent=True)
                    if module_info:
                        modules.append({
                            'path': module_path,
                            'name': module_info.get('name', module_path),
                            'description': module_info.get('description', 'No description'),
                            'type': module_type,
                            'author': module_info.get('author', 'Unknown')
                        })
                    else:
                        # Module exists but couldn't be loaded (likely missing dependencies)
                        # Add it to the list anyway but mark it
                        modules.append({
                            'path': module_path,
                            'name': module_path,
                            'description': 'No description (missing dependencies)',
                            'type': module_type,
                            'author': 'Unknown'
                        })
                except Exception:
                    # If we can't load the module, just add basic info
                    modules.append({
                        'path': module_path,
                        'name': module_path,
                        'description': 'No description',
                        'type': module_type,
                        'author': 'Unknown'
                    })
        except Exception as e:
            print_info(f"Error searching filesystem: {e}")
        
        return modules
    
    def _show_listeners(self):
        """Show all available listeners"""
        listeners = self._get_modules("listener")
        
        if not listeners:
            print_info("No listeners found")
            return
        
        # Organize by subcategory
        categories = {}
        for listener in listeners:
            parts = (listener.get('path') or "").split('/')
            subcategory = parts[2] if len(parts) >= 3 else 'other'
            
            if subcategory not in categories:
                categories[subcategory] = []
            categories[subcategory].append(listener)
        
        for category in sorted(categories.keys()):
            heading = f"[LISTENER:{category.upper()}] ({len(categories[category])})"
            self._print_module_table(categories[category], heading, include_type=False)
    
    def _show_nops(self):
        """Show available NOP types"""
        available = self.framework.nops.list_available()
        
        print_info("Available NOP types:")
        print_info("=" * 40)
        
        for arch, types in available.items():
            print_info(f"\n[{arch.upper()}]")
            for nop_type in types:
                info = self.framework.nops.get_info(arch, nop_type)
                print_info(f"  {nop_type:<15} {info}")
    
    def _show_workspaces(self):
        """Show available workspaces"""
        workspaces = self.framework.workspace_manager.list_workspaces()
        
        if not workspaces:
            print_info("No workspaces found")
            return
        
        print_info("Available workspaces:")
        print_info("=" * 50)
        
        current_workspace = self.framework.workspace_manager.get_current_workspace()
        
        for workspace in workspaces:
            status = " (current)" if current_workspace and current_workspace.name == workspace.name else ""
            print_info(f"{workspace.name:<20} {workspace.description or 'No description'}{status}")
    
    def _print_module_table(self, modules, heading: str, include_type: bool = False):
        """Render module information focusing on path + description"""
        if not modules:
            print_info(f"{heading}: no entries")
            return
        
        headers = ["Path", "Description"]
        rows = []
        for module in sorted(modules, key=lambda x: x.get('path', '')):
            path = str(module.get('path', '-')).replace("\n", " ").strip()
            description = str(module.get('description', 'No description')).replace("\n", " ").strip()
            if include_type:
                module_type = self._normalize_module_type(module.get('type', 'other')) or 'other'
                rows.append([f"{path} ({module_type})", description])
            else:
                rows.append([path, description])
        
        # Use print_table which handles terminal width and description truncation
        print_info("")
        print_info(heading)
        print_table(headers, rows, max_width=120)
    
    def _normalize_module_type(self, module_type: str):
        if not module_type:
            return None
        return self.MODULE_TYPE_ALIASES.get(module_type.lower(), module_type.lower())
    
    def _module_matches_type(self, module: dict, module_type: str) -> bool:
        target = self._normalize_module_type(module_type)
        if not target:
            return True
        
        module_type_value = self._normalize_module_type(module.get('type'))
        if module_type_value == target:
            return True
        
        detected = self._detect_module_type(module.get('path', ''))
        return self._type_matches(detected, target)
    
    def _detect_module_type(self, module_path: str) -> str:
        path = (module_path or "").lower()
        for prefix, module_type in self.MODULE_PATH_PREFIXES:
            if path.startswith(prefix):
                return module_type
        return 'other'
    
    def _type_matches(self, current_type: str, target_type: str) -> bool:
        current = self._normalize_module_type(current_type)
        target = self._normalize_module_type(target_type)
        return (current or 'other') == (target or 'other')
