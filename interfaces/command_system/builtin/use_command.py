#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Use command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_table, table_render_width
from core.framework.option.base_option import Option as BaseOption
from core.utils.privileges import is_root, is_admin
import os
from typing import Any, Dict, Optional


class UseCommand(BaseCommand):
    """Command to select and use a module"""

    SEP_WIDTH = 80
    
    @property
    def name(self) -> str:
        return "use"
    
    @property
    def description(self) -> str:
        return "Select a module for use"
    
    @property
    def usage(self) -> str:
        return "use <module_path|finding_number>"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command selects a module for use. Once selected, you can configure
its options and execute it.

After a `scanner` run, findings are numbered. You can load the module
linked to a finding with:

    use 1
    use 3

Examples:
    use auxiliary/example              # Use the example auxiliary module
    use scanner/http/security_headers_detect
    use 1                              # Load module for scanner finding #1
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the use command"""
        if len(args) == 0:
            print_error("Usage: use <module_path|finding_number>")
            print_info("Use 'search' to find available modules")
            findings = getattr(self.framework, "last_scanner_findings", None) or []
            if findings:
                print_info(f"Or pick a finding from the last scan: use 1..{len(findings)}")
            return False

        plugin_manager = getattr(self.framework, 'plugin_manager', None)
        metasploit_plugin = plugin_manager.get_plugin("metasploit") if plugin_manager else None
        if metasploit_plugin and getattr(metasploit_plugin, "is_integrated_mode_active", lambda: False)():
            # Numeric indices are KittySploit scanner findings, not MSF.
            if not str(args[0]).isdigit():
                return metasploit_plugin.msf_use(args[0])
        
        module_path = args[0]
        finding: Optional[Dict[str, Any]] = None

        if str(module_path).isdigit():
            finding = self._resolve_scanner_finding(int(module_path))
            if finding is None:
                return False
            module_path = str(finding.get("module_path") or "").strip()
            if not module_path:
                module_path = str(finding.get("scanner_path") or "").strip()
            if not module_path:
                print_error(
                    f"Finding #{finding.get('index')} has no linked module path "
                    "(scanner detection only / no exploit module)"
                )
                return False
            print_info(
                f"Finding #{finding.get('index')}: {finding.get('title')}"
            )
            kind = finding.get("module_kind") or "module"
            linked = finding.get("followup_modules") or finding.get("exploit_modules") or []
            if linked and len(linked) > 1:
                print_info(f"Linked modules: {', '.join(linked)}")
            print_info(f"Loading {kind}: {module_path}")
        
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

            if finding:
                self._apply_finding_target(module, finding)
            
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
                    table_kwargs = {
                        "max_width": self.SEP_WIDTH,
                        "expand_to_terminal": True,
                        "prefer_single_line": True,
                    }
                    frame_width = table_render_width(headers, rows, **table_kwargs)
                    print_info("")
                    print_info("Module options:")
                    print_info("=" * frame_width)
                    print_table(headers, rows, **table_kwargs)
                    print_info("=" * frame_width)
                
                if advanced_count > 0:
                    print_info("")
                    print_info(f"({advanced_count} advanced option(s) hidden - use 'show advanced' to view)")
            
            return True
            
        except Exception as e:
            print_error(f"Error loading module '{module_path}': {str(e)}")
            return False

    def _resolve_scanner_finding(self, index: int) -> Optional[Dict[str, Any]]:
        findings = getattr(self.framework, "last_scanner_findings", None) or []
        if not findings:
            print_error("No scanner findings available. Run `scanner` first.")
            return None
        if index < 1 or index > len(findings):
            print_error(f"Invalid finding number {index} (valid: 1..{len(findings)})")
            self._print_findings_hint(findings)
            return None
        return findings[index - 1]

    def _print_findings_hint(self, findings) -> None:
        print_info("Last scan findings:")
        for entry in findings[:15]:
            print_info(
                f"  #{entry.get('index')}: {entry.get('title')} "
                f"[{entry.get('module_path') or 'no module'}]"
            )
        if len(findings) > 15:
            print_info(f"  ... and {len(findings) - 15} more")

    def _apply_finding_target(self, module, finding: Dict[str, Any]) -> None:
        """Pre-fill rhost/port/ssl from the selected scanner finding."""
        host = str(finding.get("host") or "").strip()
        port = finding.get("port")
        scheme = str(finding.get("scheme") or "").strip().lower()
        applied = []
        try:
            if host:
                if hasattr(module, "target"):
                    module.set_option("target", host)
                    applied.append(f"target={host}")
                elif hasattr(module, "rhost"):
                    module.set_option("rhost", host)
                    applied.append(f"rhost={host}")
                elif hasattr(module, "rhosts"):
                    module.set_option("rhosts", host)
                    applied.append(f"rhosts={host}")
            if port is not None and str(port).strip() != "":
                try:
                    port_i = int(port)
                except (TypeError, ValueError):
                    port_i = None
                if port_i is not None:
                    if hasattr(module, "port"):
                        module.set_option("port", port_i)
                        applied.append(f"port={port_i}")
                    elif hasattr(module, "rport"):
                        module.set_option("rport", port_i)
                        applied.append(f"rport={port_i}")
            if scheme in ("http", "https") and hasattr(module, "ssl"):
                module.set_option("ssl", scheme == "https")
                applied.append(f"ssl={scheme == 'https'}")
        except Exception as exc:
            print_warning(f"Could not apply finding target options: {exc}")
            return
        if applied:
            print_success("Target options from finding: " + ", ".join(applied))
