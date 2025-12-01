#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Compatible Payloads command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning

class CompatiblePayloadsCommand(BaseCommand):
    """Command to show payloads compatible with current exploit"""
    
    @property
    def name(self) -> str:
        return "compatible_payloads"
    
    @property
    def description(self) -> str:
        return "Show payloads compatible with the current exploit"
    
    @property
    def usage(self) -> str:
        return "compatible_payloads [--detailed]"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

This command shows all payloads that are compatible with the currently selected exploit.
The compatibility is determined based on architecture, platform, handler type, session type, and protocol.

Arguments:
    --detailed      Show detailed compatibility information

Examples:
    compatible_payloads              # Show compatible payloads
    compatible_payloads --detailed   # Show detailed compatibility information

Note: This command only works when an exploit module is selected.
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the compatible payloads command"""
        try:
            # Check if an exploit is selected
            if not hasattr(self.framework, 'current_module') or not self.framework.current_module:
                print_error("No module selected. Use 'use <exploit>' first.")
                return False
            
            # Check if current module is an exploit
            if not hasattr(self.framework.current_module, 'type') or self.framework.current_module.type != 'exploit':
                print_error("Current module is not an exploit. Please select an exploit module first.")
                return False
            
            # Check if exploit has compatibility metadata
            if not hasattr(self.framework.current_module, 'get_compatible_payloads'):
                print_error("Current exploit does not support payload compatibility checking.")
                return False
            
            # Get detailed flag
            detailed = '--detailed' in args
            
            # Get compatible payloads
            compatible_payloads = self.framework.current_module.get_compatible_payloads(self.framework)
            
            if not compatible_payloads:
                print_warning("No compatible payloads found for this exploit.")
                self._show_compatibility_info()
                return True
            
            # Display compatible payloads
            self._show_compatible_payloads(compatible_payloads, detailed)
            
            return True
            
        except Exception as e:
            print_error(f"Error getting compatible payloads: {str(e)}")
            return False
    
    def _show_compatible_payloads(self, payloads, detailed=False):
        """Show compatible payloads"""
        print_success(f"Found {len(payloads)} compatible payload(s) for exploit '{self.framework.current_module.name}':")
        print_info("=" * 80)
        
        if detailed:
            # Detailed view
            print_info(f"{'Path':<40} {'Name':<25} {'Arch':<8} {'Platform':<10} {'Handler':<8}")
            print_info("-" * 80)
            
            for payload in payloads:
                arch = self._format_enum(payload.get('arch'))
                platform = self._format_enum(payload.get('platform'))
                handler = self._format_enum(payload.get('handler'))
                
                print_info(f"{payload['path']:<40} {payload['name']:<25} {arch:<8} {platform:<10} {handler:<8}")
                
                if payload.get('description'):
                    print_info(f"  {'':40} {payload['description']}")
                print_info("")
        else:
            # Simple view
            for payload in payloads:
                arch = self._format_enum(payload.get('arch'))
                platform = self._format_enum(payload.get('platform'))
                handler = self._format_enum(payload.get('handler'))
                
                print_info(f"  {payload['path']:<40} {payload['name']} ({arch}/{platform}/{handler})")
                
                if payload.get('description'):
                    print_info(f"    {payload['description']}")
        
        print_info("")
        print_info("Use 'set payload <path>' to select a payload")
        print_info("Use 'compatible_payloads --detailed' for detailed information")
    
    def _show_compatibility_info(self):
        """Show compatibility information for current exploit"""
        exploit = self.framework.current_module
        exploit_info = exploit.__info__
        
        print_info("Exploit compatibility requirements:")
        print_info("=" * 50)
        
        if exploit_info.get('arch'):
            arch_value = exploit_info['arch']
            if isinstance(arch_value, list):
                archs = [self._format_enum(arch) for arch in arch_value]
            else:
                archs = [self._format_enum(arch_value)]
            print_info(f"Architectures: {', '.join(archs)}")
        
        if exploit_info.get('platform'):
            platform_value = exploit_info['platform']
            if isinstance(platform_value, list):
                platforms = [self._format_enum(platform) for platform in platform_value]
            else:
                platforms = [self._format_enum(platform_value)]
            print_info(f"Platforms: {', '.join(platforms)}")
        
        if exploit_info.get('handler'):
            handler_value = exploit_info['handler']
            if isinstance(handler_value, list):
                handlers = [self._format_enum(handler) for handler in handler_value]
            else:
                handlers = [self._format_enum(handler_value)]
            print_info(f"Handlers: {', '.join(handlers)}")
        
        if exploit_info.get('session_type'):
            session_value = exploit_info['session_type']
            if isinstance(session_value, list):
                sessions = [self._format_enum(session) for session in session_value]
            else:
                sessions = [self._format_enum(session_value)]
            print_info(f"Session Types: {', '.join(sessions)}")
        
        if exploit_info.get('protocol'):
            protocol_value = exploit_info['protocol']
            if isinstance(protocol_value, list):
                protocols = [self._format_enum(protocol) for protocol in protocol_value]
            else:
                protocols = [self._format_enum(protocol_value)]
            print_info(f"Protocols: {', '.join(protocols)}")
    
    def _format_enum(self, enum_value):
        """Format enum value for display"""
        if enum_value is None:
            return "N/A"
        
        if hasattr(enum_value, 'value'):
            return enum_value.value
        elif hasattr(enum_value, 'name'):
            return enum_value.name.lower()
        else:
            return str(enum_value)
