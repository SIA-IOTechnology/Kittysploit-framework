#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import argparse
from typing import Dict, List, Any, Optional

class TorCommand(BaseCommand):
    """Command to manage Tor network connectivity"""
    
    @property
    def name(self) -> str:
        return "tor"
    
    @property
    def description(self) -> str:
        return "Manage Tor network connectivity for the framework"
    
    @property
    def usage(self) -> str:
        return "tor [enable|disable|status|check] [options]"
    
    def get_subcommands(self) -> List[str]:
        """Get available subcommands for auto-completion"""
        return ['enable', 'disable', 'status', 'check']
    
    def _create_parser(self):
        """Create argument parser for tor command"""
        parser = argparse.ArgumentParser(
            prog='tor',
            description='Manage Tor network connectivity for the framework'
        )
        
        subparsers = parser.add_subparsers(dest='action', help='Available actions')
        
        # Enable Tor
        enable_parser = subparsers.add_parser('enable', help='Enable Tor network')
        enable_parser.add_argument('--host', default='127.0.0.1',
                                  help='Tor SOCKS proxy host (default: 127.0.0.1)')
        enable_parser.add_argument('--socks-port', type=int, default=None,
                                  help='Tor SOCKS proxy port (default: 9050, auto-detect if not specified)')
        enable_parser.add_argument('--control-port', type=int, default=None,
                                  help='Tor Control port (default: 9051)')
        enable_parser.add_argument('--no-check', action='store_true',
                                  help='Do not check if Tor is available before enabling')
        enable_parser.add_argument('--no-save', action='store_true',
                                  help='Do not save configuration to config file')
        
        # Disable Tor
        disable_parser = subparsers.add_parser('disable', help='Disable Tor network')
        disable_parser.add_argument('--no-save', action='store_true',
                                   help='Do not save configuration to config file')
        
        # Status
        status_parser = subparsers.add_parser('status', help='Show Tor status')
        
        # Check Tor availability
        check_parser = subparsers.add_parser('check', help='Check if Tor is available')
        check_parser.add_argument('--host', default='127.0.0.1',
                                help='Tor SOCKS proxy host to check (default: 127.0.0.1)')
        check_parser.add_argument('--port', type=int, default=None,
                                help='Tor SOCKS proxy port to check (default: 9050)')
        
        return parser
    
    def execute(self, args, **kwargs):
        """Execute the tor command"""
        if not args:
            args = ['--help']
        
        try:
            parsed_args = self._create_parser().parse_args(args)
            return self._handle_action(parsed_args)
        except SystemExit:
            return True
        except Exception as e:
            print_error(f"Error executing tor command: {e}")
            return False
    
    def _handle_action(self, args):
        """Handle the specific action"""
        if not args.action:
            print_error("No action specified. Use 'tor --help' for usage information.")
            return False
        
        framework = self.framework
        
        if not hasattr(framework, 'tor_manager'):
            print_error("Tor manager not available in framework")
            return False
        
        if args.action == 'enable':
            return self._enable_tor(framework, args)
        elif args.action == 'disable':
            return self._disable_tor(framework, args)
        elif args.action == 'status':
            return self._show_status(framework)
        elif args.action == 'check':
            return self._check_tor(framework, args)
        else:
            print_error(f"Unknown action: {args.action}")
            return False
    
    def _enable_tor(self, framework, args):
        """Enable Tor network"""
        try:
            check_availability = not args.no_check
            save_config = not args.no_save
            
            result = framework.enable_tor(
                host=args.host,
                socks_port=args.socks_port,
                control_port=args.control_port,
                check_availability=check_availability,
                save_config=save_config
            )
            
            if result:
                print_success("Tor network enabled successfully")
                print_info("All framework network operations will now route through Tor")
                return True
            else:
                print_error("Failed to enable Tor network")
                print_info("Make sure Tor is running (tor daemon or Tor Browser)")
                return False
        except Exception as e:
            print_error(f"Error enabling Tor: {e}")
            return False
    
    def _disable_tor(self, framework, args):
        """Disable Tor network"""
        try:
            save_config = not args.no_save
            framework.disable_tor(save_config=save_config)
            print_success("Tor network disabled")
            return True
        except Exception as e:
            print_error(f"Error disabling Tor: {e}")
            return False
    
    def _show_status(self, framework):
        """Show Tor status"""
        try:
            status = framework.get_tor_status()
            
            print_info("=" * 60)
            print_info("Tor Network Status")
            print_info("=" * 60)
            
            enabled = status.get('enabled', False)
            print_info(f"Enabled: {'Yes' if enabled else 'No'}")
            
            if enabled:
                print_info(f"SOCKS Proxy: {status.get('socks_host', 'N/A')}:{status.get('socks_port', 'N/A')}")
                print_info(f"Control Port: {status.get('control_host', 'N/A')}:{status.get('control_port', 'N/A')}")
                print_info(f"Proxy URL: {status.get('proxy_url', 'N/A')}")
                
                # Test connection
                connection_test = status.get('connection_test', False)
                available = status.get('available', False)
                
                print_info(f"Available: {'Yes' if available else 'No'}")
                print_info(f"Connection Test: {'Passed' if connection_test else 'Failed'}")
                
                if not available:
                    print_warning("Tor SOCKS proxy is not available")
                    print_info("Make sure Tor is running")
                elif not connection_test:
                    print_warning("Tor connection test failed")
                    print_info("Tor may be running but not properly configured")
            else:
                print_info("Tor is currently disabled")
                print_info("Use 'tor enable' to enable Tor network")
            
            print_info("=" * 60)
            return True
        except Exception as e:
            print_error(f"Error getting Tor status: {e}")
            return False
    
    def _check_tor(self, framework, args):
        """Check if Tor is available"""
        try:
            port = args.port or 9050
            available = framework.check_tor_available(args.host, port)
            
            if available:
                print_success(f"Tor SOCKS proxy is available on {args.host}:{port}")
                return True
            else:
                print_warning(f"Tor SOCKS proxy is not available on {args.host}:{port}")
                print_info("Make sure Tor is running:")
                print_info("  - Tor daemon: service tor start (Linux) or brew services start tor (macOS)")
                print_info("  - Tor Browser: Start Tor Browser")
                print_info("  - Check if Tor is listening on port 9050 (daemon) or 9150 (Tor Browser)")
                return False
        except Exception as e:
            print_error(f"Error checking Tor availability: {e}")
            return False
