from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import argparse
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

class DebugCommand(BaseCommand):
    """Command to manage debug mode for KittySploit framework"""
    
    @property
    def name(self) -> str:
        return "debug"
    
    @property
    def description(self) -> str:
        return "Debug mode commands for KittySploit framework"
    
    @property
    def usage(self) -> str:
        return "debug <action> [options]"
    
    def _create_parser(self):
        """Create argument parser for debug command"""
        parser = argparse.ArgumentParser(
            prog='debug',
            description='Debug mode commands for KittySploit framework'
        )
        
        subparsers = parser.add_subparsers(dest='action', help='Available debug actions')
        
        # Start subcommand
        start_parser = subparsers.add_parser('start', help='Enable debug mode')
        start_parser.add_argument('--level', choices=['info', 'debug', 'trace'], 
                                default='info', help='Debug level (default: info)')
        start_parser.add_argument('--output', choices=['console', 'file', 'both'], 
                                default='console', help='Output destination')
        start_parser.add_argument('--file', help='Output file path (if output=file or both)')
        
        # Stop subcommand
        stop_parser = subparsers.add_parser('stop', help='Disable debug mode')
        
        # Status subcommand
        status_parser = subparsers.add_parser('status', help='Show debug mode status')
        
        # List subcommand
        list_parser = subparsers.add_parser('list', help='List all debug actions')
        list_parser.add_argument('--filter', help='Filter by action type')
        list_parser.add_argument('--limit', type=int, default=50, help='Limit number of results')
        
        # Execute subcommand
        execute_parser = subparsers.add_parser('execute', help='Execute a specific action')
        execute_parser.add_argument('action_id', help='Action ID to execute')
        
        # Block subcommand
        block_parser = subparsers.add_parser('block', help='Block a specific action')
        block_parser.add_argument('action_id', help='Action ID to block')
        
        # Unblock subcommand
        unblock_parser = subparsers.add_parser('unblock', help='Unblock a specific action')
        unblock_parser.add_argument('action_id', help='Action ID to unblock')
        
        # Clear subcommand
        clear_parser = subparsers.add_parser('clear', help='Clear all debug actions')
        
        # Export subcommand
        export_parser = subparsers.add_parser('export', help='Export actions to file')
        export_parser.add_argument('file', nargs='?', default='debug_actions.json', 
                                 help='Output file path')
        
        # Import subcommand
        import_parser = subparsers.add_parser('import', help='Import actions from file')
        import_parser.add_argument('file', help='Input file path')
        
        # Test subcommand
        test_parser = subparsers.add_parser('test', help='Create test actions')
        test_parser.add_argument('--count', type=int, default=5, help='Number of test actions')
        
        # Web subcommand
        web_parser = subparsers.add_parser('web', help='Launch web debug interface')
        web_parser.add_argument('--port', type=int, default=8080, help='Web interface port')
        web_parser.add_argument('--host', default='127.0.0.1', help='Web interface host')
        
        return parser
    
    def execute(self, args, **kwargs):
        """Execute the debug command"""
        if not args:
            args = ['status']  # Default action
        
        # Check if help is requested (either as --help/-h or as positional "help")
        if '--help' in args or '-h' in args or (len(args) > 0 and args[0] == 'help'):
            try:
                # If "help" is the first argument, replace it with --help for argparse
                if len(args) > 0 and args[0] == 'help':
                    args = ['--help'] + args[1:]
                self._create_parser().parse_args(args)
            except SystemExit:
                # SystemExit is raised by argparse when --help is used
                # This is normal behavior, not an error
                pass
            return True  # Help was displayed successfully
        
        try:
            parsed_args = self._create_parser().parse_args(args)
            
            if parsed_args.action == 'start':
                return self._handle_start(parsed_args)
            elif parsed_args.action == 'stop':
                return self._handle_stop()
            elif parsed_args.action == 'status':
                return self._handle_status()
            elif parsed_args.action == 'list':
                return self._handle_list(parsed_args)
            elif parsed_args.action == 'execute':
                return self._handle_execute(parsed_args)
            elif parsed_args.action == 'block':
                return self._handle_block(parsed_args)
            elif parsed_args.action == 'unblock':
                return self._handle_unblock(parsed_args)
            elif parsed_args.action == 'clear':
                return self._handle_clear()
            elif parsed_args.action == 'export':
                return self._handle_export(parsed_args)
            elif parsed_args.action == 'import':
                return self._handle_import(parsed_args)
            elif parsed_args.action == 'web':
                return self._handle_web(parsed_args)
            else:
                print_error("Unknown action. Use 'debug --help' for usage information.")
                return False
                
        except SystemExit:
            # This shouldn't happen if we handled --help above, but just in case
            return True  # Help was displayed
        except Exception as e:
            print_error(f"Error executing debug command: {e}")
            return False
    
    def _handle_start(self, args):
        """Handle start subcommand"""
        try:
            # Initialize debug manager if not exists
            if not hasattr(self.framework, 'debug_manager'):
                from core.debug_manager import DebugManager
                self.framework.debug_manager = DebugManager()
            
            # Register debug manager with output handler
            from core.output_handler import set_debug_manager
            set_debug_manager(self.framework.debug_manager)
            
            # Start debug mode
            self.framework.debug_manager.start_debug_mode(
                level=args.level,
                output=args.output,
                output_file=args.file
            )
            
            print_success(f"Debug mode started (level: {args.level}, output: {args.output})")
            return True
            
        except Exception as e:
            print_error(f"Failed to start debug mode: {e}")
            return False
    
    def _handle_stop(self):
        """Handle stop subcommand"""
        try:
            if hasattr(self.framework, 'debug_manager'):
                self.framework.debug_manager.stop_debug_mode()
                # Unregister debug manager
                from core.output_handler import set_debug_manager
                set_debug_manager(None)
                print_success("Debug mode stopped")
                return True
            else:
                print_warning("Debug mode is not active")
                return False
                
        except Exception as e:
            print_error(f"Failed to stop debug mode: {e}")
            return False
    
    def _handle_status(self):
        """Handle status subcommand"""
        try:
            if hasattr(self.framework, 'debug_manager'):
                status = self.framework.debug_manager.get_status()
                
                print_info("Debug Mode Status:")
                print_info(f"  Active: {status.get('active', False)}")
                print_info(f"  Level: {status.get('level', 'N/A')}")
                print_info(f"  Output: {status.get('output', 'N/A')}")
                print_info(f"  Actions Captured: {status.get('actions_count', 0)}")
                print_info(f"  Actions Blocked: {status.get('blocked_count', 0)}")
                print_info(f"  Start Time: {status.get('start_time', 'N/A')}")
                return True
            else:
                print_info("Debug mode is not initialized")
                return True  # Not an error, just not initialized
                
        except Exception as e:
            print_error(f"Failed to get debug status: {e}")
            return False
    
    def _handle_list(self, args):
        """Handle list subcommand"""
        try:
            if not hasattr(self.framework, 'debug_manager'):
                print_error("Debug mode is not active")
                return False
            
            actions = self.framework.debug_manager.list_actions(
                filter_type=args.filter,
                limit=args.limit
            )
            
            if not actions:
                print_info("No debug actions found")
                return True
            
            print_info(f"Debug Actions (showing {len(actions)} of {args.limit}):")
            print_info("=" * 80)
            
            for action in actions:
                status = "BLOCKED" if action.get('blocked', False) else "ALLOWED"
                print_info(f"ID: {action['id']:<10} Type: {action['type']:<15} Status: {status}")
                print_info(f"    Time: {action['timestamp']}")
                print_info(f"    Description: {action.get('description', 'N/A')}")
                print_info("")
            
            return True
                
        except Exception as e:
            print_error(f"Failed to list debug actions: {e}")
            return False
    
    def _handle_execute(self, args):
        """Handle execute subcommand"""
        try:
            if not hasattr(self.framework, 'debug_manager'):
                print_error("Debug mode is not active")
                return False
            
            result = self.framework.debug_manager.execute_action(args.action_id)
            
            if result:
                print_success(f"Action {args.action_id} executed successfully")
                print_info(f"Result: {result}")
                return True
            else:
                print_error(f"Failed to execute action {args.action_id}")
                return False
                
        except Exception as e:
            print_error(f"Failed to execute action: {e}")
            return False
    
    def _handle_block(self, args):
        """Handle block subcommand"""
        try:
            if not hasattr(self.framework, 'debug_manager'):
                print_error("Debug mode is not active")
                return False
            
            success = self.framework.debug_manager.block_action(args.action_id)
            
            if success:
                print_success(f"Action {args.action_id} blocked")
                return True
            else:
                print_error(f"Failed to block action {args.action_id}")
                return False
                
        except Exception as e:
            print_error(f"Failed to block action: {e}")
            return False
    
    def _handle_unblock(self, args):
        """Handle unblock subcommand"""
        try:
            if not hasattr(self.framework, 'debug_manager'):
                print_error("Debug mode is not active")
                return False
            
            success = self.framework.debug_manager.unblock_action(args.action_id)
            
            if success:
                print_success(f"Action {args.action_id} unblocked")
                return True
            else:
                print_error(f"Failed to unblock action {args.action_id}")
                return False
                
        except Exception as e:
            print_error(f"Failed to unblock action: {e}")
            return False
    
    def _handle_clear(self):
        """Handle clear subcommand"""
        try:
            if not hasattr(self.framework, 'debug_manager'):
                print_error("Debug mode is not active")
                return False
            
            count = self.framework.debug_manager.clear_actions()
            print_success(f"Cleared {count} debug actions")
            return True
            
        except Exception as e:
            print_error(f"Failed to clear debug actions: {e}")
            return False
    
    def _handle_export(self, args):
        """Handle export subcommand"""
        try:
            if not hasattr(self.framework, 'debug_manager'):
                print_error("Debug mode is not active")
                return False
            
            count = self.framework.debug_manager.export_actions(args.file)
            print_success(f"Exported {count} debug actions to {args.file}")
            return True
            
        except Exception as e:
            print_error(f"Failed to export debug actions: {e}")
            return False
    
    def _handle_import(self, args):
        """Handle import subcommand"""
        try:
            if not hasattr(self.framework, 'debug_manager'):
                print_error("Debug mode is not active")
                return False
            
            count = self.framework.debug_manager.import_actions(args.file)
            print_success(f"Imported {count} debug actions from {args.file}")
            return True
            
        except Exception as e:
            print_error(f"Failed to import debug actions: {e}")
            return False
    
    def _handle_web(self, args):
        """Handle web subcommand"""
        try:
            if not hasattr(self.framework, 'debug_manager'):
                print_error("Debug mode is not active")
                return False
            
            url = self.framework.debug_manager.launch_web_interface(
                host=args.host,
                port=args.port
            )
            
            print_success(f"Web debug interface launched at {url}")
            print_info("Press Ctrl+C to stop the web interface")
            return True
            
        except Exception as e:
            print_error(f"Failed to launch web interface: {e}")
            return False
