from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import argparse
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

class CollabConnectCommand(BaseCommand):
    """Command to connect to a KittySploit collaboration server"""
    
    @property
    def name(self) -> str:
        return "collab_connect"
    
    @property
    def description(self) -> str:
        return "Connect to a KittySploit collaboration server"
    
    @property
    def usage(self) -> str:
        return "collab_connect <host> [--port PORT] [-P PASSWORD] [-u USERNAME] [-w WORKSPACE] [-v]"
    
    def _create_parser(self):
        """Create argument parser for collab_connect command"""
        parser = argparse.ArgumentParser(
            prog='collab_connect',
            description='Connect to a KittySploit collaboration server'
        )
        
        parser.add_argument('host', help='Server host address')
        parser.add_argument('--port', type=int, default=8080,
                          help='Server port (default: 8080)')
        parser.add_argument('-P', '--password', 
                          help='Server password (if required)')
        parser.add_argument('-u', '--username', default='Anonymous',
                          help='Your username (default: Anonymous)')
        parser.add_argument('-w', '--workspace', default='default',
                          help='Workspace name (default: default)')
        parser.add_argument('-v', '--verbose', action='store_true',
                          help='Enable verbose output')
        
        return parser
    
    def execute(self, args, **kwargs):
        """Execute the collab_connect command"""
        if not args:
            print_error("Host address is required. Use 'collab_connect --help' for usage information.")
            return False
        
        try:
            parsed_args = self._create_parser().parse_args(args)
            return self._connect_to_server(parsed_args)
        except SystemExit:
            return False
        except Exception as e:
            print_error(f"Error connecting to collaboration server: {e}")
            return False
    
    def _connect_to_server(self, args):
        """Connect to the collaboration server"""
        try:
            # Import the simple collaboration client
            from core.collab_client_simple import SimpleCollaborationClient
            
            # Create client instance
            client = SimpleCollaborationClient(
                host=args.host,
                port=args.port,
                password=args.password,
                username=args.username,
                workspace=args.workspace,
                verbose=args.verbose,
                framework=self.framework
            )
            
            # Connect to server
            if client.connect():
                # Store client reference in framework
                self.framework.collab_client = client
                
                # Change workspace context
                self.framework.current_collab = args.workspace
                
                print_success(f"Connected to collaboration server at {args.host}:{args.port}")
                print_info(f"Username: {args.username}")
                print_info(f"Workspace: {args.workspace}")
                print_info("Use 'collab_chat' to open the chat interface")
                print_info("Use 'collab_disconnect' to disconnect")
                
                return True
            else:
                print_error("Failed to connect to collaboration server")
                return False
            
        except Exception as e:
            print_error(f"Failed to connect to collaboration server: {e}")
            return False
