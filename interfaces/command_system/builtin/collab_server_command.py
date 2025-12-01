from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import argparse
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

class CollabServerCommand(BaseCommand):
    """Command to start a collaboration server for KittySploit framework"""
    
    @property
    def name(self) -> str:
        return "collab_server"
    
    @property
    def description(self) -> str:
        return "Start server for collaboration between multiple KittySploit instances"
    
    @property
    def usage(self) -> str:
        return "collab_server [--host HOST] [-p PORT] [-P PASSWORD] [-w WORKSPACE] [-v]"
    
    def _create_parser(self):
        """Create argument parser for collab_server command"""
        parser = argparse.ArgumentParser(
            prog='collab_server',
            description='Start server for collaboration between multiple KittySploit instances'
        )
        
        parser.add_argument('--host', default='127.0.0.1', 
                          help='Host address to listen on (default: 127.0.0.1)')
        parser.add_argument('-p', '--port', type=int, default=8080,
                          help='Port to listen on (default: 8080)')
        parser.add_argument('-P', '--password', 
                          help='Password for authentication (optional)')
        parser.add_argument('-w', '--workspace', default='default',
                          help='Workspace name (default: default)')
        parser.add_argument('-v', '--verbose', action='store_true',
                          help='Enable verbose output')
        
        return parser
    
    def execute(self, args, **kwargs):
        """Execute the collab_server command"""
        if not args:
            args = ['--help']
        
        # Handle stop command
        if args[0] == 'stop':
            return self._stop_server()
        
        try:
            parsed_args = self._create_parser().parse_args(args)
            return self._start_server(parsed_args)
        except SystemExit:
            return False
        except Exception as e:
            print_error(f"Error starting collaboration server: {e}")
            return False
    
    def _start_server(self, args):
        """Start the collaboration server"""
        try:
            # Import the simple collaboration server
            from core.collab_server_simple import SimpleCollaborationServer
            
            # Create server instance
            server = SimpleCollaborationServer(
                host=args.host,
                port=args.port,
                password=args.password,
                workspace=args.workspace,
                verbose=args.verbose,
                framework=self.framework
            )
            
            # Start server in a separate thread
            server_thread = threading.Thread(target=server.start, daemon=True)
            server_thread.start()
            
            # Give server time to start
            time.sleep(0.5)
            
            # Store server reference in framework
            self.framework.collab_server = server
            
            # Register as a background job
            try:
                from core.job_manager import global_job_manager
                job_id = global_job_manager.add_job(
                    name=f"collab_server on {args.host}:{args.port}",
                    description=f"Collaboration server: {args.host}:{args.port} (workspace: {args.workspace})",
                    target=f"{args.host}:{args.port}",
                    module=server
                )
                if job_id:
                    # Store job_id in server for later reference
                    server.job_id = job_id
            except Exception as e:
                # Job registration is optional, don't fail if it doesn't work
                pass
            
            print_success(f"Collaboration server started on {args.host}:{args.port}")
            print_info(f"Workspace: {args.workspace}")
            if args.password:
                print_info("Authentication: Enabled")
            else:
                print_warning("Authentication: Disabled (anyone can connect)")
            
            print_info("Server is running in background. Use 'collab_server stop' to stop it.")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to start collaboration server: {e}")
            return False
    
    def _stop_server(self):
        """Stop the collaboration server"""
        try:
            if not hasattr(self.framework, 'collab_server') or not self.framework.collab_server:
                print_warning("No collaboration server is running")
                return True
            
            server = self.framework.collab_server
            
            # Update job status if job_id exists
            if hasattr(server, 'job_id'):
                try:
                    from core.job_manager import global_job_manager
                    global_job_manager.update_job_status(server.job_id, 'killed')
                except Exception:
                    pass
            
            server.stop()
            
            # Clear server reference
            self.framework.collab_server = None
            
            print_success("Collaboration server stopped")
            return True
            
        except Exception as e:
            print_error(f"Error stopping collaboration server: {e}")
            return False
