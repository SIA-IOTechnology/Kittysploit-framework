from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import argparse

class CollabDisconnectCommand(BaseCommand):
    """Command to disconnect from collaboration server"""
    
    @property
    def name(self) -> str:
        return "collab_disconnect"
    
    @property
    def description(self) -> str:
        return "Disconnect from collaboration server"
    
    @property
    def usage(self) -> str:
        return "collab_disconnect"
    
    def _create_parser(self):
        """Create argument parser for collab_disconnect command"""
        parser = argparse.ArgumentParser(
            prog='collab_disconnect',
            description='Disconnect from collaboration server'
        )
        return parser
    
    def execute(self, args, **kwargs):
        """Execute the collab_disconnect command"""
        try:
            # Check if connected to collaboration server
            if not hasattr(self.framework, 'collab_client') or not self.framework.collab_client:
                print_warning("Not connected to any collaboration server")
                return True
            
            client = self.framework.collab_client
            
            # Disconnect from server
            client.disconnect()
            
            # Clear client reference
            self.framework.collab_client = None
            
            # Reset workspace context
            self.framework.current_collab = None
            
            print_success("Disconnected from collaboration server")
            print_info("Workspace context reset to local")
            
            return True
            
        except Exception as e:
            print_error(f"Error disconnecting from collaboration server: {e}")
            return False
