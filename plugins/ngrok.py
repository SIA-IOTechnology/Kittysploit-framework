#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import shlex

class NgrokPlugin(Plugin):
    """Ngrok tunnel management plugin"""
    
    __info__ = {
        "name": "ngrok",
        "description": "Manage ngrok service for creating secure tunnels",
        "version": "1.0.0",
        "author": "KittySploit Team",
        "dependencies": ["pyngrok"]
    }
    
    def __init__(self, framework=None):
        super().__init__(framework)
        try:
            from pyngrok import ngrok
            self.ngrok = ngrok
        except ImportError:
            self.ngrok = None
    
    def run(self, *args, **kwargs):
        """Handles ngrok tunnel creation, listing, and deletion."""
        if not self.ngrok:
            print_error("pyngrok is not installed. Please install it with: pip install pyngrok")
            return False
        
        parser = ModuleArgumentParser(description=self.__doc__, prog="ngrok")
        parser.add_argument("-c", "--create", dest="create", help="Create ngrok tunnel on specified port", metavar="<port>", type=int)
        parser.add_argument("-l", "--list", action="store_true", dest="list", help="List ngrok tunnels")
        parser.add_argument("-d", "--delete", dest="delete", help="Delete ngrok tunnel by ID", metavar="<ngrok id>", type=str)
        parser.add_argument("-k", "--kill", dest="kill", action="store_true", help="Kill all ngrok tunnels")
        parser.add_argument("-s", "--status", dest="status", action="store_true", help="Show ngrok status")
        # Help is automatically added by ModuleArgumentParser

        if not args or not args[0]:
            parser.print_help()
            return True

        try:
            pargs = parser.parse_args(shlex.split(args[0]))

            if getattr(pargs, 'help', False):
                parser.print_help()
                return True

            if pargs.create is not None:
                return self._create_tunnel(pargs.create)

            if pargs.list:
                return self._list_tunnels()

            if pargs.delete is not None:
                return self._delete_tunnel(pargs.delete)

            if pargs.kill:
                return self._kill_all_tunnels()

            if pargs.status:
                return self._show_status()

            # If no specific action, show help
            parser.print_help()
            return True

        except Exception as e:
            print_error(f"An error occurred: {e}")
            return False
    
    def _create_tunnel(self, port: int):
        """Create a new ngrok tunnel"""
        try:
            print_info(f"Creating ngrok tunnel on port {port}...")
            tunnel = self.ngrok.connect(port, "http")
            print_success(f"Tunnel created successfully!")
            print_info(f"Public URL: {tunnel.public_url}")
            print_info(f"Tunnel ID: {tunnel.id}")
            print_info(f"Local URL: http://localhost:{port}")
            return True
        except Exception as e:
            print_error(f"Failed to create tunnel: {e}")
            return False
    
    def _list_tunnels(self):
        """List all active ngrok tunnels"""
        try:
            tunnels = self.ngrok.get_tunnels()
            if tunnels:
                print_info("Active ngrok tunnels:")
                print_info("=" * 60)
                print_info(f"{'ID':<20} {'Public URL':<30} {'Local URL'}")
                print_info("-" * 60)
                for tunnel in tunnels:
                    local_url = tunnel.config.get('addr', 'Unknown')
                    print_info(f"{tunnel.id:<20} {tunnel.public_url:<30} {local_url}")
                print_info("=" * 60)
                print_info(f"Total: {len(tunnels)} tunnels")
            else:
                print_info("No ngrok tunnels currently running.")
            return True
        except Exception as e:
            print_error(f"Failed to list tunnels: {e}")
            return False
    
    def _delete_tunnel(self, tunnel_id: str):
        """Delete a specific ngrok tunnel"""
        try:
            tunnels = self.ngrok.get_tunnels()
            tunnel_to_delete = None
            for tunnel in tunnels:
                if tunnel.id == tunnel_id:
                    tunnel_to_delete = tunnel
                    break
            
            if tunnel_to_delete:
                self.ngrok.disconnect(tunnel_to_delete.public_url)
                print_success(f"Tunnel {tunnel_to_delete.public_url} (ID: {tunnel_to_delete.id}) has been disconnected.")
                return True
            else:
                print_error(f"No tunnel found with ID {tunnel_id}.")
                return False
        except Exception as e:
            print_error(f"Failed to delete tunnel: {e}")
            return False
    
    def _kill_all_tunnels(self):
        """Kill all ngrok tunnels"""
        try:
            tunnels = self.ngrok.get_tunnels()
            if not tunnels:
                print_info("No tunnels to kill.")
                return True
            
            for tunnel in tunnels:
                self.ngrok.disconnect(tunnel.public_url)
            
            print_success(f"Killed {len(tunnels)} tunnel(s).")
            return True
        except Exception as e:
            print_error(f"Failed to kill tunnels: {e}")
            return False
    
    def _show_status(self):
        """Show ngrok status"""
        try:
            tunnels = self.ngrok.get_tunnels()
            print_info("Ngrok Status:")
            print_info(f"  Active tunnels: {len(tunnels)}")
            
            if tunnels:
                print_info("  Tunnel details:")
                for tunnel in tunnels:
                    print_info(f"    - {tunnel.id}: {tunnel.public_url}")
            else:
                print_info("  No active tunnels")
            
            return True
        except Exception as e:
            print_error(f"Failed to get status: {e}")
            return False
