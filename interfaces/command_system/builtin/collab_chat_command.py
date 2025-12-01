from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning
import argparse
import threading
import time
import shutil
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
from prompt_toolkit.application import get_app

class CollabChatCommand(BaseCommand):
    """Command to open chat interface for collaboration"""
    
    @property
    def name(self) -> str:
        return "collab_chat"
    
    @property
    def description(self) -> str:
        return "Open chat interface for collaboration"
    
    @property
    def usage(self) -> str:
        return "collab_chat [--web] [--history]"
    
    def _create_parser(self):
        """Create argument parser for collab_chat command"""
        parser = argparse.ArgumentParser(
            prog='collab_chat',
            description='Open chat interface for collaboration'
        )
        
        parser.add_argument('--web', action='store_true',
                          help='Open web-based chat interface')
        parser.add_argument('--history', action='store_true',
                          help='Show chat history')
        
        return parser
    
    def execute(self, args, **kwargs):
        """Execute the collab_chat command"""
        if not args:
            args = []
        
        try:
            parsed_args = self._create_parser().parse_args(args)
            return self._open_chat(parsed_args)
        except SystemExit:
            return False
        except Exception as e:
            print_error(f"Error opening chat interface: {e}")
            return False
    
    def _open_chat(self, args):
        """Open chat interface"""
        # Check if connected to collaboration server
        if not hasattr(self.framework, 'collab_client') or not self.framework.collab_client:
            print_error("Not connected to collaboration server. Use 'collab_connect' first.")
            return False
        
        client = self.framework.collab_client
        
        if not client.is_server_connected():
            print_error("Not connected to collaboration server")
            return False
        
        if args.history:
            return self._show_chat_history(client)
        elif args.web:
            return self._open_web_chat(client)
        else:
            return self._open_console_chat(client)
    
    def _show_chat_history(self, client):
        """Show chat history"""
        messages = client.get_chat_history()
        
        if not messages:
            print_info("No chat history available")
            return True
        
        print_info("=== Chat History ===")
        for message in messages[-20:]:  # Show last 20 messages
            # Parse timestamp as UTC and format it (server sends UTC timestamps)
            from datetime import timezone
            try:
                dt = datetime.fromisoformat(message['timestamp'].replace('Z', '+00:00'))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                timestamp = dt.strftime("%H:%M:%S")
            except Exception:
                timestamp = datetime.fromisoformat(message['timestamp']).strftime("%H:%M:%S")
            username = message['username']
            content = message['content']
            message_type = message.get('message_type', 'text')
            
            # Color coding
            if message_type == 'command':
                print_info(f"[{timestamp}] {username}: {content}")
            elif message_type == 'result':
                print_success(f"[{timestamp}] {username}: {content}")
            elif message_type == 'error':
                print_error(f"[{timestamp}] {username}: {content}")
            else:
                print_info(f"[{timestamp}] {username}: {content}")
        
        return True
    
    def _open_web_chat(self, client):
        """Open web-based chat interface"""
        try:
            import webbrowser
            
            # Open server web interface
            server_url = f"http://{client.host}:{client.port}"
            webbrowser.open(server_url)
            
            print_success(f"Opening web chat interface: {server_url}")
            print_info("You can also access it manually in your browser")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to open web interface: {e}")
            return False
    
    def _open_console_chat(self, client):
        """Open console-based chat interface"""
        print_success("=== Collaboration Chat ===")
        print_info("Type your messages and press Enter to send")
        print_info("Type '/exit' to leave chat")
        print_info("Type '/help' for more commands")
        print_info("=" * 30)
        
        # Set chat mode flag to enable message display via queue
        client._in_chat_mode = True
        
        # Create prompt session with prompt_toolkit for better message handling
        chat_style = Style.from_dict({
            'prompt': 'ansicyan bold',
        })
        
        prompt_text = self._get_prompt_text(client)

        def get_chat_prompt():
            return HTML(f'<prompt>{prompt_text}</prompt>')
        
        prompt_session = PromptSession(
            style=chat_style,
            message=get_chat_prompt
        )
        
        # Store reference to prompt session in client for message display
        client._chat_prompt_session = prompt_session
        
        try:
            while True:
                # Get user input using prompt_toolkit
                try:
                    raw_message = prompt_session.prompt()
                except (EOFError, KeyboardInterrupt):
                    break
                
                # Remove the previous prompt/input so chat log stays clean
                self._clear_prompt_input_line(prompt_text, raw_message)
                message = raw_message.strip()
                
                if not message:
                    continue
                
                # Handle special commands
                if message == '/exit':
                    break
                elif message == '/help':
                    self._show_chat_help()
                    continue
                elif message == '/history':
                    self._show_recent_messages(client)
                    continue
                elif message == '/clients':
                    self._show_connected_clients(client)
                    continue
                elif message == '/debug':
                    self._show_debug_info(client)
                    continue
                elif message == '/refresh':
                    self._refresh_chat_history(client)
                    continue
                elif message.startswith('/'):
                    print_error(f"Unknown command: {message}")
                    continue
                
                # Send message
                if client.send_chat_message(message):
                    # Don't display immediately - wait for server to echo back with server timestamp
                    # This ensures all timestamps are synchronized from the server
                    pass
                else:
                    print_error("Failed to send message")
            
            print_info("Left chat interface")
            return True
            
        except KeyboardInterrupt:
            print_info("\nLeft chat interface")
            return True
        except Exception as e:
            print_error(f"Error in chat interface: {e}")
            return False
        finally:
            client._in_chat_mode = False  # Clear chat mode flag
            # Clean up prompt session reference
            if hasattr(client, '_chat_prompt_session'):
                del client._chat_prompt_session
    
    def _show_chat_help(self):
        """Show chat help"""
        print_info("=== Chat Commands ===")
        print_info("/exit     - Leave chat interface")
        print_info("/help     - Show this help")
        print_info("/history  - Show recent messages")
        print_info("/clients  - Show connected clients")
        print_info("/debug    - Show debug information")
        print_info("/refresh  - Refresh chat history from server")
        print_info("=" * 20)
    
    def _show_recent_messages(self, client):
        """Show recent messages"""
        messages = client.get_chat_history()
        
        if not messages:
            print_info("No recent messages")
            return
        
        print_info("=== Recent Messages ===")
        for message in messages[-10:]:  # Show last 10 messages
            # Parse timestamp as UTC and format it (server sends UTC timestamps)
            from datetime import timezone
            try:
                dt = datetime.fromisoformat(message['timestamp'].replace('Z', '+00:00'))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                timestamp = dt.strftime("%H:%M:%S")
            except Exception:
                timestamp = datetime.fromisoformat(message['timestamp']).strftime("%H:%M:%S")
            username = message['username']
            content = message['content']
            
            print_info(f"[{timestamp}] {username}: {content}")
    
    def _show_connected_clients(self, client):
        """Show connected clients"""
        clients = client.get_connected_clients()
        
        if not clients:
            print_info("No connected clients")
            return
        
        print_info("=== Connected Clients ===")
        for client_info in clients:
            username = client_info.get('username', 'Unknown')
            workspace = client_info.get('workspace', 'Unknown')
            client_id = client_info.get('client_id', 'Unknown')
            print_info(f"- {username} (ID: {client_id}, Workspace: {workspace})")
    
    def _show_debug_info(self, client):
        """Show debug information"""
        print_info("=== Debug Information ===")
        print_info(f"Client username: {client.username}")
        print_info(f"Client workspace: {client.workspace}")
        print_info(f"Client connected: {client.is_server_connected()}")
        print_info(f"Client verbose: {client.verbose}")
        print_info(f"Chat messages count: {len(client.chat_messages)}")
        print_info(f"Connected clients count: {len(client.connected_clients)}")
        
        # Show recent messages
        if client.chat_messages:
            print_info("=== Recent Messages ===")
            for msg in client.chat_messages[-5:]:  # Last 5 messages
                timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%H:%M:%S")
                username = msg['username']
                content = msg['content'][:50] + "..." if len(msg['content']) > 50 else msg['content']
                print_info(f"[{timestamp}] {username}: {content}")
        
        print_info("=" * 25)
    
    def _refresh_chat_history(self, client):
        """Refresh chat history from server"""
        print_info("Refreshing chat history from server...")
        
        if client.request_chat_history():
            print_success("Chat history refresh requested")
            print_info("Use /history to see the updated history")
        else:
            print_error("Failed to request chat history refresh")
    
    def _get_prompt_text(self, client) -> str:
        """Return the plain text prompt label for the chat interface."""
        username = getattr(client, 'username', 'user')
        return f"[{username}]> "
    
    def _clear_prompt_input_line(self, prompt_text: str, raw_message: str) -> None:
        """
        Remove the user's previously entered text so only formatted chat messages remain.
        This keeps the prompt at the bottom with a clean chat history.
        """
        if not raw_message:
            return
        if not sys.stdout or not sys.stdout.isatty():
            return
        
        try:
            columns = max(shutil.get_terminal_size(fallback=(80, 24)).columns, 1)
        except Exception:
            columns = 80
        
        # Account for long lines that wrap by estimating how many terminal rows were used
        message_lines = raw_message.splitlines() or ['']
        total_lines = 0
        for idx, line in enumerate(message_lines):
            visible_length = len(line)
            if idx == 0:
                visible_length += len(prompt_text)
            total_lines += max(1, (visible_length // columns) + 1)
        
        try:
            for _ in range(total_lines):
                sys.stdout.write('\x1b[1A')  # Move cursor up
                sys.stdout.write('\x1b[2K')  # Clear the entire line
            sys.stdout.write('\r')
            sys.stdout.flush()
        except Exception:
            pass
