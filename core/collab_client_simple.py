#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simple Collaboration Client - Console-only client for KittySploit collaboration
No web dependencies for better security
"""

import socket
import json
import threading
import time
import uuid
import queue
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional

from core.output_handler import print_info, print_success, print_error, print_warning


class SimpleCollaborationClient:
    """Simple collaboration client using raw sockets for better security"""
    
    def __init__(self, host: str, port: int = 8080, password: str = None,
                 username: str = "Anonymous", workspace: str = "default",
                 verbose: bool = False, framework=None):
        self.host = host
        self.port = port
        self.password = password
        self.username = username
        self.workspace = workspace
        self.verbose = verbose
        self.framework = framework
        
        # Client state
        self.is_connected = False
        self.socket = None
        self.chat_messages: List[Dict] = []
        self.connected_clients: List[Dict] = []
        self.workspace_data: Dict = {}  # Store workspace data including shared modules
        
        # Message queue for non-intrusive display
        self._message_queue = queue.Queue()
        self._display_thread = None
        self._recv_buffer = ""
        
        # Threading
        self._lock = threading.Lock()
        self._receive_thread = None
    
    def connect(self) -> bool:
        """Connect to the collaboration server"""
        try:
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Send connection request
            request = {
                'username': self.username,
                'workspace': self.workspace,
                'password': self.password or ''
            }
            
            # Use newline-delimited JSON to handle large payloads
            self._send_json(request)
            
            # Receive response (may be larger than 1024 bytes)
            response = self._recv_json_blocking(self.socket)
            if response is None:
                raise ConnectionError("No response from collaboration server")
            
            if response.get('status') == 'success':
                self.is_connected = True
                
                # Add existing clients to the list
                with self._lock:
                    existing_clients = response.get('existing_clients', [])
                    for client_info in existing_clients:
                        self.connected_clients.append(client_info)
                    
                    # Add self to connected clients list
                    self.connected_clients.append({
                        'username': self.username,
                        'client_id': response.get('client_id', ''),
                        'workspace': response.get('workspace', self.workspace)
                    })
                    
                    # Load chat history from server
                    chat_history = response.get('chat_history', [])
                    for msg in chat_history:
                        self.chat_messages.append(msg)
                    
                    if self.verbose and chat_history:
                        print_info(f"Loaded {len(chat_history)} messages from chat history")
                    
                    # Load workspace data from server
                    workspace_data = response.get('workspace_data', {})
                    if workspace_data:
                        self.workspace_data.update(workspace_data)
                        if self.verbose:
                            print_info(f"Loaded workspace data: {list(workspace_data.keys())}")
                            if 'shared_module' in workspace_data:
                                shared_module = workspace_data['shared_module']
                                module_path = shared_module.get('module_path', 'unknown')
                                shared_by = shared_module.get('shared_by', 'unknown')
                                has_source = bool(shared_module.get('source_code'))
                                source_info = "with source code" if has_source else "without source code"
                                print_info(f"Found shared module '{module_path}' from {shared_by} ({source_info})")
                
                # Start receive thread
                self._receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
                self._receive_thread.start()
                
                # Start message display thread for non-intrusive output
                self._display_thread = threading.Thread(target=self._display_message_loop, daemon=True)
                self._display_thread.start()
                
                if self.verbose:
                    print_success(f"Connected to collaboration server at {self.host}:{self.port}")
                    print_info(f"Workspace: {response.get('workspace', self.workspace)}")
                    if existing_clients:
                        print_info(f"Found {len(existing_clients)} existing clients")
                
                return True
            else:
                error_msg = response.get('message', 'Unknown error')
                if self.verbose:
                    print_error(f"Connection failed: {error_msg}")
                return False
            
        except Exception as e:
            if self.verbose:
                print_error(f"Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the collaboration server"""
        self.is_connected = False
        
        # Signal display thread to stop
        if hasattr(self, '_message_queue') and self._message_queue:
            self._message_queue.put(None)  # Stop signal
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        if self.verbose:
            print_info("Disconnected from collaboration server")
    
    def _display_message_loop(self):
        """Display messages from queue in a non-intrusive way"""
        while self.is_connected:
            try:
                # Wait for message with timeout
                try:
                    msg_data = self._message_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                
                # Stop signal
                if msg_data is None:
                    break
                
                # Display message using non-intrusive method
                self._display_message_non_intrusive(
                    msg_data['timestamp'],
                    msg_data['username'],
                    msg_data['content'],
                    msg_data['msg_type']
                )
                
            except Exception as e:
                if self.verbose:
                    print_error(f"Error in display thread: {e}")
                time.sleep(0.1)
    
    def _display_message_non_intrusive(self, timestamp: str, username: str, content: str, msg_type: str):
        """
        Display a message in a non-intrusive way that doesn't interrupt user input.
        Uses prompt_toolkit's print_formatted_text to properly handle the prompt.
        Displays all messages (including our own) with server timestamps for consistency.
        """
        try:
            # Display all messages, including our own (they come from server with server timestamp)
            
            # Check if we're in chat mode with prompt_toolkit
            if hasattr(self, '_chat_prompt_session') and self._chat_prompt_session:
                # Use prompt_toolkit's print_formatted_text for proper prompt handling
                # This automatically keeps the prompt at the bottom
                from prompt_toolkit import print_formatted_text
                from prompt_toolkit.formatted_text import FormattedText
                
                # Format message with colors
                if msg_type == 'command':
                    formatted_msg = FormattedText([
                        ('ansicyan', f'[{timestamp}]'),
                        ('', f' {username}: {content}')
                    ])
                elif msg_type == 'result':
                    formatted_msg = FormattedText([
                        ('ansigreen', f'[{timestamp}]'),
                        ('', f' {username}: {content}')
                    ])
                elif msg_type == 'error':
                    formatted_msg = FormattedText([
                        ('ansired', f'[{timestamp}]'),
                        ('', f' {username}: {content}')
                    ])
                else:
                    # Default: cyan for text messages
                    formatted_msg = FormattedText([
                        ('ansicyan', f'[{timestamp}]'),
                        ('', f' {username}: {content}')
                    ])
                
                # Print using prompt_toolkit - this automatically handles prompt repositioning
                # When used with a PromptSession, print_formatted_text will automatically
                # redraw the prompt below the new message, keeping it at the bottom
                try:
                    # Print the formatted message
                    # prompt_toolkit will handle keeping the prompt at the bottom
                    print_formatted_text(formatted_msg)
                    
                    # Try to invalidate the application to force prompt redraw
                    # This ensures the prompt is redrawn below the message
                    try:
                        from prompt_toolkit.application import get_app
                        app = get_app()
                        if app.is_running:
                            # Invalidate to force redraw - this will redraw the prompt below
                            app.invalidate()
                    except (RuntimeError, AttributeError):
                        # No application running - that's okay, print_formatted_text
                        # should still work and the prompt will be handled by the session
                        pass
                except Exception as e:
                    # Fallback if prompt_toolkit fails
                    if self.verbose:
                        print_warning(f"Error displaying message with prompt_toolkit: {e}")
                    # Fall through to simple print
                    raise
            else:
                # Fallback to simple print if not using prompt_toolkit
                if msg_type == 'command':
                    print(f"\033[36m[{timestamp}]\033[0m {username}: {content}")
                elif msg_type == 'result':
                    print(f"\033[32m[{timestamp}]\033[0m {username}: {content}")
                elif msg_type == 'error':
                    print(f"\033[31m[{timestamp}]\033[0m {username}: {content}")
                else:
                    print(f"\033[36m[{timestamp}]\033[0m {username}: {content}")
                sys.stdout.flush()
        except Exception as e:
            # Ultimate fallback: simple print
            try:
                if username != self.username:
                    print(f"[{timestamp}] {username}: {content}")
            except:
                pass
    
    def send_chat_message(self, content: str, message_type: str = "text") -> bool:
        """Send a chat message"""
        if not self.is_connected:
            print_error("Not connected to collaboration server")
            return False
        
        try:
            message = {
                'type': 'chat_message',
                'content': content,
                'message_type': message_type
            }
            
            self._send_json(message)
            
            if self.verbose:
                print_info(f"Sent message: {content[:50]}...")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to send message: {e}")
            return False
    
    def send_command_result(self, command: str, result: str, success: bool = True) -> bool:
        """Send command execution result"""
        message_type = "result" if success else "error"
        content = f"Command: {command}\nResult: {result}"
        
        return self.send_chat_message(content, message_type)
    
    def sync_workspace(self, workspace_data: Dict) -> bool:
        """Sync workspace data with server"""
        if not self.is_connected:
            return False
        
        try:
            # Update local workspace data immediately (optimistic update)
            with self._lock:
                self.workspace_data.update(workspace_data)
            
            message = {
                'type': 'workspace_sync',
                'data': workspace_data
            }
            
            self._send_json(message)
            
            if self.verbose:
                print_info("Workspace synchronized")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to sync workspace: {e}")
            return False
    
    def _receive_loop(self):
        """Receive messages from server"""
        while self.is_connected and self.socket:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                
                if not data:
                    break
                
                self._recv_buffer += data
                self._process_incoming_messages()
                
            except Exception as e:
                if self.verbose:
                    print_error(f"Error receiving message: {e}")
                break
        
        self.is_connected = False
    
    def _handle_server_message(self, message: Dict):
        """Handle message from server"""
        message_type = message.get('type', 'unknown')
        
        if message_type == 'client_joined':
            username = message.get('username', 'Unknown')
            client_id = message.get('client_id', '')
            workspace = message.get('workspace', '')
            
            with self._lock:
                # Add to connected clients list
                client_info = {
                    'username': username,
                    'client_id': client_id,
                    'workspace': workspace
                }
                self.connected_clients.append(client_info)
            
            if self.verbose:
                print_info(f"{username} joined the collaboration")
        
        elif message_type == 'client_left':
            username = message.get('username', 'Unknown')
            client_id = message.get('client_id', '')
            
            with self._lock:
                # Remove from connected clients list
                self.connected_clients = [
                    client for client in self.connected_clients 
                    if client.get('client_id') != client_id
                ]
            
            if self.verbose:
                print_info(f"{username} left the collaboration")
        
        elif message_type == 'chat_message':
            chat_data = message.get('message', {})
            
            if self.verbose:
                print_info(f"Received chat message: {chat_data}")
            
            # Validate chat data before processing
            if not chat_data or 'username' not in chat_data or 'content' not in chat_data:
                if self.verbose:
                    print_error(f"Invalid chat message format: {chat_data}")
                return
            
            with self._lock:
                self.chat_messages.append(chat_data)
            
            # Only queue messages for display if we're in chat mode
            # Messages are only displayed automatically when in collab_chat interface
            # When not in chat mode, messages are stored but not displayed automatically
            if hasattr(self, '_in_chat_mode') and self._in_chat_mode:
                try:
                    # Parse timestamp as UTC and format it (server sends UTC timestamps)
                    from datetime import timezone
                    try:
                        # Try to parse with timezone info
                        dt = datetime.fromisoformat(chat_data['timestamp'].replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            # If no timezone info, assume UTC
                            dt = dt.replace(tzinfo=timezone.utc)
                        # Format as UTC time (HH:MM:SS)
                        timestamp = dt.strftime("%H:%M:%S")
                    except Exception:
                        # Fallback to simple parsing
                        timestamp = datetime.fromisoformat(chat_data['timestamp']).strftime("%H:%M:%S")
                    
                    username = chat_data['username']
                    content = chat_data['content']
                    msg_type = chat_data.get('message_type', 'text')
                    
                    # Queue all messages (including our own) with server timestamp
                    # This ensures consistent timestamps across all clients
                    self._message_queue.put({
                        'timestamp': timestamp,
                        'username': username,
                        'content': content,
                        'msg_type': msg_type
                    })
                except Exception as e:
                    if self.verbose:
                        print_error(f"Error queuing chat message: {e}")
        
        elif message_type == 'workspace_update':
            workspace_data = message.get('data', {})
            
            with self._lock:
                self.workspace_data.update(workspace_data)
            
            if self.verbose:
                print_info("Workspace updated from server")
            
            # Check if a module was shared
            if 'shared_module' in workspace_data:
                shared_module = workspace_data['shared_module']
                shared_by = shared_module.get('shared_by', 'Unknown')
                module_path = shared_module.get('module_path', 'Unknown')
                has_source = bool(shared_module.get('source_code'))
                
                # Only notify if it wasn't shared by us
                if shared_by != self.username:
                    print_info(f"Module '{module_path}' shared by {shared_by}")
                    if has_source:
                        print_info("Source code included - use 'collab_sync_module' to load it")
                    else:
                        print_info("Use 'collab_sync_module' to load it (no source code)")
            
            # Check if a module is being edited collaboratively
            if 'editing_module' in workspace_data and workspace_data['editing_module']:
                editing_info = workspace_data['editing_module']
                if editing_info.get('editing') and editing_info.get('edited_by') != self.username:
                    module_path = editing_info.get('module_path', 'Unknown')
                    edited_by = editing_info.get('edited_by', 'Unknown')
                    print_info(f"Module '{module_path}' is being edited by {edited_by}")
                    print_info("Use 'collab_sync_edit' to see the changes")
        
        elif message_type == 'chat_history_response':
            messages = message.get('messages', [])
            
            with self._lock:
                # Clear existing messages and load new ones
                self.chat_messages.clear()
                for msg in messages:
                    self.chat_messages.append(msg)
            
            if self.verbose:
                print_info(f"Received chat history: {len(messages)} messages")
    
    def get_chat_history(self) -> List[Dict]:
        """Get chat message history"""
        with self._lock:
            return self.chat_messages.copy()
    
    def get_connected_clients(self) -> List[Dict]:
        """Get list of connected clients"""
        with self._lock:
            return self.connected_clients.copy()
    
    def is_server_connected(self) -> bool:
        """Check if connected to server"""
        return self.is_connected and self.socket is not None
    
    def get_workspace_data(self) -> Dict:
        """Get current workspace data"""
        with self._lock:
            return self.workspace_data.copy()
    
    def get_shared_module(self) -> Optional[Dict]:
        """Get the most recently shared module from workspace data"""
        with self._lock:
            return self.workspace_data.get('shared_module')
    
    def request_chat_history(self) -> bool:
        """Request chat history from server"""
        if not self.is_connected:
            print_error("Not connected to collaboration server")
            return False
        
        try:
            message = {
                'type': 'request_chat_history'
            }
            
            self._send_json(message)
            
            if self.verbose:
                print_info("Requested chat history from server")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to request chat history: {e}")
            return False
    
    def _send_json(self, payload: Dict) -> None:
        """Send a JSON message terminated with a newline."""
        if not self.socket:
            raise ConnectionError("Not connected to collaboration server")
        
        data = (json.dumps(payload) + '\n').encode('utf-8')
        self.socket.sendall(data)
    
    def _recv_json_blocking(self, sock: socket.socket, timeout: float = 5.0) -> Optional[Dict]:
        """Receive a single JSON object, blocking until a newline delimiter is found."""
        if sock is None:
            return None
        
        previous_timeout = sock.gettimeout()
        buffer = ''
        try:
            sock.settimeout(timeout)
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    return None
                buffer += chunk.decode('utf-8')
                if '\n' in buffer:
                    line, remainder = buffer.split('\n', 1)
                    self._recv_buffer = remainder + self._recv_buffer
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        # Corrupted payload, discard this entry and keep waiting
                        continue
        finally:
            sock.settimeout(previous_timeout)
    
    def _process_incoming_messages(self) -> None:
        """Process any complete newline-delimited JSON messages in the buffer."""
        while '\n' in self._recv_buffer:
            line, remainder = self._recv_buffer.split('\n', 1)
            self._recv_buffer = remainder
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._handle_server_message(message)
