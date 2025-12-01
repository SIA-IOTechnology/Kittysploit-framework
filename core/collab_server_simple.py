#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simple Collaboration Server - Console-only collaboration for KittySploit framework
No web interface for better security
"""

import socket
import select
import threading
import json
import hashlib
import time
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Set

from core.output_handler import print_info, print_success, print_error, print_warning


class CollaborationClient:
    """Represents a connected client"""
    
    def __init__(self, client_id: str, username: str, workspace: str, socket_conn):
        self.client_id = client_id
        self.username = username
        self.workspace = workspace
        self.socket = socket_conn
        self.connected_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.is_active = True
        self.recv_buffer = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'client_id': self.client_id,
            'username': self.username,
            'workspace': self.workspace,
            'connected_at': self.connected_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'is_active': self.is_active
        }


class ChatMessage:
    """Represents a chat message"""
    
    def __init__(self, message_id: str, username: str, content: str, message_type: str = "text"):
        self.message_id = message_id
        self.username = username
        self.content = content
        self.message_type = message_type
        # Use UTC timezone-aware datetime for consistent timestamps across clients
        from datetime import timezone
        self.timestamp = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'message_id': self.message_id,
            'username': self.username,
            'content': self.content,
            'message_type': self.message_type,
            'timestamp': self.timestamp.isoformat()
        }


class SimpleCollaborationServer:
    """Simple collaboration server using raw sockets for better security"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, 
                 password: str = None, workspace: str = "default", 
                 verbose: bool = False, framework=None):
        self.host = host
        self.port = port
        self.password = password
        self.workspace = workspace
        self.verbose = verbose
        self.framework = framework
        
        # Server state
        self.is_running = False
        self.server_socket = None
        self.clients: Dict[str, CollaborationClient] = {}
        self.chat_messages: List[ChatMessage] = []
        # Store workspace data separately for each workspace
        self.workspace_data: Dict[str, Dict[str, Any]] = {}  # workspace_name -> workspace_data
        
        # Threading (use RLock to avoid deadlocks when broadcasting inside locked sections)
        self._lock = threading.RLock()
        self._server_thread = None
    
    def start(self):
        """Start the collaboration server"""
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.is_running = True
            
            if self.verbose:
                print_success(f"Collaboration server started on {self.host}:{self.port}")
                print_info(f"Workspace: {self.workspace}")
                if self.password:
                    print_info("Authentication: Enabled")
                else:
                    print_warning("Authentication: Disabled")
            
            # Start server loop in a separate thread
            self._server_thread = threading.Thread(target=self._server_loop, daemon=True)
            self._server_thread.start()
            
        except Exception as e:
            print_error(f"Failed to start collaboration server: {e}")
            self.is_running = False
    
    def stop(self):
        """Stop the collaboration server"""
        self.is_running = False
        
        # Close all client connections
        with self._lock:
            for client in self.clients.values():
                try:
                    client.socket.close()
                except:
                    pass
            self.clients.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        if self.verbose:
            print_info("Collaboration server stopped")
    
    def _server_loop(self):
        """Main server loop"""
        while self.is_running:
            try:
                # Wait for connections
                ready_sockets, _, _ = select.select([self.server_socket], [], [], 1.0)
                
                if ready_sockets:
                    client_socket, address = self.server_socket.accept()
                    self._handle_new_client(client_socket, address)
                
                # Process existing clients
                self._process_clients()
                
            except Exception as e:
                if self.verbose:
                    print_error(f"Server loop error: {e}")
                break
    
    def _handle_new_client(self, client_socket, address):
        """Handle new client connection"""
        try:
            # Receive initial data (may be larger than 1024 bytes)
            request = self._recv_json_blocking(client_socket)
            if not request:
                client_socket.close()
                return
            
            # Authenticate if password is set
            if self.password:
                provided_password = request.get('password', '')
                if provided_password != self.password:
                    response = {'status': 'error', 'message': 'Invalid password'}
                    self._send_json(client_socket, response)
                    client_socket.close()
                    return
            
            # Create client
            client_id = str(uuid.uuid4())[:8]
            username = request.get('username', 'Anonymous')
            workspace = request.get('workspace', self.workspace)
            
            client = CollaborationClient(
                client_id=client_id,
                username=username,
                workspace=workspace,
                socket_conn=client_socket
            )
            
            with self._lock:
                self.clients[client_id] = client
            
            # Send welcome response with existing clients and chat history
            existing_clients = []
            for existing_client_id, existing_client in self.clients.items():
                if existing_client_id != client_id and existing_client.workspace == workspace:
                    existing_clients.append({
                        'username': existing_client.username,
                        'client_id': existing_client_id,
                        'workspace': existing_client.workspace
                    })
            
            # Get chat history for this workspace
            workspace_chat_history = []
            for msg in self.chat_messages:
                # For now, send all messages (in a real implementation, you might want to filter by workspace)
                workspace_chat_history.append(msg.to_dict())
            
            # Get workspace data for this workspace
            workspace_data_for_client = self.workspace_data.get(workspace, {})
            
            response = {
                'status': 'success',
                'client_id': client_id,
                'workspace': workspace,
                'message': f'Welcome to workspace {workspace}',
                'existing_clients': existing_clients,
                'chat_history': workspace_chat_history,
                'workspace_data': workspace_data_for_client  # Send current workspace state
            }
            self._send_json(client_socket, response)
            
            # Notify other clients
            join_message = {
                'type': 'client_joined',
                'username': username,
                'client_id': client_id,
                'workspace': workspace
            }
            if self.verbose:
                print_info(f"Broadcasting client_joined message: {join_message}")
            self._broadcast_message(join_message, exclude_client=client_id)
            
            if self.verbose:
                print_info(f"Client {username} ({address[0]}:{address[1]}) connected to workspace {workspace}")
            
        except Exception as e:
            if self.verbose:
                print_error(f"Error handling new client: {e}")
            try:
                client_socket.close()
            except:
                pass
    
    def _process_clients(self):
        """Process messages from existing clients"""
        with self._lock:
            clients_to_remove = []
            
            for client_id, client in self.clients.items():
                try:
                    # Check if socket is ready for reading
                    ready_sockets, _, _ = select.select([client.socket], [], [], 0.1)
                    
                    if ready_sockets:
                        data = client.socket.recv(4096).decode('utf-8')
                        
                        if not data:
                            # Client disconnected
                            clients_to_remove.append(client_id)
                            continue
                        
                        client.recv_buffer += data
                        for message in self._extract_messages_from_buffer(client):
                            self._handle_client_message(client, message)
                            client.last_activity = datetime.utcnow()
                
                except Exception as e:
                    if self.verbose:
                        print_error(f"Error processing client {client_id}: {e}")
                    clients_to_remove.append(client_id)
            
            # Remove disconnected clients
            for client_id in clients_to_remove:
                client = self.clients[client_id]
                self._broadcast_message({
                    'type': 'client_left',
                    'username': client.username,
                    'client_id': client_id
                }, exclude_client=client_id)
                
                try:
                    client.socket.close()
                except:
                    pass
                
                del self.clients[client_id]
                
                if self.verbose:
                    print_info(f"Client {client.username} disconnected")
    
    def _handle_client_message(self, client: CollaborationClient, message: Dict):
        """Handle message from client"""
        message_type = message.get('type', 'unknown')
        
        if message_type == 'chat_message':
            content = message.get('content', '')
            msg_type = message.get('message_type', 'text')
            
            # Create chat message
            chat_msg = ChatMessage(
                message_id=str(uuid.uuid4())[:8],
                username=client.username,
                content=content,
                message_type=msg_type
            )
            
            with self._lock:
                self.chat_messages.append(chat_msg)
            
            # Broadcast to all clients in same workspace
            chat_broadcast = {
                'type': 'chat_message',
                'message': chat_msg.to_dict()
            }
            if self.verbose:
                print_info(f"Broadcasting chat message from {client.username} in workspace {client.workspace}: {chat_broadcast}")
            self._broadcast_message(chat_broadcast, workspace=client.workspace)
            
            if self.verbose:
                print_info(f"Chat message from {client.username}: {content[:50]}...")
        
        elif message_type == 'workspace_sync':
            workspace_data = message.get('data', {})
            
            with self._lock:
                # Initialize workspace data if it doesn't exist
                if client.workspace not in self.workspace_data:
                    self.workspace_data[client.workspace] = {}
                
                # Update workspace data for this specific workspace
                self.workspace_data[client.workspace].update(workspace_data)
            
            # Broadcast workspace update with only the data for this workspace
            self._broadcast_message({
                'type': 'workspace_update',
                'data': self.workspace_data[client.workspace]
            }, workspace=client.workspace)
            
            if self.verbose:
                print_info(f"Workspace '{client.workspace}' synchronized by {client.username}")
                if 'shared_module' in workspace_data:
                    print_info(f"Module '{workspace_data['shared_module'].get('module_path', 'unknown')}' shared")
        
        elif message_type == 'request_chat_history':
            # Send chat history to the requesting client
            with self._lock:
                chat_history = [msg.to_dict() for msg in self.chat_messages]
            
            history_response = {
                'type': 'chat_history_response',
                'messages': chat_history
            }
            
            try:
                self._send_json(client.socket, history_response)
                if self.verbose:
                    print_info(f"Sent chat history ({len(chat_history)} messages) to {client.username}")
            except Exception as e:
                if self.verbose:
                    print_error(f"Failed to send chat history to {client.username}: {e}")
    
    def _broadcast_message(self, message: Dict, workspace: str = None, exclude_client: str = None):
        """Broadcast message to clients"""
        with self._lock:
            if self.verbose:
                print_info(f"Broadcasting to {len(self.clients)} clients (workspace: {workspace}, exclude: {exclude_client})")
            
            sent_count = 0
            for client_id, client in self.clients.items():
                if exclude_client and client_id == exclude_client:
                    if self.verbose:
                        print_info(f"Skipping excluded client {client_id}")
                    continue
                
                # Fix workspace filtering - only filter if workspace is specified
                if workspace is not None and client.workspace != workspace:
                    if self.verbose:
                        print_info(f"Skipping client {client_id} (workspace mismatch: {client.workspace} != {workspace})")
                    continue
                
                try:
                    if self.verbose:
                        print_info(f"Sending message to client {client_id} ({client.username}) in workspace {client.workspace}")
                    self._send_json(client.socket, message)
                    sent_count += 1
                except Exception as e:
                    if self.verbose:
                        print_error(f"Error broadcasting to client {client_id}: {e}")
            
            if self.verbose:
                print_info(f"Message broadcasted to {sent_count} clients")
    
    def _send_json(self, sock, payload: Dict) -> None:
        """Send a JSON payload terminated with a newline."""
        data = (json.dumps(payload) + '\n').encode('utf-8')
        sock.sendall(data)
    
    def _recv_json_blocking(self, sock, timeout: float = 5.0) -> Optional[Dict]:
        """Receive a newline-delimited JSON payload."""
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
                    line, _ = buffer.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        continue
        finally:
            sock.settimeout(previous_timeout)
    
    def _extract_messages_from_buffer(self, client: CollaborationClient) -> List[Dict]:
        """Return complete JSON messages from a client's buffer."""
        messages = []
        while '\n' in client.recv_buffer:
            line, remainder = client.recv_buffer.split('\n', 1)
            client.recv_buffer = remainder
            line = line.strip()
            if not line:
                continue
            try:
                messages.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return messages
    
    def get_status(self) -> Dict:
        """Get server status"""
        with self._lock:
            return {
                'is_running': self.is_running,
                'host': self.host,
                'port': self.port,
                'workspace': self.workspace,
                'client_count': len(self.clients),
                'message_count': len(self.chat_messages),
                'has_password': bool(self.password)
            }
    
    def get_clients(self) -> List[Dict]:
        """Get connected clients"""
        with self._lock:
            return [client.to_dict() for client in self.clients.values()]
    
    def get_chat_history(self, limit: int = 50) -> List[Dict]:
        """Get chat message history"""
        with self._lock:
            return [msg.to_dict() for msg in self.chat_messages[-limit:]]
    
    def debug_clients(self):
        """Debug method to show all connected clients"""
        with self._lock:
            if self.verbose:
                print_info("=== Connected Clients Debug ===")
                for client_id, client in self.clients.items():
                    print_info(f"Client {client_id}: {client.username} in workspace {client.workspace}")
                print_info(f"Total clients: {len(self.clients)}")
                print_info("=" * 30)
