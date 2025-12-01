#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Connection Manager for Multiple Remote Connections
"""

import threading
import time
from typing import Dict, List, Optional, Any, Callable
from core.output_handler import print_info, print_success, print_error, print_warning

class ConnectionManager:
    """Manager for multiple remote connections"""
    
    def __init__(self):
        # Import here to avoid circular import
        from core.lib.remote_connection import RemoteConnection
        self.connections: Dict[str, RemoteConnection] = {}
        self.current_connection: Optional[str] = None
        self.lock = threading.Lock()
        self.auto_reconnect_enabled = True
        self.connection_callbacks: Dict[str, List[Callable]] = {}
    
    def add(self, name: str, connection, auto_connect: bool = True) -> bool:
        """
        Add a new connection to the manager
        
        Args:
            name: Unique name for the connection
            connection: RemoteConnection object
            auto_connect: Whether to connect automatically
            
        Returns:
            bool: True if added successfully
        """
        with self.lock:
            if name in self.connections:
                print_warning(f"Connection '{name}' already exists. Replacing...")
            
            self.connections[name] = connection
            
            if auto_connect and not connection.connected:
                if connection.connect():
                    print_success(f"Connected '{name}' to {connection.host}:{connection.port}")
                else:
                    print_error(f"Failed to connect '{name}' to {connection.host}:{connection.port}")
            
            # Set as current if it's the first connection
            if self.current_connection is None:
                self.current_connection = name
            
            return True
    
    def remove(self, name: str) -> bool:
        """
        Remove a connection from the manager
        
        Args:
            name: Name of the connection to remove
            
        Returns:
            bool: True if removed successfully
        """
        with self.lock:
            if name not in self.connections:
                print_warning(f"Connection '{name}' not found")
                return False
            
            # Disconnect if connected
            if self.connections[name].connected:
                self.connections[name].disconnect()
            
            # Remove from manager
            del self.connections[name]
            
            # Update current connection if needed
            if self.current_connection == name:
                self.current_connection = None
                if self.connections:
                    self.current_connection = list(self.connections.keys())[0]
            
            print_info(f"Removed connection '{name}'")
            return True
    
    def switch(self, name: str) -> bool:
        """
        Switch to a different connection
        
        Args:
            name: Name of the connection to switch to
            
        Returns:
            bool: True if switched successfully
        """
        with self.lock:
            if name not in self.connections:
                print_error(f"Connection '{name}' not found")
                return False
            
            self.current_connection = name
            print_success(f"Switched to connection '{name}'")
            return True
    
    def get_current(self):
        """Get the current active connection"""
        with self.lock:
            if self.current_connection and self.current_connection in self.connections:
                return self.connections[self.current_connection]
            return None
    
    def get(self, name: str):
        """Get a specific connection by name"""
        with self.lock:
            return self.connections.get(name)
    
    def list_connections(self) -> Dict[str, Dict[str, Any]]:
        """List all connections with their status"""
        with self.lock:
            result = {}
            for name, conn in self.connections.items():
                result[name] = {
                    'connection': conn,
                    'host': conn.host,
                    'port': conn.port,
                    'protocol': conn.protocol,
                    'connected': conn.connected,
                    'is_current': name == self.current_connection
                }
            return result
    
    def broadcast(self, command: str, exclude_current: bool = False) -> Dict[str, Any]:
        """
        Send a command to all connected connections
        
        Args:
            command: Command to send
            exclude_current: Whether to exclude the current connection
            
        Returns:
            Dict with results from each connection
        """
        results = {}
        
        with self.lock:
            for name, conn in self.connections.items():
                if not conn.connected:
                    results[name] = {'error': 'Not connected'}
                    continue
                
                if exclude_current and name == self.current_connection:
                    continue
                
                try:
                    result = conn.send_command(command)
                    results[name] = {'success': True, 'result': result}
                except Exception as e:
                    results[name] = {'error': str(e)}
        
        return results
    
    def send_to(self, name: str, command: str) -> Optional[str]:
        """
        Send a command to a specific connection
        
        Args:
            name: Name of the connection
            command: Command to send
            
        Returns:
            Command result or None if failed
        """
        conn = self.get(name)
        if not conn:
            print_error(f"Connection '{name}' not found")
            return None
        
        if not conn.connected:
            print_error(f"Connection '{name}' is not connected")
            return None
        
        return conn.send_command(command)
    
    def connect_all(self) -> Dict[str, bool]:
        """Connect all connections"""
        results = {}
        
        with self.lock:
            for name, conn in self.connections.items():
                if not conn.connected:
                    results[name] = conn.connect()
                else:
                    results[name] = True
        
        return results
    
    def disconnect_all(self) -> Dict[str, bool]:
        """Disconnect all connections"""
        results = {}
        
        with self.lock:
            for name, conn in self.connections.items():
                if conn.connected:
                    conn.disconnect()
                    results[name] = True
                else:
                    results[name] = True
        
        return results
    
    def interactive(self, name: str = None) -> bool:
        """
        Start interactive session with a connection
        
        Args:
            name: Name of the connection (uses current if None)
            
        Returns:
            bool: True if started successfully
        """
        if name is None:
            name = self.current_connection
        
        conn = self.get(name)
        if not conn:
            print_error(f"Connection '{name}' not found")
            return False
        
        if not conn.connected:
            print_error(f"Connection '{name}' is not connected")
            return False
        
        return conn.interactive()
    
    def add_callback(self, event: str, callback: Callable) -> None:
        """
        Add a callback for connection events
        
        Args:
            event: Event type ('connected', 'disconnected', 'error')
            callback: Callback function
        """
        if event not in self.connection_callbacks:
            self.connection_callbacks[event] = []
        self.connection_callbacks[event].append(callback)
    
    def _trigger_callback(self, event: str, connection_name: str, **kwargs) -> None:
        """Trigger callbacks for an event"""
        if event in self.connection_callbacks:
            for callback in self.connection_callbacks[event]:
                try:
                    callback(connection_name, **kwargs)
                except Exception as e:
                    print_error(f"Callback error: {e}")
    
    def monitor_connections(self, interval: int = 30) -> None:
        """
        Start monitoring connections for auto-reconnect
        
        Args:
            interval: Check interval in seconds
        """
        def monitor_loop():
            while True:
                with self.lock:
                    for name, conn in self.connections.items():
                        if not conn.connected and self.auto_reconnect_enabled:
                            print_info(f"Attempting to reconnect '{name}'...")
                            if conn.connect():
                                print_success(f"Reconnected '{name}'")
                                self._trigger_callback('connected', name)
                            else:
                                print_error(f"Failed to reconnect '{name}'")
                                self._trigger_callback('error', name, error='Reconnection failed')
                
                time.sleep(interval)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        print_info("Connection monitoring started")
    
    def enable_auto_reconnect(self, enabled: bool = True) -> None:
        """Enable or disable auto-reconnect"""
        self.auto_reconnect_enabled = enabled
        print_info(f"Auto-reconnect {'enabled' if enabled else 'disabled'}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        with self.lock:
            total = len(self.connections)
            connected = sum(1 for conn in self.connections.values() if conn.connected)
            
            return {
                'total_connections': total,
                'connected_connections': connected,
                'disconnected_connections': total - connected,
                'current_connection': self.current_connection,
                'auto_reconnect_enabled': self.auto_reconnect_enabled
            }
    
    def __repr__(self) -> str:
        """String representation"""
        stats = self.get_stats()
        return f"ConnectionManager(connections={stats['total_connections']}, connected={stats['connected_connections']})"
