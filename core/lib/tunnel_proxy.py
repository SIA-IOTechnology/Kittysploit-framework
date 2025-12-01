#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tunneling and Proxy System for KittySploit
"""

import socket
import threading
import time
import requests
from typing import Optional, Dict, Any, Callable
from core.output_handler import print_info, print_success, print_error, print_warning
from kittysploit.remote_connection import RemoteConnection

class Tunnel:
    """Tunnel manager for port forwarding"""
    
    def __init__(self, local_host: str, local_port: int, 
                 remote_host: str, remote_port: int, 
                 via_connection: Optional[RemoteConnection] = None):
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.via_connection = via_connection
        self.server_socket = None
        self.active_connections = []
        self.running = False
        self.thread = None
    
    def start(self) -> bool:
        """Start the tunnel"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.local_host, self.local_port))
            self.server_socket.listen(5)
            
            self.running = True
            self.thread = threading.Thread(target=self._tunnel_loop, daemon=True)
            self.thread.start()
            
            print_success(f"Tunnel started: {self.local_host}:{self.local_port} -> {self.remote_host}:{self.remote_port}")
            return True
            
        except Exception as e:
            print_error(f"Failed to start tunnel: {e}")
            return False
    
    def stop(self) -> bool:
        """Stop the tunnel"""
        try:
            self.running = False
            
            # Close all active connections
            for conn in self.active_connections:
                try:
                    conn.close()
                except:
                    pass
            self.active_connections.clear()
            
            # Close server socket
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            
            print_info("Tunnel stopped")
            return True
            
        except Exception as e:
            print_error(f"Error stopping tunnel: {e}")
            return False
    
    def _tunnel_loop(self):
        """Main tunnel loop"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print_info(f"New connection from {addr}")
                
                # Handle connection in separate thread
                conn_thread = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, addr),
                    daemon=True
                )
                conn_thread.start()
                
            except Exception as e:
                if self.running:
                    print_error(f"Tunnel error: {e}")
                break
    
    def _handle_connection(self, client_socket, addr):
        """Handle individual connection"""
        try:
            if self.via_connection and self.via_connection.connected:
                # Tunnel through remote connection (SSH tunnel)
                self._handle_ssh_tunnel(client_socket)
            else:
                # Direct tunnel
                self._handle_direct_tunnel(client_socket)
                
        except Exception as e:
            print_error(f"Connection handling error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_direct_tunnel(self, client_socket):
        """Handle direct tunnel (no SSH)"""
        try:
            # Connect to remote host
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((self.remote_host, self.remote_port))
            
            # Add to active connections
            self.active_connections.append(remote_socket)
            
            # Start bidirectional forwarding
            self._forward_data(client_socket, remote_socket)
            
        except Exception as e:
            print_error(f"Direct tunnel error: {e}")
        finally:
            try:
                remote_socket.close()
            except:
                pass
    
    def _handle_ssh_tunnel(self, client_socket):
        """Handle SSH tunnel"""
        try:
            # Use SSH connection to create tunnel
            tunnel_cmd = f"ssh -L {self.local_port}:{self.remote_host}:{self.remote_port} -N"
            result = self.via_connection.send_command(tunnel_cmd)
            
            if result:
                print_info("SSH tunnel established")
                # Handle the tunneled connection
                self._forward_data(client_socket, None)
            else:
                print_error("Failed to establish SSH tunnel")
                
        except Exception as e:
            print_error(f"SSH tunnel error: {e}")
    
    def _forward_data(self, client_socket, remote_socket):
        """Forward data between client and remote sockets"""
        def forward(src, dst, name):
            try:
                while self.running:
                    data = src.recv(4096)
                    if not data:
                        break
                    if dst:
                        dst.send(data)
            except Exception as e:
                if self.running:
                    print_error(f"Forwarding error ({name}): {e}")
        
        # Start forwarding threads
        if remote_socket:
            client_to_remote = threading.Thread(
                target=forward, 
                args=(client_socket, remote_socket, "client->remote"),
                daemon=True
            )
            remote_to_client = threading.Thread(
                target=forward, 
                args=(remote_socket, client_socket, "remote->client"),
                daemon=True
            )
            
            client_to_remote.start()
            remote_to_client.start()
            
            # Wait for threads to complete
            client_to_remote.join()
            remote_to_client.join()
    
    def get_status(self) -> Dict[str, Any]:
        """Get tunnel status"""
        return {
            'running': self.running,
            'local_endpoint': f"{self.local_host}:{self.local_port}",
            'remote_endpoint': f"{self.remote_host}:{self.remote_port}",
            'active_connections': len(self.active_connections),
            'via_connection': self.via_connection is not None
        }

class Proxy:
    """HTTP/HTTPS Proxy server"""
    
    def __init__(self, host: str = 'localhost', port: int = 8080):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.thread = None
        self.target_host = None
        self.target_port = None
        self.target_protocol = 'http'
    
    def start(self, target_host: str, target_port: int = 80, protocol: str = 'http') -> bool:
        """
        Start the proxy server
        
        Args:
            target_host: Target host to proxy to
            target_port: Target port
            protocol: Protocol (http/https)
        """
        try:
            self.target_host = target_host
            self.target_port = target_port
            self.target_protocol = protocol
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            self.thread = threading.Thread(target=self._proxy_loop, daemon=True)
            self.thread.start()
            
            print_success(f"Proxy started: {self.host}:{self.port} -> {protocol}://{target_host}:{target_port}")
            return True
            
        except Exception as e:
            print_error(f"Failed to start proxy: {e}")
            return False
    
    def stop(self) -> bool:
        """Stop the proxy server"""
        try:
            self.running = False
            
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            
            print_info("Proxy stopped")
            return True
            
        except Exception as e:
            print_error(f"Error stopping proxy: {e}")
            return False
    
    def _proxy_loop(self):
        """Main proxy loop"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print_info(f"New proxy connection from {addr}")
                
                # Handle connection in separate thread
                conn_thread = threading.Thread(
                    target=self._handle_proxy_connection,
                    args=(client_socket, addr),
                    daemon=True
                )
                conn_thread.start()
                
            except Exception as e:
                if self.running:
                    print_error(f"Proxy error: {e}")
                break
    
    def _handle_proxy_connection(self, client_socket, addr):
        """Handle proxy connection"""
        try:
            # Read HTTP request
            request = client_socket.recv(4096).decode('utf-8')
            
            if not request:
                return
            
            # Parse request
            lines = request.split('\n')
            if not lines:
                return
            
            # Extract method, path, and headers
            first_line = lines[0].strip()
            method, path, version = first_line.split(' ', 2)
            
            # Build target URL
            if path.startswith('http://') or path.startswith('https://'):
                target_url = path
            else:
                target_url = f"{self.target_protocol}://{self.target_host}:{self.target_port}{path}"
            
            # Forward request
            self._forward_request(client_socket, method, target_url, request)
            
        except Exception as e:
            print_error(f"Proxy connection error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _forward_request(self, client_socket, method, target_url, original_request):
        """Forward HTTP request to target"""
        try:
            # Send request to target
            if method.upper() == 'GET':
                response = requests.get(target_url, timeout=10)
            elif method.upper() == 'POST':
                # Extract body from original request
                body_start = original_request.find('\r\n\r\n')
                if body_start != -1:
                    body = original_request[body_start + 4:]
                    response = requests.post(target_url, data=body, timeout=10)
                else:
                    response = requests.post(target_url, timeout=10)
            else:
                response = requests.request(method, target_url, timeout=10)
            
            # Send response back to client
            response_text = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
            for header, value in response.headers.items():
                response_text += f"{header}: {value}\r\n"
            response_text += "\r\n"
            response_text += response.text
            
            client_socket.send(response_text.encode('utf-8'))
            
        except Exception as e:
            print_error(f"Request forwarding error: {e}")
            # Send error response
            error_response = "HTTP/1.1 500 Internal Server Error\r\n\r\nProxy Error"
            client_socket.send(error_response.encode('utf-8'))
    
    def get_status(self) -> Dict[str, Any]:
        """Get proxy status"""
        return {
            'running': self.running,
            'proxy_endpoint': f"{self.host}:{self.port}",
            'target_endpoint': f"{self.target_protocol}://{self.target_host}:{self.target_port}" if self.target_host else None
        }

class TunnelProxyManager:
    """Manager for tunnels and proxies"""
    
    def __init__(self):
        self.tunnels: Dict[str, Tunnel] = {}
        self.proxies: Dict[str, Proxy] = {}
    
    def create_tunnel(self, name: str, local_host: str, local_port: int, 
                     remote_host: str, remote_port: int, 
                     via_connection: Optional[RemoteConnection] = None) -> Tunnel:
        """Create a new tunnel"""
        tunnel = Tunnel(local_host, local_port, remote_host, remote_port, via_connection)
        self.tunnels[name] = tunnel
        print_info(f"Tunnel '{name}' created")
        return tunnel
    
    def create_proxy(self, name: str, host: str = 'localhost', port: int = 8080) -> Proxy:
        """Create a new proxy"""
        proxy = Proxy(host, port)
        self.proxies[name] = proxy
        print_info(f"Proxy '{name}' created")
        return proxy
    
    def start_tunnel(self, name: str) -> bool:
        """Start a tunnel"""
        if name not in self.tunnels:
            print_error(f"Tunnel '{name}' not found")
            return False
        
        return self.tunnels[name].start()
    
    def stop_tunnel(self, name: str) -> bool:
        """Stop a tunnel"""
        if name not in self.tunnels:
            print_error(f"Tunnel '{name}' not found")
            return False
        
        return self.tunnels[name].stop()
    
    def start_proxy(self, name: str, target_host: str, target_port: int = 80, protocol: str = 'http') -> bool:
        """Start a proxy"""
        if name not in self.proxies:
            print_error(f"Proxy '{name}' not found")
            return False
        
        return self.proxies[name].start(target_host, target_port, protocol)
    
    def stop_proxy(self, name: str) -> bool:
        """Stop a proxy"""
        if name not in self.proxies:
            print_error(f"Proxy '{name}' not found")
            return False
        
        return self.proxies[name].stop()
    
    def list_tunnels(self) -> Dict[str, Dict[str, Any]]:
        """List all tunnels"""
        return {name: tunnel.get_status() for name, tunnel in self.tunnels.items()}
    
    def list_proxies(self) -> Dict[str, Dict[str, Any]]:
        """List all proxies"""
        return {name: proxy.get_status() for name, proxy in self.proxies.items()}
    
    def remove_tunnel(self, name: str) -> bool:
        """Remove a tunnel"""
        if name not in self.tunnels:
            print_error(f"Tunnel '{name}' not found")
            return False
        
        self.tunnels[name].stop()
        del self.tunnels[name]
        print_info(f"Tunnel '{name}' removed")
        return True
    
    def remove_proxy(self, name: str) -> bool:
        """Remove a proxy"""
        if name not in self.proxies:
            print_error(f"Proxy '{name}' not found")
            return False
        
        self.proxies[name].stop()
        del self.proxies[name]
        print_info(f"Proxy '{name}' removed")
        return True
