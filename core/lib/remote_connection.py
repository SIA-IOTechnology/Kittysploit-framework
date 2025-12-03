#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Remote Connection Manager for KittySploit
"""

import socket
import paramiko
import requests
import json
import time
from typing import Optional, Dict, Any, Union
from core.output_handler import print_info, print_success, print_error, print_warning

class RemoteConnection:
    """Manager for remote connections to various services"""
    
    def __init__(self, host: str, port: int, protocol: str = 'tcp', 
                 username: str = None, password: str = None, 
                 api_key: str = None, timeout: int = 10, **kwargs):
        """
        Initialize remote connection
        
        Args:
            host: Target host
            port: Target port
            protocol: Connection protocol (tcp, ssh, http, https, rpc, api)
            username: Username for authentication
            password: Password for authentication
            api_key: API key for API connections
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.username = username
        self.password = password
        self.api_key = api_key
        self.timeout = timeout
        self.connection = None
        self.connected = False
        
    def connect(self) -> bool:
        """Establish connection to remote host"""
        try:
            if self.protocol in ['tcp', 'tcp_raw']:
                return self._connect_tcp()
            elif self.protocol == 'ssh':
                return self._connect_ssh()
            elif self.protocol in ['http', 'https']:
                return self._connect_http()
            elif self.protocol == 'rpc':
                return self._connect_rpc()
            elif self.protocol == 'api':
                return self._connect_api()
            else:
                print_error(f"Unsupported protocol: {self.protocol}")
                return False
        except Exception as e:
            print_error(f"Connection failed: {e}")
            return False
    
    def _connect_tcp(self) -> bool:
        """Connect via raw TCP (with proxy support if configured)"""
        try:
            # Check if proxy is configured
            proxy_host = None
            proxy_port = None
            proxy_type = None
            
            # Check framework proxy config
            if hasattr(self, 'framework') and self.framework:
                if hasattr(self.framework, 'is_proxy_enabled') and self.framework.is_proxy_enabled():
                    proxy_url = self.framework.get_proxy_url()
                    if proxy_url and proxy_url.startswith('socks'):
                        import re
                        match = re.match(r'socks(\d)://([^:]+):(\d+)', proxy_url)
                        if match:
                            proxy_type_num = int(match.group(1))
                            proxy_host = match.group(2)
                            proxy_port = int(match.group(3))
                            
                            # Import socks
                            try:
                                import socks
                                proxy_type = socks.SOCKS5 if proxy_type_num == 5 else socks.SOCKS4
                            except ImportError:
                                print_warning("PySocks not installed - proxy not available for TCP")
                                proxy_host = None
            
            # Create socket
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Configure proxy if available
            if proxy_host and proxy_port and proxy_type:
                try:
                    self.connection.set_proxy(proxy_type, proxy_host, proxy_port)
                except AttributeError:
                    print_warning("SOCKS proxy not available for this socket")
            
            self.connection.settimeout(self.timeout)
            self.connection.connect((self.host, self.port))
            self.connected = True
            print_success(f"TCP connection established to {self.host}:{self.port}")
            return True
        except Exception as e:
            print_error(f"TCP connection failed: {e}")
            return False
    
    def _connect_ssh(self) -> bool:
        """Connect via SSH"""
        try:
            if not self.username:
                print_error("SSH requires username")
                return False
            
            self.connection = paramiko.SSHClient()
            self.connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.connection.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            self.connected = True
            print_success(f"SSH connection established to {self.username}@{self.host}:{self.port}")
            return True
        except Exception as e:
            print_error(f"SSH connection failed: {e}")
            return False
    
    def _connect_http(self) -> bool:
        """Connect via HTTP/HTTPS"""
        try:
            # Determine the correct protocol based on port
            if self.port == 443 or self.protocol == 'https':
                protocol = 'https'
            else:
                protocol = 'http'
            
            url = f"{protocol}://{self.host}:{self.port}"
            response = requests.get(url, timeout=self.timeout, verify=False)
            self.connection = requests.Session()
            self.connection.headers.update({'User-Agent': 'KittySploit/1.0'})
            self.connected = True
            print_success(f"HTTP connection established to {url}")
            return True
        except Exception as e:
            print_error(f"HTTP connection failed: {e}")
            return False
    
    def _connect_rpc(self) -> bool:
        """Connect via RPC (assuming JSON-RPC over HTTP)"""
        try:
            url = f"http://{self.host}:{self.port}/rpc"
            response = requests.post(
                url,
                json={"jsonrpc": "2.0", "method": "ping", "id": 1},
                timeout=self.timeout
            )
            if response.status_code == 200:
                self.connection = requests.Session()
                self.connection.headers.update({
                    'Content-Type': 'application/json',
                    'User-Agent': 'KittySploit/1.0'
                })
                self.connected = True
                print_success(f"RPC connection established to {url}")
                return True
            else:
                print_error(f"RPC connection failed: HTTP {response.status_code}")
                return False
        except Exception as e:
            print_error(f"RPC connection failed: {e}")
            return False
    
    def _connect_api(self) -> bool:
        """Connect via API"""
        try:
            url = f"http://{self.host}:{self.port}/api"
            headers = {'User-Agent': 'KittySploit/1.0'}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            response = requests.get(f"{url}/status", headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                self.connection = requests.Session()
                self.connection.headers.update(headers)
                self.connected = True
                print_success(f"API connection established to {url}")
                return True
            else:
                print_error(f"API connection failed: HTTP {response.status_code}")
                return False
        except Exception as e:
            print_error(f"API connection failed: {e}")
            return False
    
    def send_command(self, command: str) -> Optional[str]:
        """Send command to remote host"""
        if not self.connected:
            print_error("Not connected to remote host")
            return None
        
        try:
            if self.protocol == 'ssh':
                return self._send_ssh_command(command)
            elif self.protocol in ['http', 'https']:
                return self._send_http_request(command)
            elif self.protocol == 'rpc':
                return self._send_rpc_request(command)
            elif self.protocol == 'api':
                return self._send_api_request(command)
            elif self.protocol in ['tcp', 'tcp_raw']:
                return self._send_tcp_data(command)
            else:
                print_error(f"Command sending not supported for protocol: {self.protocol}")
                return None
        except Exception as e:
            print_error(f"Command execution failed: {e}")
            return None
    
    def _send_ssh_command(self, command: str) -> str:
        """Send command via SSH"""
        stdin, stdout, stderr = self.connection.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        if error:
            print_warning(f"SSH command error: {error}")
        
        return output
    
    def _send_http_request(self, command: str) -> str:
        """Send HTTP request"""
        try:
            # Determine the correct protocol based on port
            if self.port == 443 or self.protocol == 'https':
                protocol = 'https'
            else:
                protocol = 'http'
            
            # If command looks like a raw HTTP request, send it directly
            if command.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                # Parse the HTTP request
                lines = command.strip().split('\r\n')
                request_line = lines[0]
                headers = {}
                
                # Parse headers
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                
                # Extract method, path, and version
                method, path, version = request_line.split(' ', 2)
                
                # Send the request
                url = f"{protocol}://{self.host}:{self.port}{path}"
                response = self.connection.request(method, url, headers=headers, timeout=self.timeout)
                
                # Format response
                response_text = f"{version} {response.status_code} {response.reason}\r\n"
                for key, value in response.headers.items():
                    response_text += f"{key}: {value}\r\n"
                response_text += "\r\n" + response.text
                
                return response_text
            else:
                # Send as regular GET request
                url = f"{protocol}://{self.host}:{self.port}/"
                response = self.connection.get(url, timeout=self.timeout)
                return response.text
                
        except Exception as e:
            return f"HTTP request failed: {e}"
    
    def _send_rpc_request(self, command: str) -> str:
        """Send RPC request"""
        try:
            # Parse command as JSON-RPC method
            try:
                method_data = json.loads(command)
                method = method_data.get('method', 'execute')
                params = method_data.get('params', [])
            except:
                method = 'execute'
                params = [command]
            
            rpc_data = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": int(time.time())
            }
            
            response = self.connection.post(
                f"http://{self.host}:{self.port}/rpc",
                json=rpc_data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return json.dumps(result, indent=2)
            else:
                return f"RPC request failed: HTTP {response.status_code}"
        except Exception as e:
            return f"RPC request failed: {e}"
    
    def _send_api_request(self, command: str) -> str:
        """Send API request"""
        try:
            # Parse command as API endpoint
            try:
                command_data = json.loads(command)
                endpoint = command_data.get('endpoint', '/execute')
                method = command_data.get('method', 'POST')
                data = command_data.get('data', {})
            except:
                endpoint = '/execute'
                method = 'POST'
                data = {"command": command}
            
            if method.upper() == 'GET':
                response = self.connection.get(
                    f"http://{self.host}:{self.port}/api{endpoint}",
                    timeout=self.timeout
                )
            else:
                response = self.connection.post(
                    f"http://{self.host}:{self.port}/api{endpoint}",
                    json=data,
                    timeout=self.timeout
                )
            
            return response.text
        except Exception as e:
            return f"API request failed: {e}"
    
    def _send_tcp_data(self, data: str) -> str:
        """Send data via TCP"""
        try:
            self.connection.send(data.encode('utf-8'))
            response = self.connection.recv(4096)
            return response.decode('utf-8')
        except Exception as e:
            return f"TCP data send failed: {e}"
    
    def disconnect(self):
        """Disconnect from remote host"""
        if self.connected:
            try:
                if self.protocol == 'ssh' and self.connection:
                    self.connection.close()
                elif self.connection:
                    self.connection.close()
                self.connected = False
                print_info(f"Disconnected from {self.host}:{self.port}")
            except Exception as e:
                print_warning(f"Error during disconnect: {e}")
    
    def get_info(self) -> Dict[str, Any]:
        """Get connection information"""
        return {
            'host': self.host,
            'port': self.port,
            'protocol': self.protocol,
            'connected': self.connected,
            'username': self.username,
            'timeout': self.timeout
        }
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def interactive(self, prompt: str = None, welcome_message: str = None):
        """
        Start an interactive session with the remote connection
        
        Args:
            prompt: Custom prompt string (default: based on protocol)
            welcome_message: Welcome message to display
        """
        if not self.connected:
            print_error("Not connected to remote host. Please connect first.")
            return False
        
        # Set default prompt based on protocol
        if prompt is None:
            if self.protocol == 'ssh':
                prompt = f"{self.username}@{self.host}:{self.port}$ "
            elif self.protocol in ['http', 'https']:
                prompt = f"HTTP[{self.host}:{self.port}]> "
            elif self.protocol == 'rpc':
                prompt = f"RPC[{self.host}:{self.port}]> "
            elif self.protocol == 'api':
                prompt = f"API[{self.host}:{self.port}]> "
            else:
                prompt = f"{self.host}:{self.port}> "
        
        # Display welcome message
        if welcome_message is None:
            welcome_message = f"Interactive session started with {self.host}:{self.port} via {self.protocol.upper()}"
        
        print_info(welcome_message)
        print_info("Type 'help' for available commands, 'exit' or 'quit' to end session")
        print_info("-" * 60)
        
        try:
            while True:
                try:
                    # Get user input
                    command = input(prompt).strip()
                    
                    # Handle special commands
                    if command.lower() in ['exit', 'quit', 'q']:
                        print_info("Ending interactive session...")
                        break
                    elif command.lower() in ['help', 'h', '?']:
                        self._show_interactive_help()
                        continue
                    elif command.lower() in ['status', 'info']:
                        self._show_connection_info()
                        continue
                    elif command.lower() in ['clear', 'cls']:
                        self._clear_screen()
                        continue
                    elif command.lower() == '':
                        continue
                    
                    # Send command to remote host
                    result = self.send_command(command)
                    
                    if result:
                        print(result)
                    else:
                        print_warning("No response received")
                        
                except KeyboardInterrupt:
                    print_info("\nUse 'exit' or 'quit' to end the session")
                    continue
                except EOFError:
                    print_info("\nEnding interactive session...")
                    break
                    
        except Exception as e:
            print_error(f"Interactive session error: {e}")
            return False
        
        print_info("Interactive session ended")
        return True
    
    def _show_interactive_help(self):
        """Show help for interactive commands"""
        help_text = """
Interactive Commands:
  help, h, ?     - Show this help message
  status, info   - Show connection information
  clear, cls     - Clear the screen
  exit, quit, q  - End interactive session
  
Regular commands will be sent to the remote host.
"""
        print(help_text)
    
    def _show_connection_info(self):
        """Show current connection information"""
        info = self.get_info()
        print(f"""
Connection Information:
  Host: {info['host']}
  Port: {info['port']}
  Protocol: {info['protocol']}
  Connected: {info['connected']}
  Username: {info.get('username', 'N/A')}
  Timeout: {info['timeout']}s
""")
    
    def _clear_screen(self):
        """Clear the screen"""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
    
    def __repr__(self) -> str:
        """String representation"""
        status = "connected" if self.connected else "disconnected"
        return f"RemoteConnection({self.host}:{self.port}, {self.protocol}, {status})"
