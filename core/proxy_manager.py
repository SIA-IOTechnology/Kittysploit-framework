#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Proxy Manager - Intercepts and logs all network requests from framework modules
Supports HTTP, HTTPS, TCP, and other protocols
"""

import socket
import threading
import time
import json
import ssl
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import select
import struct
from http.client import HTTPConnection
import requests

from core.output_handler import print_info, print_success, print_error, print_warning


@dataclass
class NetworkRequest:
    """Represents a captured network request"""
    id: str
    timestamp: str
    protocol: str  # HTTP, HTTPS, TCP, UDP, etc.
    method: str = ""  # GET, POST, etc. for HTTP
    url: str = ""  # Full URL for HTTP
    host: str = ""
    port: int = 0
    headers: Dict[str, str] = None
    body: bytes = b""
    body_text: str = ""
    response_code: int = 0
    response_headers: Dict[str, str] = None
    response_body: bytes = b""
    response_body_text: str = ""
    duration_ms: float = 0.0
    ssl_enabled: bool = False
    error: str = ""
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.response_headers is None:
            self.response_headers = {}
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Convert bytes to base64 for JSON serialization
        if isinstance(data['body'], bytes):
            data['body'] = base64.b64encode(data['body']).decode('utf-8')
        if isinstance(data['response_body'], bytes):
            data['response_body'] = base64.b64encode(data['response_body']).decode('utf-8')
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'NetworkRequest':
        """Create from dictionary"""
        # Convert base64 back to bytes
        if isinstance(data.get('body'), str):
            data['body'] = base64.b64decode(data['body'])
        if isinstance(data.get('response_body'), str):
            data['response_body'] = base64.b64decode(data['response_body'])
        return cls(**data)


class ProxyManager:
    """Manages network request interception and logging"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.is_running = False
        self.captured_requests: List[NetworkRequest] = []
        self.request_counter = 0
        self._lock = threading.Lock()
        self.mode = 'http'
        self.socks_username: Optional[str] = None
        self.socks_password: Optional[str] = None
        self.supported_modes = {'http', 'socks'}
        
        # Proxy server settings
        self.proxy_host = "127.0.0.1"
        self.proxy_port = 8888
        self.proxy_socket = None
        self.proxy_thread = None
        
        # Configuration
        self.capture_http = True
        self.capture_https = True
        self.capture_tcp = True
        self.capture_udp = True
        self.max_requests = 1000  # Limit stored requests
        
        # SSL context for HTTPS interception
        self.ssl_context = None
        self._setup_ssl_context()
    
    def _setup_ssl_context(self):
        """Setup SSL context for HTTPS interception"""
        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        except Exception as e:
            if self.verbose:
                print_error(f"Failed to setup SSL context: {e}")
    
    def start(self, host: str = "127.0.0.1", port: int = 8888, mode: str = "http",
              socks_username: Optional[str] = None, socks_password: Optional[str] = None) -> bool:
        """Start the proxy server"""
        try:
            chosen_mode = (mode or "http").lower()
            if chosen_mode not in self.supported_modes:
                raise ValueError(f"Unsupported proxy mode: {mode}")

            self.mode = chosen_mode
            self.socks_username = socks_username
            self.socks_password = socks_password
            self.proxy_host = host
            self.proxy_port = port
            
            # Create proxy socket
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.proxy_socket.bind((host, port))
            self.proxy_socket.listen(10)
            
            self.is_running = True
            
            # Start proxy thread
            self.proxy_thread = threading.Thread(target=self._proxy_loop, daemon=True)
            self.proxy_thread.start()
            
            if self.verbose:
                if self.mode == 'http':
                    print_info("Intercepting HTTP, HTTPS, and TCP traffic")
                else:
                    if socks_username or socks_password:
                        print_warning("SOCKS authentication not supported yet; credentials ignored.")
                    print_info("SOCKS5 proxy listening for TCP traffic")
            
            return True
            
        except Exception as e:
            print_error(f"Failed to start proxy server: {e}")
            return False
    
    def stop(self):
        """Stop the proxy server"""
        self.is_running = False
        
        if self.proxy_socket:
            try:
                self.proxy_socket.close()
            except:
                pass
            self.proxy_socket = None
        
        if self.verbose:
            print_info("Proxy server stopped")
    
    def _proxy_loop(self):
        """Main proxy server loop"""
        while self.is_running:
            try:
                client_socket, address = self.proxy_socket.accept()
                
                # Handle each client in a separate thread
                handler = self._handle_client if self.mode == 'http' else self._handle_socks_client
                client_thread = threading.Thread(
                    target=handler,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()  # Start the thread!
                
            except Exception as e:
                if self.is_running:  # Only log if we're supposed to be running
                    if self.verbose:
                        print_error(f"Error in proxy loop: {e}")
                break
    
    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle a client connection"""
        try:
            if self.verbose:
                print_info(f"New client connection from {address}")
            
            # Read the first line to determine protocol
            first_line = self._read_line(client_socket)
            if not first_line:
                if self.verbose:
                    print_warning(f"No data received from {address}")
                return
            
            if self.verbose:
                print_info(f"First line from {address}: {first_line.decode('utf-8', errors='ignore').strip()}")
            
            if first_line.startswith(b'CONNECT'):
                # Check if it's a known non-HTTP port
                target_info = self._parse_connect_target(first_line)
                if target_info and target_info['port'] in [21, 22, 23, 25, 53, 110, 143, 993, 995]:
                    # Handle as TCP tunnel for known protocols
                    self._handle_tcp_tunnel(client_socket, target_info, address)
                else:
                    # HTTPS CONNECT method
                    self._handle_https_connect(client_socket, first_line, address)
            elif first_line.startswith(b'GET') or first_line.startswith(b'POST') or first_line.startswith(b'PUT') or first_line.startswith(b'DELETE'):
                # HTTP request
                if self.verbose:
                    print_info(f"Handling HTTP request from {address}")
                self._handle_http_request(client_socket, first_line, address)
            else:
                # Generic TCP connection
                if self.verbose:
                    print_info(f"Handling generic TCP connection from {address}")
                self._handle_tcp_connection(client_socket, first_line, address)
                
        except Exception as e:
            if self.verbose:
                print_error(f"Error handling client {address}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_socks_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Minimal SOCKS5 handler that forwards traffic and logs requests."""
        try:
            client_socket.settimeout(5)

            greeting = self._recv_exact(client_socket, 2)
            if not greeting or greeting[0] != 5:
                return
            nmethods = greeting[1]
            self._recv_exact(client_socket, nmethods)  # Consume methods list
            client_socket.sendall(b'\x05\x00')  # No authentication

            request_header = self._recv_exact(client_socket, 4)
            if len(request_header) < 4 or request_header[0] != 5:
                return

            cmd = request_header[1]
            atyp = request_header[3]
            if cmd != 1:  # Only CONNECT supported
                client_socket.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            if atyp == 1:  # IPv4
                dest_address = socket.inet_ntoa(self._recv_exact(client_socket, 4))
            elif atyp == 3:  # Domain name
                length = self._recv_exact(client_socket, 1)
                if not length:
                    return
                dest_address = self._recv_exact(client_socket, length[0]).decode('utf-8', errors='ignore')
            elif atyp == 4:  # IPv6
                addr_bytes = self._recv_exact(client_socket, 16)
                try:
                    dest_address = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                except AttributeError:
                    dest_address = ':'.join(f'{b:02x}' for b in addr_bytes)
            else:
                client_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return

            port_bytes = self._recv_exact(client_socket, 2)
            if len(port_bytes) < 2:
                return
            dest_port = struct.unpack('!H', port_bytes)[0]

            # Send success reply
            client_socket.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0))

            guessed_protocol = self._protocol_for_port(dest_port, default='SOCKS5')
            request = NetworkRequest(
                id=f"req_{self.request_counter}",
                timestamp=datetime.now().isoformat(),
                protocol="SOCKS5",
                method="CONNECT",
                url=f"{guessed_protocol.lower()}://{dest_address}:{dest_port}",
                host=dest_address,
                port=dest_port,
                headers={
                    'x-transport': 'SOCKS5',
                    'x-guessed-protocol': guessed_protocol
                },
                ssl_enabled=False
            )

            self._create_tcp_tunnel(client_socket, dest_address, dest_port, request)

        except Exception as e:
            if self.verbose:
                print_error(f"SOCKS client error from {address}: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
    
    def _handle_http_request(self, client_socket: socket.socket, first_line: bytes, address: Tuple[str, int]):
        """Handle HTTP request"""
        try:
            # Parse HTTP request
            request_data = self._parse_http_request(client_socket, first_line)
            if not request_data:
                return
            
            # Create request object
            request = NetworkRequest(
                id=f"req_{self.request_counter}",
                timestamp=datetime.now().isoformat(),
                protocol="HTTP",
                method=request_data['method'],
                url=request_data['url'],
                host=request_data['host'],
                port=request_data['port'],
                headers=request_data['headers'],
                body=request_data['body'],
                body_text=request_data['body'].decode('utf-8', errors='ignore'),
                ssl_enabled=False
            )
            
            # Forward request to target server
            response_data = self._forward_http_request(request_data)
            
            if response_data:
                request.response_code = response_data.get('status_code', 0)
                request.response_headers = response_data.get('headers', {})
                body = response_data.get('body', b'') or b''
                request.response_body = body
                request.response_body_text = body.decode('utf-8', errors='ignore')
                request.duration_ms = response_data.get('duration_ms', 0.0)
                
                # Send response back to client
                self._send_http_response(client_socket, response_data)
            else:
                request.error = "Upstream request failed"
                self._send_http_error(client_socket, 504, "Gateway Timeout")
            
            # Store request
            self._store_request(request)
            
            if self.verbose:
                print_info(f"HTTP {request.method} {request.url} -> {request.response_code}")
                
        except Exception as e:
            if self.verbose:
                print_error(f"Error handling HTTP request: {e}")
    
    def _handle_https_connect(self, client_socket: socket.socket, first_line: bytes, address: Tuple[str, int]):
        """Handle HTTPS CONNECT request"""
        try:
            # Parse CONNECT request
            parts = first_line.decode('utf-8').split()
            if len(parts) < 2:
                return
            
            target = parts[1]
            if ':' in target:
                host, port = target.split(':')
                port = int(port)
            else:
                host = target
                port = 443
            
            # Send CONNECT response
            client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # For HTTPS, we need to create a direct tunnel without SSL wrapping
            # The client will handle SSL after the tunnel is established
            self._create_https_tunnel(client_socket, host, port, address)
            
        except Exception as e:
            if self.verbose:
                print_error(f"Error handling HTTPS CONNECT: {e}")
    
    def _parse_connect_target(self, connect_line: bytes) -> Optional[Dict]:
        """Parse CONNECT target from first line"""
        try:
            line = connect_line.decode('utf-8').strip()
            parts = line.split()
            if len(parts) >= 2:
                target = parts[1]
                if ':' in target:
                    host, port = target.split(':')
                    return {'host': host, 'port': int(port)}
        except Exception as e:
            if self.verbose:
                print_error(f"Error parsing CONNECT target: {e}")
        return None
    
    def _protocol_for_port(self, port: int, default: str = 'TCP') -> str:
        """Best-effort guess of protocol type based on destination port."""
        protocol_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S'
        }
        return protocol_map.get(port, default)
    
    def _handle_tcp_tunnel(self, client_socket: socket.socket, target_info: Dict, address: Tuple[str, int]):
        """Handle TCP tunnel for non-HTTP protocols"""
        try:
            host = target_info['host']
            port = target_info['port']
            
            # Determine protocol based on port
            protocol = self._protocol_for_port(port, default='TCP')
             
            # Send CONNECT response
            client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # Create request object for logging
            request = NetworkRequest(
                id=f"req_{self.request_counter}",
                timestamp=datetime.now().isoformat(),
                protocol=protocol,
                method="CONNECT",
                url=f"{protocol.lower()}://{host}:{port}",
                host=host,
                port=port,
                ssl_enabled=False
            )
            
            # Create tunnel to target server
            self._create_tcp_tunnel(client_socket, host, port, request)
            
        except Exception as e:
            if self.verbose:
                print_error(f"Error handling TCP tunnel: {e}")
    
    def _create_tcp_tunnel(self, client_socket: socket.socket, host: str, port: int, request: NetworkRequest):
        """Create TCP tunnel to target server"""
        try:
            # Connect to target server
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((host, port))
            
            # Tunnel data between client and server
            self._tunnel_data(client_socket, target_socket, request)
            
            target_socket.close()
            
        except Exception as e:
            if self.verbose:
                print_error(f"Error creating TCP tunnel: {e}")
    
    def _handle_tcp_connection(self, client_socket: socket.socket, first_line: bytes, address: Tuple[str, int]):
        """Handle generic TCP connection"""
        try:
            # For TCP, we'll just log the connection attempt
            # In a real implementation, you'd need to know the target
            request = NetworkRequest(
                id=f"req_{self.request_counter}",
                timestamp=datetime.now().isoformat(),
                protocol="TCP",
                host=address[0],
                port=address[1],
                body=first_line,
                body_text=first_line.decode('utf-8', errors='ignore'),
                ssl_enabled=False
            )
            
            self._store_request(request)
            
            if self.verbose:
                print_info(f"TCP connection from {address[0]}:{address[1]}")
                
        except Exception as e:
            if self.verbose:
                print_error(f"Error handling TCP connection: {e}")
    
    def _parse_http_request(self, client_socket: socket.socket, first_line: bytes) -> Optional[Dict]:
        """Parse HTTP request from client"""
        try:
            # Parse request line
            parts = first_line.decode('utf-8').strip().split()
            if len(parts) < 3:
                return None
            
            method = parts[0]
            url = parts[1]
            version = parts[2]
            
            # Read headers
            headers = {}
            while True:
                line = self._read_line(client_socket)
                if not line or line == b'\r\n':
                    break
                
                if b':' in line:
                    key, value = line.decode('utf-8').split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Determine host and port from Host header
            host = headers.get('host', 'localhost')
            if ':' in host:
                host, port = host.split(':', 1)
                try:
                    port = int(port)
                except ValueError:
                    port = 80
            else:
                port = 80  # Default HTTP port
            
            # Build full URL
            if url.startswith('http://') or url.startswith('https://'):
                full_url = url
            else:
                # Relative URL - construct full URL
                full_url = f"http://{host}:{port}{url}"
            
            # Read body if present
            body = b""
            content_length = headers.get('content-length')
            if content_length:
                try:
                    body_length = int(content_length)
                    body = client_socket.recv(body_length)
                except ValueError:
                    pass  # Invalid content-length, ignore
            
            return {
                'method': method,
                'url': full_url,
                'version': version,
                'host': host,
                'port': port,
                'headers': headers,
                'body': body
            }
            
        except Exception as e:
            if self.verbose:
                print_error(f"Error parsing HTTP request: {e}")
            return None
    
    def _forward_http_request(self, request_data: Dict) -> Optional[Dict]:
        """Forward HTTP request to target server"""
        try:
            start_time = time.time()

            # Use the full URL from the request
            target_url = request_data['url']
            
            # Clean up headers for forwarding
            headers = request_data['headers'].copy()
            headers.pop('proxy-connection', None)
            headers.pop('connection', None)
            headers.pop('proxy-authorization', None)
            
            # Set proper Host header
            if request_data['port'] in (80, 443):
                headers['host'] = request_data['host']
            else:
                headers['host'] = f"{request_data['host']}:{request_data['port']}"

            body = request_data['body'] if request_data['body'] else None

            # Create session with proper configuration
            session = requests.Session()
            session.trust_env = False
            
            # Disable SSL verification for proxy interception
            session.verify = False
            
            # Suppress SSL warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            response = session.request(
                method=request_data['method'],
                url=target_url,
                headers=headers,
                data=body,
                timeout=30,  # Increased timeout
                allow_redirects=False,
                stream=False
            )

            response_headers = {k.lower(): v for k, v in response.headers.items()}
            response_body = response.content
            response_data = {
                'status_code': response.status_code,
                'reason': response.reason,
                'headers': response_headers,
                'body': response_body,
                'duration_ms': (time.time() - start_time) * 1000
            }
            session.close()
            return response_data

        except requests.exceptions.Timeout:
            if self.verbose:
                print_error(f"Timeout forwarding HTTP request to {request_data.get('url', 'unknown')}")
            return None
        except requests.exceptions.ConnectionError as e:
            if self.verbose:
                print_error(f"Connection error forwarding HTTP request: {e}")
            return None
        except Exception as e:
            if self.verbose:
                print_error(f"Error forwarding HTTP request: {e}")
            return None
    
    def _read_http_response(self, socket: socket.socket) -> Dict:
        """Read HTTP response from socket"""
        try:
            # Read status line
            status_line = self._read_line(socket).decode('utf-8')
            parts = status_line.split()
            status_code = int(parts[1]) if len(parts) > 1 else 0
            
            # Read headers
            headers = {}
            while True:
                line = self._read_line(socket)
                if not line or line == b'\r\n':
                    break
                
                if b':' in line:
                    key, value = line.decode('utf-8').split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Read body
            body = b""
            content_length = headers.get('content-length')
            if content_length:
                body = socket.recv(int(content_length))
            else:
                # Read until connection closes
                while True:
                    try:
                        chunk = socket.recv(4096)
                        if not chunk:
                            break
                        body += chunk
                    except:
                        break
            
            return {
                'status_code': status_code,
                'headers': headers,
                'body': body
            }
            
        except Exception as e:
            if self.verbose:
                print_error(f"Error reading HTTP response: {e}")
            return {'status_code': 0, 'headers': {}, 'body': b''}
    
    def _send_http_response(self, client_socket: socket.socket, response_data: Dict):
        """Send HTTP response to client"""
        try:
            status_code = response_data.get('status_code', 502)
            reason = response_data.get('reason') or 'OK'
            body = response_data.get('body', b'') or b''
            headers = (response_data.get('headers') or {}).copy()

            headers.pop('transfer-encoding', None)
            headers.setdefault('content-length', str(len(body)))
            headers.setdefault('connection', 'close')

            status_line = f"HTTP/1.1 {status_code} {reason}\r\n"
            client_socket.sendall(status_line.encode('utf-8'))

            for key, value in headers.items():
                header_line = f"{key.title()}: {value}\r\n"
                client_socket.sendall(header_line.encode('utf-8'))

            client_socket.sendall(b'\r\n')
            if body:
                client_socket.sendall(body)

        except Exception as e:
            if self.verbose:
                print_error(f"Error sending HTTP response: {e}")
    
    def _send_http_error(self, client_socket: socket.socket, status: int, reason: str):
        """Send a minimal HTTP error response to the client."""
        body = f'{{"error": "{reason}"}}'.encode('utf-8')
        headers = {
            'content-type': 'application/json',
            'content-length': str(len(body)),
            'connection': 'close'
        }
        response = {
            'status_code': status,
            'reason': reason,
            'headers': headers,
            'body': body
        }
        self._send_http_response(client_socket, response)
    
    def _create_https_tunnel(self, client_socket: socket.socket, host: str, port: int, address: Tuple[str, int]):
        """Create HTTPS tunnel (CONNECT method)"""
        try:
            # Connect to target server
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)
            target_socket.connect((host, port))
            
            # Create request object for logging
            request = NetworkRequest(
                id=f"req_{self.request_counter}",
                timestamp=datetime.now().isoformat(),
                protocol="HTTPS",
                method="CONNECT",
                url=f"https://{host}:{port}",
                host=host,
                port=port,
                ssl_enabled=True,
                response_code=200  # CONNECT successful
            )
            
            if self.verbose:
                print_info(f"HTTPS tunnel established to {host}:{port}")
            
            # Tunnel data between client and server (raw data, no SSL wrapping)
            self._tunnel_data(client_socket, target_socket, request)
            
            target_socket.close()
            
        except socket.timeout:
            if self.verbose:
                print_error(f"Timeout connecting to {host}:{port}")
            # Create failed request object
            request = NetworkRequest(
                id=f"req_{self.request_counter}",
                timestamp=datetime.now().isoformat(),
                protocol="HTTPS",
                method="CONNECT",
                url=f"https://{host}:{port}",
                host=host,
                port=port,
                ssl_enabled=True,
                response_code=504,  # Gateway Timeout
                error="Connection timeout"
            )
            self._store_request(request)
        except Exception as e:
            if self.verbose:
                print_error(f"Error creating HTTPS tunnel to {host}:{port}: {e}")
            # Create failed request object
            request = NetworkRequest(
                id=f"req_{self.request_counter}",
                timestamp=datetime.now().isoformat(),
                protocol="HTTPS",
                method="CONNECT",
                url=f"https://{host}:{port}",
                host=host,
                port=port,
                ssl_enabled=True,
                response_code=502,  # Bad Gateway
                error=str(e)
            )
            self._store_request(request)
    
    def _create_ssl_tunnel(self, client_socket: socket.socket, host: str, port: int, address: Tuple[str, int]):
        """Create SSL tunnel for HTTPS (legacy method)"""
        try:
            # Connect to target server
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)
            target_socket.connect((host, port))
            
            # Create SSL context for target
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            ssl_socket = ssl_context.wrap_socket(target_socket, server_hostname=host)
            
            # Create request object for logging
            request = NetworkRequest(
                id=f"req_{self.request_counter}",
                timestamp=datetime.now().isoformat(),
                protocol="HTTPS",
                method="CONNECT",
                url=f"https://{host}:{port}",
                host=host,
                port=port,
                ssl_enabled=True
            )
            
            if self.verbose:
                print_info(f"SSL tunnel established to {host}:{port}")
            
            # Tunnel data between client and server
            self._tunnel_data(client_socket, ssl_socket, request)
            
            ssl_socket.close()
            target_socket.close()
            
        except ssl.SSLError as e:
            if self.verbose:
                print_error(f"SSL error creating tunnel to {host}:{port}: {e}")
        except socket.timeout:
            if self.verbose:
                print_error(f"Timeout connecting to {host}:{port}")
        except Exception as e:
            if self.verbose:
                print_error(f"Error creating SSL tunnel to {host}:{port}: {e}")
    
    def _tunnel_data(self, client_socket: socket.socket, target_socket: socket.socket, request: NetworkRequest):
        """Tunnel data between client and target"""
        try:
            start_time = time.time()
            total_client_data = 0
            total_target_data = 0
            
            while True:
                ready_sockets, _, _ = select.select([client_socket, target_socket], [], [], 1.0)
                
                if not ready_sockets:
                    # Check for timeout
                    if time.time() - start_time > 300:  # 5 minute timeout
                        if self.verbose:
                            print_warning(f"Tunnel timeout for {request.protocol} {request.host}:{request.port}")
                        # Update status for timeout
                        request.response_code = 504  # Gateway Timeout
                        request.error = "Tunnel timeout"
                        break
                    continue
                
                for sock in ready_sockets:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            return
                        
                        if sock == client_socket:
                            # Data from client to target
                            target_socket.send(data)
                            request.body += data
                            total_client_data += len(data)
                            
                            if self.verbose and len(data) < 200:
                                print_info(f"[{request.protocol}] Client -> Target: {len(data)} bytes")
                        else:
                            # Data from target to client
                            client_socket.send(data)
                            request.response_body += data
                            total_target_data += len(data)
                            
                            if self.verbose and len(data) < 200:
                                print_info(f"[{request.protocol}] Target -> Client: {len(data)} bytes")
                            
                    except socket.error:
                        return
                    except Exception as e:
                        if self.verbose:
                            print_error(f"Error in tunnel data transfer: {e}")
                        # Update status for error
                        request.response_code = 502  # Bad Gateway
                        request.error = str(e)
                        return
                        
        except Exception as e:
            if self.verbose:
                print_error(f"Error in data tunnel: {e}")
            # Update status for error
            request.response_code = 502  # Bad Gateway
            request.error = str(e)
        finally:
            # Update request with final data
            request.duration_ms = (time.time() - start_time) * 1000
            request.body_text = request.body.decode('utf-8', errors='ignore')
            request.response_body_text = request.response_body.decode('utf-8', errors='ignore')
            
            # For successful tunnels, ensure we have a proper status
            if request.response_code == 0 and request.duration_ms > 0:
                request.response_code = 200  # Successful tunnel
            
            if self.verbose:
                print_info(f"[{request.protocol}] Tunnel closed - Client: {total_client_data} bytes, Target: {total_target_data} bytes")
            
            # Store the request
            self._store_request(request)
    
    def _read_line(self, socket: socket.socket) -> bytes:
        """Read a line from socket"""
        line = b""
        socket.settimeout(5)  # Set timeout for reading
        
        try:
            while True:
                char = socket.recv(1)
                if not char:
                    break
                line += char
                if line.endswith(b'\n'):
                    break
                # Prevent infinite loops with very long lines
                if len(line) > 8192:
                    break
        except socket.timeout:
            if self.verbose:
                print_warning("Timeout reading line from socket")
        except Exception as e:
            if self.verbose:
                print_error(f"Error reading line from socket: {e}")
        
        return line
    
    def _recv_exact(self, sock: socket.socket, size: int) -> bytes:
        """Read an exact number of bytes from a socket."""
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                break
            data += chunk
        return data
    
    def _store_request(self, request: NetworkRequest):
        """Store captured request"""
        with self._lock:
            self.request_counter += 1
            request.id = f"req_{self.request_counter}"
            
            self.captured_requests.append(request)
            
            # Limit stored requests
            if len(self.captured_requests) > self.max_requests:
                self.captured_requests.pop(0)
    
    def get_requests(self, limit: int = 50) -> List[Dict]:
        """Get captured requests"""
        with self._lock:
            return [req.to_dict() for req in self.captured_requests[-limit:]]
    
    def get_request_by_id(self, request_id: str) -> Optional[Dict]:
        """Get specific request by ID"""
        with self._lock:
            for req in self.captured_requests:
                if req.id == request_id:
                    return req.to_dict()
        return None
    
    def clear_requests(self):
        """Clear all captured requests"""
        with self._lock:
            self.captured_requests.clear()
            self.request_counter = 0
    
    def export_requests(self, filename: str) -> bool:
        """Export requests to JSON file"""
        try:
            with self._lock:
                data = {
                    'exported_at': datetime.now().isoformat(),
                    'total_requests': len(self.captured_requests),
                    'requests': [req.to_dict() for req in self.captured_requests]
                }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            if self.verbose:
                print_success(f"Exported {len(self.captured_requests)} requests to {filename}")
            
            return True
            
        except Exception as e:
            if self.verbose:
                print_error(f"Failed to export requests: {e}")
            return False
    
    def replay_request(self, request_id: str) -> bool:
        """Replay a captured request"""
        try:
            request_data = self.get_request_by_id(request_id)
            if not request_data:
                if self.verbose:
                    print_error(f"Request {request_id} not found")
                return False
            
            # Convert back to NetworkRequest object
            request = NetworkRequest.from_dict(request_data)
            
            if request.protocol in ['HTTP', 'HTTPS']:
                return self._replay_http_request(request)
            else:
                if self.verbose:
                    print_warning(f"Replay not supported for protocol: {request.protocol}")
                return False
                
        except Exception as e:
            if self.verbose:
                print_error(f"Failed to replay request: {e}")
            return False
    
    def _replay_http_request(self, request: NetworkRequest) -> bool:
        """Replay HTTP/HTTPS request"""
        try:
            import requests
            
            # Prepare request
            url = request.url
            if not url.startswith('http'):
                url = f"http://{request.host}:{request.port}{url}"
            
            headers = request.headers.copy()
            
            # Make request
            if request.method == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif request.method == 'POST':
                response = requests.post(url, data=request.body, headers=headers, timeout=30)
            elif request.method == 'PUT':
                response = requests.put(url, data=request.body, headers=headers, timeout=30)
            elif request.method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=30)
            else:
                if self.verbose:
                    print_warning(f"Unsupported method for replay: {request.method}")
                return False
            
            if self.verbose:
                print_success(f"Replayed {request.method} {url} -> {response.status_code}")
            
            return True
            
        except Exception as e:
            if self.verbose:
                print_error(f"Failed to replay HTTP request: {e}")
            return False
    
    def get_status(self) -> Dict:
        """Get proxy status"""
        return {
            'is_running': self.is_running,
            'mode': self.mode,
            'host': self.proxy_host,
            'port': self.proxy_port,
            'captured_requests': len(self.captured_requests),
            'capture_http': self.capture_http,
            'capture_https': self.capture_https,
            'capture_tcp': self.capture_tcp,
            'capture_udp': self.capture_udp
        }
