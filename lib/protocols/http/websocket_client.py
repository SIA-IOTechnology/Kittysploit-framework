#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WebSocket client library for KittySploit Framework
Provides a standardized interface for WebSocket connections in exploit modules

WebSocket is an extension of HTTP that provides full-duplex communication channels
over a single TCP connection. It starts with an HTTP handshake and then upgrades
to the WebSocket protocol.
"""

import logging
import time
from typing import Dict, List, Any, Optional, Union, Callable
from urllib.parse import urljoin

from core.framework.option import OptString, OptPort, OptBool, OptInteger
from core.framework.base_module import BaseModule

logger = logging.getLogger(__name__)

try:
    import websocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False
    websocket = None

class WebSocket_client(BaseModule):
    """Advanced WebSocket client with security testing capabilities"""
    
    target = OptString("", "Target URL, IP or hostname", True)
    port = OptPort(80, "Target port", True)
    
    ssl = OptBool(False, "SSL enabled: true/false", False, advanced=True)
    verify_ssl = OptBool(False, "Verify SSL certificates: true/false", False, advanced=True)
    timeout = OptInteger(10, "WebSocket timeout in seconds", True, advanced=True)
    proxy = OptString("", "Proxy URL (e.g., 'http://127.0.0.1:8080')", False, advanced=True)
    
    def __init__(self, framework=None):
        """
        Initialize WebSocket client using options from the module.
        Options are defined as class attributes and can be set via set_option().
        """
        super().__init__(framework)
        self.ws = None
        self.connected = False
        self.logger = logger
        
        if not WEBSOCKET_AVAILABLE:
            self.logger.warning("websocket-client library not available. Install with: pip install websocket-client")
    
    def _get_option_value(self, option):
        """Helper to get option value"""
        if hasattr(option, 'value'):
            return option.value
        elif hasattr(option, '__get__'):
            try:
                return option.__get__(self, type(self))
            except:
                return option
        return option
    
    def _build_ws_url(self, path: str = '/') -> str:
        """Build WebSocket URL from target, port, and path"""
        target = None
        port = None
        
        if hasattr(self, 'target'):
            target = self._get_option_value(self.target)
        elif hasattr(self, 'rhost'):
            target = self._get_option_value(self.rhost)
        
        if hasattr(self, 'port'):
            port = self._get_option_value(self.port)
        elif hasattr(self, 'rport'):
            port = self._get_option_value(self.rport)
        
        if not target:
            raise ValueError("target not set. Please set target option (or rhost for compatibility).")
        if not port:
            raise ValueError("port not set. Please set port option (or rport for compatibility).")
        
        # Determine protocol based on ssl option or port
        if hasattr(self, 'ssl'):
            ssl_enabled = self._get_option_value(self.ssl)
            protocol = 'wss' if ssl_enabled else 'ws'
        else:
            # Fallback: determine protocol based on port
            protocol = 'wss' if int(port) == 443 else 'ws'
        
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
        
        return f"{protocol}://{target}:{port}{path}"
    
    def connect(self, path: str = '/', 
                headers: Optional[Dict[str, str]] = None,
                cookies: Optional[Dict[str, str]] = None,
                subprotocols: Optional[List[str]] = None) -> bool:
        """
        Connect to a WebSocket server.
        
        Args:
            path: WebSocket path (default: '/')
            headers: Dictionary of headers to send
            cookies: Dictionary of cookies (will be added to Cookie header)
            subprotocols: List of subprotocols to request
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        if not WEBSOCKET_AVAILABLE:
            self.logger.error("websocket-client library not available")
            return False
        
        try:
            ws_url = self._build_ws_url(path)
            
            # Build headers
            ws_headers = {}
            if headers:
                ws_headers.update(headers)
            
            # Add cookies to headers if provided
            if cookies:
                cookie_str = '; '.join([f"{k}={v}" for k, v in cookies.items()])
                if 'Cookie' in ws_headers:
                    ws_headers['Cookie'] = f"{ws_headers['Cookie']}; {cookie_str}"
                else:
                    ws_headers['Cookie'] = cookie_str
            
            # Convert headers dict to list format for websocket-client
            header_list = [f"{k}: {v}" for k, v in ws_headers.items()]
            
            # SSL options
            sslopt = {}
            verify_ssl = self._get_option_value(self.verify_ssl) if hasattr(self, 'verify_ssl') else False
            if self._build_ws_url(path).startswith('wss://') and not verify_ssl:
                import ssl
                sslopt = {"cert_reqs": ssl.CERT_NONE}
            
            # Get timeout
            timeout = self._get_option_value(self.timeout) if hasattr(self, 'timeout') else 10
            
            # Connect
            self.logger.debug(f"Connecting to WebSocket: {ws_url}")
            self.ws = websocket.create_connection(
                ws_url,
                header=header_list if header_list else None,
                subprotocols=subprotocols,
                sslopt=sslopt if sslopt else None,
                timeout=timeout
            )
            
            self.connected = True
            self.logger.info(f"Successfully connected to WebSocket: {ws_url}")
            return True
            
        except Exception as e:
            self.logger.error(f"WebSocket connection failed: {e}")
            self.connected = False
            return False
    
    def send(self, data: Union[str, bytes], opcode: int = None) -> bool:
        """
        Send data through the WebSocket connection.
        
        Args:
            data: Data to send (string or bytes)
            opcode: WebSocket opcode (default: TEXT for str, BINARY for bytes)
        
        Returns:
            bool: True if send successful, False otherwise
        """
        if not self.connected or not self.ws:
            self.logger.error("WebSocket not connected")
            return False
        
        try:
            if isinstance(data, str):
                self.ws.send(data, opcode=opcode or websocket.ABNF.OPCODE_TEXT)
            else:
                self.ws.send(data, opcode=opcode or websocket.ABNF.OPCODE_BINARY)
            return True
        except Exception as e:
            self.logger.error(f"WebSocket send failed: {e}")
            return False
    
    def recv(self, timeout: Optional[float] = None) -> Optional[Union[str, bytes]]:
        """
        Receive data from the WebSocket connection.
        
        Args:
            timeout: Optional timeout in seconds (overrides default timeout)
        
        Returns:
            str or bytes: Received data, or None on error/timeout
        """
        if not self.connected or not self.ws:
            self.logger.error("WebSocket not connected")
            return None
        
        try:
            if timeout:
                self.ws.settimeout(timeout)
            else:
                timeout_val = self._get_option_value(self.timeout) if hasattr(self, 'timeout') else 10
                self.ws.settimeout(timeout_val)
            
            data = self.ws.recv()
            return data
        except websocket.WebSocketTimeoutException:
            self.logger.debug("WebSocket receive timeout")
            return None
        except websocket.WebSocketConnectionClosedException:
            self.logger.warning("WebSocket connection closed")
            self.connected = False
            return None
        except Exception as e:
            self.logger.error(f"WebSocket receive failed: {e}")
            return None
    
    def recv_text(self, timeout: Optional[float] = None) -> Optional[str]:
        """
        Receive text data from the WebSocket connection.
        
        Args:
            timeout: Optional timeout in seconds
        
        Returns:
            str: Received text data, or None on error/timeout
        """
        data = self.recv(timeout)
        if data is None:
            return None
        
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8', errors='ignore')
            except:
                return None
        return str(data)
    
    def recv_binary(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        Receive binary data from the WebSocket connection.
        
        Args:
            timeout: Optional timeout in seconds
        
        Returns:
            bytes: Received binary data, or None on error/timeout
        """
        data = self.recv(timeout)
        if data is None:
            return None
        
        if isinstance(data, str):
            return data.encode('utf-8')
        return data
    
    def ping(self, payload: bytes = b'') -> bool:
        """Send a ping frame"""
        if not self.connected or not self.ws:
            return False
        try:
            self.ws.ping(payload)
            return True
        except:
            return False
    
    def pong(self, payload: bytes = b'') -> bool:
        """Send a pong frame"""
        if not self.connected or not self.ws:
            return False
        try:
            self.ws.pong(payload)
            return True
        except:
            return False
    
    def wait_for_prompt(self, prompt: str = ' # ', timeout: Optional[float] = None, 
                       max_wait: float = 30.0) -> bool:
        """
        Wait for a specific prompt string in received data.
        
        Args:
            prompt: Prompt string to wait for (default: ' # ')
            timeout: Timeout per receive operation
            max_wait: Maximum total time to wait
        
        Returns:
            bool: True if prompt found, False on timeout
        """
        start_time = time.time()
        buffer = ""
        
        while time.time() - start_time < max_wait:
            data = self.recv_text(timeout)
            if data:
                buffer += data
                if prompt in buffer:
                    return True
            time.sleep(0.1)
        
        return False
    
    def send_command(self, command: str, wait_prompt: bool = True, 
                    prompt: str = ' # ', timeout: Optional[float] = None) -> Optional[str]:
        """
        Send a command and optionally wait for prompt.
        
        Args:
            command: Command to send
            wait_prompt: Whether to wait for prompt after sending
            prompt: Prompt string to wait for
            timeout: Timeout for waiting
        
        Returns:
            str: Received response, or None on error
        """
        if not self.send_text(f"{command}\n"):
            return None
        
        if wait_prompt:
            if not self.wait_for_prompt(prompt, timeout):
                return None
        
        # Collect response
        response = ""
        start_time = time.time()
        while time.time() - start_time < (timeout or 5.0):
            data = self.recv_text(0.5)
            if data:
                response += data
                if prompt in response:
                    break
            else:
                break
        
        return response
    
    def run_commands(self, commands: List[str], 
                    prompt: str = ' # ',
                    command_timeout: Optional[float] = None,
                    max_iterations: int = 100) -> bool:
        """
        Run a list of commands sequentially, waiting for prompts.
        
        Args:
            commands: List of commands to execute
            prompt: Prompt string to wait for between commands
            command_timeout: Timeout per command
            max_iterations: Maximum number of iterations to prevent infinite loops
        
        Returns:
            bool: True if all commands executed successfully
        """
        if not self.connected:
            return False
        
        command_index = 0
        iteration = 0
        
        while command_index < len(commands) and iteration < max_iterations:
            iteration += 1
            
            # Wait for prompt
            if not self.wait_for_prompt(prompt, command_timeout):
                self.logger.warning(f"Timeout waiting for prompt before command {command_index + 1}")
            
            # Send command
            if command_index < len(commands):
                cmd = commands[command_index]
                self.logger.debug(f"Sending command {command_index + 1}/{len(commands)}: {cmd}")
                if not self.send_text(f"{cmd}\n"):
                    self.logger.error(f"Failed to send command: {cmd}")
                    return False
                command_index += 1
                
                # Small delay to allow command processing
                time.sleep(0.1)
        
        return command_index >= len(commands)
    
    def close(self):
        """Close the WebSocket connection"""
        if self.ws:
            try:
                self.ws.close()
            except:
                pass
            self.ws = None
        self.connected = False
    
    def is_connected(self) -> bool:
        """Check if WebSocket is connected"""
        return self.connected and self.ws is not None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

