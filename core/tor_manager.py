#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tor Network Manager
Manages Tor network connectivity for the framework
"""

import socket
import requests
from typing import Optional, Dict, Any
from core.output_handler import print_info, print_success, print_error, print_warning


class TorManager:
    """Manages Tor network connectivity"""
    
    # Default Tor SOCKS proxy ports
    DEFAULT_SOCKS_PORT = 9050  # Standard Tor daemon
    DEFAULT_SOCKS_PORT_TOR_BROWSER = 9150  # Tor Browser
    
    # Default Tor Control ports
    DEFAULT_CONTROL_PORT = 9051  # Standard Tor daemon
    DEFAULT_CONTROL_PORT_TOR_BROWSER = 9151  # Tor Browser
    
    def __init__(self, framework=None):
        """Initialize Tor Manager"""
        self.framework = framework
        self.enabled = False
        self.socks_host = '127.0.0.1'
        self.socks_port = self.DEFAULT_SOCKS_PORT
        self.control_host = '127.0.0.1'
        self.control_port = self.DEFAULT_CONTROL_PORT
        self._last_check_result = None
    
    def check_tor_available(self, host: str = None, port: int = None) -> bool:
        """
        Check if Tor SOCKS proxy is available
        
        Args:
            host: Tor SOCKS proxy host (default: 127.0.0.1)
            port: Tor SOCKS proxy port (default: 9050, fallback: 9150)
            
        Returns:
            True if Tor is available, False otherwise
        """
        check_host = host or self.socks_host
        check_port = port or self.socks_port
        
        # Try default port first, then Tor Browser port
        ports_to_try = [check_port]
        if check_port == self.DEFAULT_SOCKS_PORT:
            ports_to_try.append(self.DEFAULT_SOCKS_PORT_TOR_BROWSER)
        
        for test_port in ports_to_try:
            try:
                # Try to connect to SOCKS proxy
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((check_host, test_port))
                sock.close()
                
                if result == 0:
                    # Connection successful, update port if we used fallback
                    if test_port != check_port:
                        self.socks_port = test_port
                        if self.framework:
                            print_info(f"Tor detected on port {test_port} (Tor Browser port)")
                    self._last_check_result = True
                    return True
            except Exception:
                continue
        
        self._last_check_result = False
        return False
    
    def test_tor_connection(self, test_url: str = "https://check.torproject.org/api/ip") -> bool:
        """
        Test Tor connection by making a request through Tor
        
        Args:
            test_url: URL to test (default: Tor Project check service)
            
        Returns:
            True if request goes through Tor, False otherwise
        """
        if not self.enabled:
            return False
        
        try:
            # Configure requests to use Tor SOCKS proxy
            proxies = {
                'http': f'socks5h://{self.socks_host}:{self.socks_port}',
                'https': f'socks5h://{self.socks_host}:{self.socks_port}'
            }
            
            response = requests.get(test_url, proxies=proxies, timeout=10)
            
            # Check if response indicates Tor usage
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Tor Project API returns "IsTor": true if using Tor
                    if data.get('IsTor', False):
                        return True
                except:
                    # If not JSON, just check if request succeeded
                    return True
            
            return False
        except Exception as e:
            if self.framework and hasattr(self.framework, 'output_handler'):
                self.framework.output_handler.print_warning(f"Tor connection test failed: {e}")
            return False
    
    def get_tor_proxy_url(self) -> Optional[str]:
        """
        Get Tor SOCKS proxy URL
        
        Returns:
            SOCKS5 proxy URL if Tor is enabled, None otherwise
        """
        if self.enabled:
            return f"socks5://{self.socks_host}:{self.socks_port}"
        return None
    
    def get_tor_proxy_dict(self) -> Dict[str, str]:
        """
        Get Tor proxy dictionary for requests library
        
        Returns:
            Dictionary with 'http' and 'https' proxy URLs
        """
        if not self.enabled:
            return {}
        
        proxy_url = f"socks5h://{self.socks_host}:{self.socks_port}"
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    
    def enable(self, host: str = '127.0.0.1', socks_port: int = None, 
               control_port: int = None, check_availability: bool = True) -> bool:
        """
        Enable Tor network
        
        Args:
            host: Tor SOCKS proxy host (default: 127.0.0.1)
            socks_port: Tor SOCKS proxy port (default: 9050, auto-detect if None)
            control_port: Tor Control port (default: 9051)
            check_availability: Whether to check if Tor is available before enabling
            
        Returns:
            True if Tor was enabled successfully, False otherwise
        """
        self.socks_host = host
        self.control_host = host
        
        # Auto-detect port if not specified
        if socks_port is None:
            # Try default port first
            if self.check_tor_available(host, self.DEFAULT_SOCKS_PORT):
                self.socks_port = self.DEFAULT_SOCKS_PORT
            elif self.check_tor_available(host, self.DEFAULT_SOCKS_PORT_TOR_BROWSER):
                self.socks_port = self.DEFAULT_SOCKS_PORT_TOR_BROWSER
            else:
                if check_availability:
                    print_error("Tor SOCKS proxy not available on ports 9050 or 9150")
                    print_info("Make sure Tor is running or specify a custom port")
                    return False
                # Use default port anyway if check is disabled
                self.socks_port = self.DEFAULT_SOCKS_PORT
        else:
            self.socks_port = socks_port
            if check_availability and not self.check_tor_available(host, socks_port):
                print_warning(f"Tor SOCKS proxy may not be available on {host}:{socks_port}")
        
        self.control_port = control_port or self.DEFAULT_CONTROL_PORT
        
        # Configure framework proxy to use Tor
        if self.framework:
            self.framework.configure_proxy(
                enabled=True,
                host=self.socks_host,
                port=self.socks_port,
                scheme='socks5'
            )
            
            # Install socket wrapper for universal Tor support
            try:
                from lib.pivot.socket_wrapper import install_socket_wrapper
                install_socket_wrapper(self.framework)
            except Exception as e:
                print_warning(f"Could not install socket wrapper: {e}")
                print_info("HTTP/HTTPS will work through Tor, but raw TCP may not")
            
            # Install requests wrapper to intercept all requests library calls
            try:
                from core.tor_requests_wrapper import install_tor_requests_wrapper
                install_tor_requests_wrapper(self)
            except Exception as e:
                print_warning(f"Could not install requests wrapper: {e}")
                print_info("Direct requests.get/post calls may not use Tor")
        
        self.enabled = True
        
        if self.framework and hasattr(self.framework, 'output_handler'):
            print_success(f"Tor network enabled: socks5://{self.socks_host}:{self.socks_port}")
        
        return True
    
    def disable(self):
        """Disable Tor network"""
        if not self.enabled:
            return
        
        # Uninstall requests wrapper
        try:
            from core.tor_requests_wrapper import uninstall_tor_requests_wrapper
            uninstall_tor_requests_wrapper()
        except Exception:
            pass
        
        # Disable framework proxy
        if self.framework:
            self.framework.configure_proxy(enabled=False)
        
        self.enabled = False
        
        if self.framework and hasattr(self.framework, 'output_handler'):
            print_info("Tor network disabled")
    
    def is_enabled(self) -> bool:
        """Check if Tor is enabled"""
        return self.enabled
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get Tor status information
        
        Returns:
            Dictionary with Tor status information
        """
        status = {
            'enabled': self.enabled,
            'socks_host': self.socks_host,
            'socks_port': self.socks_port,
            'control_host': self.control_host,
            'control_port': self.control_port,
            'proxy_url': self.get_tor_proxy_url()
        }
        
        if self.enabled:
            # Test connection if enabled
            status['connection_test'] = self.test_tor_connection()
            status['available'] = self.check_tor_available()
        else:
            status['connection_test'] = False
            status['available'] = self.check_tor_available()
        
        return status
