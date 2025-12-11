#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import urllib3
from typing import Dict, List, Any, Optional, Union
from urllib.parse import urljoin, urlparse
import logging
import time

from core.framework.option import OptString, OptPort, OptBool
from core.framework.base_module import BaseModule

logger = logging.getLogger(__name__)

class Http_client(BaseModule):
    """Advanced HTTP client with security testing capabilities"""
    
    target = OptString("", "Target URL, IP or hostname", True)
    port = OptPort(443, "Target port", True)
    path = OptString("/", "Target path", True)  
    ssl = OptBool(True, "SSL enabled: true/false", True, advanced=True)
    user_agent = OptString("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "User agent", True, advanced=True)
    follow_redirects = OptBool(True, "Follow redirects: true/false", True, advanced=True)
    timeout = OptPort(10, "Request timeout in seconds", True, advanced=True)
    verify_ssl = OptBool(False, "Verify SSL certificates: true/false", False, advanced=True)
    proxy = OptString("", "Proxy URL (e.g., 'http://127.0.0.1:8080')", False, advanced=True)
    
    def __init__(self, framework=None):
        """
        Initialize HTTP client using options from the module.
        Options are defined as class attributes and can be set via set_option().
        """
        super().__init__(framework)
        self.session = requests.Session()
        self.logger = logger  # Initialize logger
        # Initialize session configuration (will be updated in _configure_session)
        self._configure_session()
    
    def _configure_session(self):
        """Configure the HTTP session using current option values"""
        # Get option values (handle both OptString/OptPort/OptBool and direct values)
        def get_option_value(option):
            if hasattr(option, 'value'):
                return option.value
            elif hasattr(option, '__get__'):
                # It's a descriptor, try to get the value
                try:
                    return option.__get__(self, type(self))
                except:
                    return option
            return option
        
        # Get values from options
        user_agent = get_option_value(self.user_agent) if hasattr(self, 'user_agent') else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        proxy = get_option_value(self.proxy) if hasattr(self, 'proxy') else ""
        verify_ssl = get_option_value(self.verify_ssl) if hasattr(self, 'verify_ssl') else False
        follow_redirects = get_option_value(self.follow_redirects) if hasattr(self, 'follow_redirects') else True
        
        # Convert verify_ssl to boolean if it's a string
        if isinstance(verify_ssl, str):
            verify_ssl = verify_ssl.lower() in ('true', 'yes', 'y', '1')
        elif not isinstance(verify_ssl, bool):
            verify_ssl = bool(verify_ssl)
        
        # Configure session headers
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Set proxy if provided, otherwise check framework proxy config
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        else:
            # Check if framework has proxy configured
            if self.framework and hasattr(self.framework, 'is_proxy_enabled'):
                if self.framework.is_proxy_enabled():
                    proxy_url = self.framework.get_proxy_url()
                    if proxy_url:
                        self.session.proxies = {
                            'http': proxy_url,
                            'https': proxy_url,
                            'all': proxy_url
                        }
                    else:
                        self.session.proxies = {}
                else:
                    self.session.proxies = {}
            else:
                self.session.proxies = {}
        
        # Disable SSL warnings if verify_ssl is False
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Configure redirects
        self.session.max_redirects = 10 if follow_redirects else 0
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """Perform GET request"""
        return self._request('GET', url, **kwargs)
    
    def post(self, url: str, data: Optional[Union[Dict, str]] = None, **kwargs) -> requests.Response:
        """Perform POST request"""
        return self._request('POST', url, data=data, **kwargs)
    
    def put(self, url: str, data: Optional[Union[Dict, str]] = None, **kwargs) -> requests.Response:
        """Perform PUT request"""
        return self._request('PUT', url, data=data, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        """Perform DELETE request"""
        return self._request('DELETE', url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """Perform HEAD request"""
        return self._request('HEAD', url, **kwargs)
    
    def options(self, url: str, **kwargs) -> requests.Response:
        """Perform OPTIONS request"""
        return self._request('OPTIONS', url, **kwargs)
    
    def http_request(self, method: str = 'GET', path: str = '/', 
                     cookies: Optional[Dict[str, str]] = None,
                     headers: Optional[Dict[str, str]] = None,
                     data: Optional[Union[Dict, str]] = None,
                     session: bool = False,
                     **kwargs) -> Union[requests.Response, Any]:
        """
        Make an HTTP request using target and port from the module options.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path (default: '/')
            cookies: Dictionary of cookies to send
            headers: Dictionary of headers to send
            data: Data to send (for POST, PUT, etc.)
            session: If True, return a response object with a 'session' attribute
            **kwargs: Additional arguments passed to requests
        
        Returns:
            requests.Response: If session=False
            Response-like object with 'session' attribute: If session=True
        """
        # Helper to get option value
        def get_option_value(option):
            if hasattr(option, 'value'):
                return option.value
            elif hasattr(option, '__get__'):
                try:
                    return option.__get__(self, type(self))
                except:
                    return option
            return option
        
        # Get target and port from options (fallback to rhost/rport for compatibility)
        target = None
        port = None
        
        if hasattr(self, 'target'):
            target = get_option_value(self.target)
        elif hasattr(self, 'rhost'):
            target = get_option_value(self.rhost)
        
        if hasattr(self, 'port'):
            port = get_option_value(self.port)
        elif hasattr(self, 'rport'):
            port = get_option_value(self.rport)
        
        if not target:
            raise ValueError("target not set. Please set target option (or rhost for compatibility).")
        if not port:
            raise ValueError("port not set. Please set port option (or rport for compatibility).")
        
        # Determine protocol based on ssl option or port
        if hasattr(self, 'ssl'):
            ssl_enabled = get_option_value(self.ssl)
            protocol = 'https' if ssl_enabled else 'http'
        else:
            # Fallback: determine protocol based on port
            # Port 443 typically uses HTTPS
            protocol = 'https' if int(port) == 443 else 'http'
        
        # Auto-enable SSL for port 443 if not explicitly set
        if protocol == 'https' and hasattr(self, 'ssl'):
            ssl_enabled = get_option_value(self.ssl)
            if not ssl_enabled and int(port) == 443:
                # Auto-enable SSL for port 443
                if hasattr(self.ssl, 'value'):
                    self.ssl.value = True
                # Also ensure verify_ssl is False for self-signed certificates
                if hasattr(self, 'verify_ssl') and hasattr(self.verify_ssl, 'value'):
                    if self.verify_ssl.value is True:
                        # Only disable if it was explicitly set to True, otherwise keep False
                        pass
                    else:
                        self.verify_ssl.value = False
        
        url = f"{protocol}://{target}:{port}{path}"
        
        # Prepare request parameters
        request_kwargs = kwargs.copy()
        
        # Add cookies if provided
        if cookies:
            request_kwargs['cookies'] = cookies
        
        # Add headers if provided
        if headers:
            request_kwargs['headers'] = headers
        
        # Add data if provided
        if data:
            request_kwargs['data'] = data
        
        # Make the request
        response = self._request(method, url, **request_kwargs)
        
        # If session=True, wrap the response to include the session
        if session:
            # Create a wrapper object that has both response attributes and session
            class ResponseWithSession:
                def __init__(self, response_obj, session_obj):
                    # Copy all response attributes
                    for attr in dir(response_obj):
                        if not attr.startswith('_'):
                            try:
                                setattr(self, attr, getattr(response_obj, attr))
                            except:
                                pass
                    # Add session attribute
                    self.session = session_obj
            
            return ResponseWithSession(response, self.session)
        
        return response
    
    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Internal request method"""
        try:
            # Reconfigure session in case options changed
            self._configure_session()
            
            # Merge headers
            headers = kwargs.pop('headers', {})
            if headers:
                self.session.headers.update(headers)
            
            # Get timeout and verify_ssl from options
            def get_option_value(option):
                if hasattr(option, 'value'):
                    return option.value
                elif hasattr(option, '__get__'):
                    try:
                        return option.__get__(self, type(self))
                    except:
                        return option
                return option
            
            timeout = get_option_value(self.timeout) if hasattr(self, 'timeout') else 30
            verify_ssl = get_option_value(self.verify_ssl) if hasattr(self, 'verify_ssl') else False
            
            # Convert verify_ssl to boolean if it's a string
            if isinstance(verify_ssl, str):
                verify_ssl = verify_ssl.lower() in ('true', 'yes', 'y', '1')
            elif not isinstance(verify_ssl, bool):
                verify_ssl = bool(verify_ssl)
            
            # Set timeout and verify
            kwargs.setdefault('timeout', timeout)
            # Always use verify_ssl option value (defaults to False for self-signed certificates)
            kwargs['verify'] = verify_ssl
            
            # Debug logging (only if logger is configured for debug)
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"Request: {method} {url}")
                if 'cookies' in kwargs:
                    self.logger.debug(f"Cookies: {kwargs['cookies']}")
                self.logger.debug(f"Headers: {dict(self.session.headers)}")
                        
            response = self.session.request(method, url, **kwargs)
            
            # Log response status if not 200
            if response.status_code != 200:
                self.logger.warning(f"HTTP {method} {url} returned status {response.status_code}")
                        
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {method} {url} - {e}")
            raise
    
    def set_header(self, name: str, value: str):
        """Set a custom header"""
        self.session.headers[name] = value
    
    def remove_header(self, name: str):
        """Remove a header"""
        if name in self.session.headers:
            del self.session.headers[name]
    
    def set_cookie(self, name: str, value: str, domain: Optional[str] = None):
        """Set a cookie"""
        self.session.cookies.set(name, value, domain=domain)
    
    def get_cookies(self) -> Dict[str, str]:
        """Get all cookies"""
        return dict(self.session.cookies)
    
    def clear_cookies(self):
        """Clear all cookies"""
        self.session.cookies.clear()
    
    def set_auth(self, username: str, password: str):
        """Set basic authentication"""
        self.session.auth = (username, password)
    
    def set_bearer_token(self, token: str):
        """Set bearer token authentication"""
        self.session.headers['Authorization'] = f'Bearer {token}'
    
    
    def close(self):
        """Close the session"""
        self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
