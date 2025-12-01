#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generic HTTP Client Listener - Ultra-simple implementation following generic pattern
Author: KittySploit Team
Version: 1.0.0
"""

from kittysploit import *
import requests

class Module(Listener):
    """Ultra-simple HTTP client listener - just returns connection, framework handles the rest"""
    
    __info__ = {
        'name': 'Generic HTTP Client Listener',
        'description': 'Ultra-simple HTTP client listener - framework handles session management',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.HTTP,
        'protocol': 'http',
        'references': []
    }
    
    rhost = OptString("httpbin.org", "Target HTTP server", True)
    rport = OptPort(80, "Target HTTP port", True)
    path = OptString("/", "HTTP path", True)
    
    def run(self):
        """Run the HTTP client listener - ultra-simple implementation"""
        try:
            print_status(f"Connecting to HTTP server {self.rhost}:{self.rport}")
            
            # Create HTTP session
            http_session = requests.Session()
            http_session.headers.update({
                'User-Agent': 'KittySploit-Framework/1.0',
                'Accept': 'application/json'
            })
            
            # Test connection
            url = f"http://{self.rhost}:{self.rport}{self.path}"
            response = http_session.get(url, timeout=10)
            
            if response.status_code == 200:
                print_success(f"Connected to HTTP server {self.rhost}:{self.rport}")
                
                # Return connection data - framework extracts info from __info__
                return (http_session, self.rhost, self.rport)
            else:
                print_error(f"HTTP connection failed: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print_error(f"HTTP connection error: {e}")
            return False
        except Exception as e:
            print_error(f"Connection error: {e}")
            return False
    
    def shutdown(self):
        """Clean up connection"""
        try:
            if hasattr(self, 'http_session') and self.http_session:
                self.http_session.close()
        except Exception as e:
            pass
