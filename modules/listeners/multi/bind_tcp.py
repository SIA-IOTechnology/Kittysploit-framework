#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import socket

class Module(Listener):
    
    __info__ = {
        'name': 'Generic Bind TCP Listener',
        'description': 'Ultra-simple bind TCP listener - framework handles session management',
        'author': 'KittySploit Team',
        'handler': Handler.BIND,
        'session_type': SessionType.SHELL,
        'references': []
    }
    
    rhost = OptString("127.0.0.1", "Target IPv4 or IPv6 address", True)
    rport = OptPort(4444, "Target port", True)
    
    def run(self):
        """Run the bind TCP listener - ultra-simple implementation"""
        try:
            print_status(f"Trying connect to {self.rhost}:{self.rport}")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                self.sock.connect((self.rhost, self.rport))
                print_success(f"Connected to {self.rhost}:{self.rport}")
                
                return (self.sock, self.rhost, self.rport)
                
            except ConnectionRefusedError:
                print_error("Connection refused")
                return False
        
        except KeyboardInterrupt:
            return False
        except OSError as e:
            print_error(f"Connection error: {e}")
            return False
    
    def shutdown(self):
        """Clean up connection"""
        try:
            if hasattr(self, 'sock') and self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
        except OSError as e:
            pass
