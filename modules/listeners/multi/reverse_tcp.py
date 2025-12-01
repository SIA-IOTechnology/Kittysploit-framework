#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import socket

class Module(Listener):
    
    __info__ = {
        'name': 'Generic Reverse TCP Listener',
        'description': 'Ultra-simple reverse TCP listener - framework handles session management',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.REVERSE,
        'session_type': SessionType.SHELL,
    }
    
    lhost = OptString("127.0.0.1", "Local IPv4 or IPv6 address", True)
    lport = OptPort(4444, "Local port", True)
    
    def run(self):
        """Run the reverse TCP listener - ultra-simple implementation"""
        try:

            print_status(f"Starting server on {self.lhost}:{self.lport}")
            print_status("Waiting connection...")
            print_status("Press Ctrl+C to stop the listener")
            
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.settimeout(1.0)  # Set timeout for non-blocking behavior
            self.sock.bind((self.lhost, int(self.lport)))
            self.sock.listen(5)
            
            print_success(f"Listening on {self.lhost}:{self.lport}")
            
            while not self.stop_flag.is_set():
                try:
                    # Accept connection
                    client_socket, address = self.sock.accept()
                    print_success(f"Connection received from {address[0]}:{address[1]}")
                    
                    # Return connection data - framework extracts info from __info__
                    return (client_socket, address[0], address[1], additional_data={'connection_type': 'reverse', 'protocol': 'tcp'})
                    
                except socket.timeout:
                    # Timeout occurred, continue listening
                    continue
                except KeyboardInterrupt:
                    print_info("Interrupted by user")
                    break
                except Exception as e:
                    if not self.stop_flag.is_set():
                        print_error(f"Error accepting connection: {e}")
                    break
            
            return False
                
        except KeyboardInterrupt:
            print_info("Interrupted by user")
            return False
        except OSError as e:
            print_error(f"Listener error: {e}")
            return False
    
    def shutdown(self):
        """Clean up connection"""
        try:
            if hasattr(self, 'sock') and self.sock:
                self.sock.close()
        except OSError as e:
            pass
