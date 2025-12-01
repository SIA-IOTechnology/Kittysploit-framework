#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import socket
import shlex
from threading import Thread, Lock
from time import sleep

class ListenPlugin(Plugin):
    """Netcat-like listener plugin for accepting TCP connections"""

    __info__ = {
        "name": "listen",
        "description": "Netcat-like listener for accepting TCP connections",
        "version": "1.0.0",
        "author": "KittySploit Team",
        "dependencies": []
    }

    def __init__(self, framework=None):
        super().__init__(framework)
        self.lock = Lock()
        self.s = None
        self.conn = None
        self.stop_threads = False
        self.port = 6000
        self.stop_loop = True
        self.recv_thread = None
        self.listen_thread = None

    def initialize(self):
        """Initialize the socket and bind to the specified port"""
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.s.bind(("0.0.0.0", self.port))
            print_success(f"Listening on 0.0.0.0:{self.port}")
            print_info("Type 'exit' to close connection")
            print_info("Waiting for client...")
            return True
        except OSError as e:
            if e.errno == 98 or e.errno == 10048:  # Address already in use
                print_error(f"Port {self.port} is already in use")
            elif e.errno == 13:  # Permission denied
                print_error(f"Permission denied: You may need root privileges to bind port {self.port}")
            else:
                print_error(f"Failed to bind port {self.port}: {e}")
            return False
        except Exception as e:
            print_error(f"Error initializing listener: {e}")
            return False

    def listen(self):
        """Listen for incoming connections"""
        if not self.s:
            return
        
        self.s.listen(1)
        
        # Keep accepting connections until stopped
        while not self.stop_threads:
            try:
                # Wait for a new connection
                if self.conn is None:
                    self.conn, addr = self.s.accept()
                    self.conn.settimeout(3)
                    print_success(f"Connection established from {addr[0]}:{addr[1]}")
                    
                    # Start receive thread if not already running
                    if not self.recv_thread or not self.recv_thread.is_alive():
                        self.recv_thread = Thread(target=self.recv, daemon=True)
                        self.recv_thread.start()
                else:
                    # Wait a bit before checking again
                    sleep(0.5)
                    
            except OSError as e:
                if not self.stop_threads:
                    # If socket was closed, break the loop
                    if e.errno == 9:  # Bad file descriptor
                        break
                    print_error(f"Error accepting connection: {e}")
                    sleep(1)
            except Exception as e:
                if not self.stop_threads:
                    print_error(f"Unexpected error in listen: {e}")
                    sleep(1)

    def recv(self):
        """Receive data from the connected client"""
        while not self.stop_threads:
            if not self.conn:
                sleep(0.1)
                continue
            
            try:
                data = self.conn.recv(4096)
                if not data:
                    # Connection closed by client
                    print_warning("Connection closed by client")
                    self._close_connection()
                    break
                else:
                    # Decode and print received data
                    decoded = data.decode(errors="ignore")
                    print_info(decoded.rstrip())
            except socket.timeout:
                # Timeout is normal, continue listening
                continue
            except OSError as e:
                if not self.stop_threads:
                    print_warning(f"Connection error: {e}")
                self._close_connection()
                break
            except Exception as e:
                if not self.stop_threads:
                    print_error(f"Error receiving data: {e}")
                self._close_connection()
                break

    def run(self, *args, **kwargs):
        """Main execution method for the plugin"""
        parser = ModuleArgumentParser(description="Netcat-like listener for accepting TCP connections", prog="listen")
        parser.add_argument("-p", "--port", dest="port", help="Port to listen on", type=int, default=6000)
        
        if not args or not args[0]:
            parser.print_help()
            return True
        
        try:
            pargs = parser.parse_args(shlex.split(args[0]))
            
            if hasattr(pargs, 'help') and pargs.help:
                parser.print_help()
                return True
            
            if isinstance(pargs.port, int):
                if pargs.port < 1 or pargs.port > 65535:
                    print_error("Port must be between 1 and 65535")
                    return False
                self.port = pargs.port
            
            # Initialize and start listening
            if not self.initialize():
                return False
            
            # Start listening thread
            self.stop_loop = True
            self.stop_threads = False
            self.listen_thread = Thread(target=self.listen, daemon=True)
            self.listen_thread.start()
            
            # Main input loop
            try:
                while self.stop_loop:
                    try:
                        data = input()
                        
                        if not self.conn:
                            if data.lower() == "exit":
                                print_info("Stopping listener...")
                                self.stop()
                                break
                            print_status("Waiting for client connection...")
                            continue
                        
                        # Handle exit command
                        if data.lower() == "exit":
                            print_success("Closing connection and stopping listener...")
                            self.stop()
                            break
                        
                        # Send data to connected client
                        try:
                            data_to_send = data + "\n"
                            self.conn.send(data_to_send.encode())
                        except OSError as e:
                            print_error(f"Failed to send data: {e}")
                            self._close_connection()
                            print_status("Waiting for new client connection...")
                            
                    except KeyboardInterrupt:
                        print_info("\nInterrupted by user")
                        self.stop()
                        break
                    except EOFError:
                        print_info("\nStopping listener...")
                        self.stop()
                        break
                        
            except Exception as e:
                print_error(f"Error in main loop: {e}")
                self.stop()
                return False
            
            return True
            
        except Exception as e:
            print_error(f"Error parsing arguments: {e}")
            parser.print_help()
            return False

    def _close_connection(self):
        """Close the current connection"""
        try:
            if self.conn:
                self.conn.close()
                self.conn = None
                print_info("Connection closed. Waiting for new connection...")
        except Exception:
            pass
    
    def stop(self):
        """Stop the listener and close all connections"""
        self.stop_threads = True
        self.stop_loop = False
        
        # Close connection first
        self._close_connection()
        
        # Close socket (this will cause accept() to raise an exception)
        try:
            if self.s:
                self.s.close()
                self.s = None
        except Exception:
            pass
        
        print_success("Listener stopped")
