#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import paramiko

class Module(Listener):
    
    __info__ = {
        'name': 'Generic SSH Client Listener',
        'description': 'Ultra-simple SSH client listener - framework handles session management',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.SSH,
        'dependencies': ['paramiko'],
    }
    
    rhost = OptString("127.0.0.1", "Target IPv4 or IPv6 address", True)
    rport = OptPort(22, "Target SSH port", True)
    username = OptString("root", "SSH username", True)
    password = OptString("", "SSH password", True)
    
    def run(self):
        """Connect once to the SSH server."""
        if getattr(self, '_connect_done', False):
            return None
        self._connect_done = True
        try:
            print_status(f"Trying connect to {self.rhost}:{self.rport}")
            
            ssh_channel = paramiko.SSHClient()
            ssh_channel.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_channel.connect(self.rhost, self.rport, self.username, self.password)
            self.ssh_channel = ssh_channel
            
            print_success(f"Connected to SSH server {self.rhost}:{self.rport}")
            
            return (ssh_channel, self.rhost, self.rport)
            
        except KeyboardInterrupt:
            return False
        except paramiko.AuthenticationException:
            print_error(f"SSH authentication failed for {self.username}@{self.rhost}:{self.rport}")
            return False
        except paramiko.SSHException as e:
            print_error(f"SSH connection error: {e}")
            return False
        except OSError as e:
            print_error(f"Connection error: {e}")
            return False
    
    def shutdown(self):
        """Clean up connection"""
        try:
            if hasattr(self, 'ssh_channel') and self.ssh_channel:
                self.ssh_channel.close()
        except Exception as e:
            pass
