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
        """Run the SSH client listener - ultra-simple implementation"""
        try:
            print_status(f"Connecting to SSH server {self.rhost}:{self.rport} as {self.username}")
            
            ssh_channel = paramiko.SSHClient()
            ssh_channel.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_channel.connect(self.rhost, self.rport, self.username, self.password)
            
            print_success(f"Connected to SSH server {self.rhost}:{self.rport}")
            
            # Return connection data - framework extracts info from __info__
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
