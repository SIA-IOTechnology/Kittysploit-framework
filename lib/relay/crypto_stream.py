#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""E2E encryption + keepalive for relay-bridged TCP streams."""

from __future__ import annotations

import socket
import struct
import threading
import time
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

FRAME_MAGIC = b"KSF1"
TYPE_DATA = 0x01
TYPE_KEEPALIVE = 0x02
TYPE_KEEPALIVE_ACK = 0x03
MAX_FRAME_PAYLOAD = 60000


def derive_relay_key(token: str, psk: str = "") -> bytes:
    """Derive a 32-byte ChaCha20 key from room token + optional pre-shared secret."""
    material = f"{token}\0{psk}".encode("utf-8", errors="replace")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"kittyrelay-v2-e2e",
        info=b"ksrl-chacha20",
    ).derive(material)


def _nonce(seq: int) -> bytes:
    return b"\x00\x00\x00\x00" + struct.pack(">Q", seq & 0xFFFFFFFFFFFFFFFF)


class SecureRelayStream:
    """
    Socket-like E2E encrypted stream over a relay-bridged TCP connection.

    Compatible with ClassicShell / PTY relay (sendall, recv, settimeout, close).
    """

    def __init__(
        self,
        sock: socket.socket,
        key: bytes,
        *,
        keepalive_interval: float = 30.0,
        keepalive_timeout: float = 90.0,
        on_disconnect: Optional[Callable[[], None]] = None,
    ):
        self._sock = sock
        self._cipher = ChaCha20Poly1305(key)
        self._send_seq = 0
        self._recv_seq = 0
        self._recv_buf = bytearray()
        self._read_buf = bytearray()
        self._io_lock = threading.Lock()
        self._last_recv = time.monotonic()
        self._keepalive_interval = max(0.0, float(keepalive_interval))
        self._keepalive_timeout = max(5.0, float(keepalive_timeout))
        self._on_disconnect = on_disconnect
        self._stop = threading.Event()
        self._closed = False
        self._timeout: Optional[float] = None
        self._keepalive_thread: Optional[threading.Thread] = None
        if self._keepalive_interval > 0:
            self._keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
            self._keepalive_thread.start()

    def set_disconnect_callback(self, callback: Optional[Callable[[], None]]) -> None:
        self._on_disconnect = callback

    def settimeout(self, timeout: Optional[float]) -> None:
        self._timeout = None if timeout is None else float(timeout)

    def getpeername(self):
        return self._sock.getpeername()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        try:
            self._send_frame(TYPE_KEEPALIVE, b"bye")
        except Exception:
            pass
        try:
            self._sock.close()
        except OSError:
            pass

    def shutdown(self, how=socket.SHUT_RDWR) -> None:
        try:
            self._sock.shutdown(how)
        except OSError:
            pass

    def sendall(self, data) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        if self._closed:
            raise BrokenPipeError("secure relay stream closed")
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + MAX_FRAME_PAYLOAD]
            self._send_frame(TYPE_DATA, chunk)
            offset += len(chunk)

    def recv(self, bufsize: int) -> bytes:
        if self._closed:
            return b""
        deadline = None if self._timeout is None else time.monotonic() + self._timeout

        while not self._recv_buf:
            if self._closed:
                return b""
            try:
                self._read_one_frame(deadline)
            except TimeoutError:
                return b""

        out = bytes(self._recv_buf[:bufsize])
        del self._recv_buf[:bufsize]
        return out

    def _send_frame(self, ftype: int, payload: bytes = b"") -> None:
        with self._io_lock:
            nonce = _nonce(self._send_seq)
            self._send_seq += 1
            plain = bytes([ftype]) + payload
            ct = self._cipher.encrypt(nonce, plain, FRAME_MAGIC)
            frame = FRAME_MAGIC + struct.pack(">I", len(ct)) + ct
            self._sock.sendall(frame)

    def _read_exact(self, n: int, deadline: Optional[float]) -> bytes:
        while len(self._read_buf) < n:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("frame read timeout")
            try:
                if self._timeout is not None:
                    self._sock.settimeout(
                        max(0.05, deadline - time.monotonic()) if deadline else self._timeout
                    )
                chunk = self._sock.recv(max(4096, n - len(self._read_buf)))
            except socket.timeout:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError("frame read timeout")
                continue
            if not chunk:
                self._mark_disconnect()
                raise ConnectionResetError("relay peer disconnected")
            self._read_buf.extend(chunk)
        out = bytes(self._read_buf[:n])
        del self._read_buf[:n]
        return out

    def _read_one_frame(self, deadline: Optional[float]) -> None:
        header = self._read_exact(8, deadline)
        if header[:4] != FRAME_MAGIC:
            raise ValueError("invalid relay frame magic")
        (clen,) = struct.unpack(">I", header[4:8])
        if clen <= 0 or clen > 65536:
            raise ValueError("invalid relay frame length")
        ct = self._read_exact(clen, deadline)
        nonce = _nonce(self._recv_seq)
        self._recv_seq += 1
        plain = self._cipher.decrypt(nonce, ct, FRAME_MAGIC)
        ftype = plain[0]
        payload = plain[1:]
        self._last_recv = time.monotonic()
        if ftype == TYPE_DATA:
            self._recv_buf.extend(payload)
        elif ftype == TYPE_KEEPALIVE:
            try:
                self._send_frame(TYPE_KEEPALIVE_ACK, b"")
            except OSError:
                self._mark_disconnect()
        elif ftype == TYPE_KEEPALIVE_ACK:
            pass
        else:
            raise ValueError(f"unknown relay frame type: {ftype}")

    def _keepalive_loop(self) -> None:
        while not self._stop.wait(self._keepalive_interval):
            if self._closed:
                break
            if time.monotonic() - self._last_recv > self._keepalive_timeout:
                self._mark_disconnect()
                break
            try:
                self._send_frame(TYPE_KEEPALIVE, b"")
            except OSError:
                self._mark_disconnect()
                break

    def _mark_disconnect(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        cb = self._on_disconnect
        if cb:
            try:
                cb()
            except Exception:
                pass
        try:
            self._sock.close()
        except OSError:
            pass


def wrap_secure_stream(
    sock: socket.socket,
    token: str,
    *,
    psk: str = "",
    keepalive_interval: float = 30.0,
    keepalive_timeout: float = 90.0,
    on_disconnect: Optional[Callable[[], None]] = None,
) -> SecureRelayStream:
    key = derive_relay_key(token, psk)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    return SecureRelayStream(
        sock,
        key,
        keepalive_interval=keepalive_interval,
        keepalive_timeout=keepalive_timeout,
        on_disconnect=on_disconnect,
    )
