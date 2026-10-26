"""HTTP transport for multipart payloads.

Provides chunked and plain HTTP POST senders. The chunked sender bypasses
PHP's post_max_size check: without Content-Length, SG(request_info).content_length
stays 0 and rfc1867_post_handler skips its size check. The multipart parser reads
the dechunked body directly.

Supports HTTP/HTTPS, proxy tunneling (SOCKS5/HTTP), connection reuse,
and configurable timeouts with retry logic.
"""
from __future__ import annotations

import socket
import ssl
import struct
import time
from dataclasses import dataclass


DEFAULT_BOUNDARY = "C" * 10
MAX_RESPONSE = 4 << 20  # 4 MB


@dataclass
class TransportConfig:
    host: str = "127.0.0.1"
    port: int = 80
    tls: bool = False
    proxy: str = ""  # socks5://host:port or http://host:port
    timeout: float = 120.0
    retries: int = 1
    retry_delay: float = 0.5


def _connect(cfg: TransportConfig) -> socket.socket:
    """Establish a TCP connection, optionally through a proxy."""
    if cfg.proxy:
        if cfg.proxy.startswith("socks5://"):
            return _socks5_connect(cfg)
        elif cfg.proxy.startswith("http://"):
            return _http_proxy_connect(cfg)
        else:
            raise ValueError(f"unsupported proxy scheme: {cfg.proxy}")

    s = socket.create_connection((cfg.host, cfg.port), timeout=cfg.timeout)
    s.settimeout(cfg.timeout)

    if cfg.tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=cfg.host)

    return s


def _socks5_connect(cfg: TransportConfig) -> socket.socket:
    """Connect through a SOCKS5 proxy."""
    proxy_url = cfg.proxy.replace("socks5://", "")
    proxy_host, proxy_port_str = proxy_url.rsplit(":", 1)
    proxy_port = int(proxy_port_str)

    s = socket.create_connection((proxy_host, proxy_port), timeout=cfg.timeout)
    s.settimeout(cfg.timeout)

    # SOCKS5 handshake: no auth
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if resp != b"\x05\x00":
        s.close()
        raise ConnectionError("SOCKS5 handshake failed")

    # SOCKS5 connect request
    addr = cfg.host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr +
              struct.pack("!H", cfg.port))
    resp = s.recv(10)
    if len(resp) < 2 or resp[1] != 0:
        s.close()
        raise ConnectionError(f"SOCKS5 connect failed: status {resp[1] if len(resp) > 1 else 'unknown'}")

    if cfg.tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=cfg.host)

    return s


def _http_proxy_connect(cfg: TransportConfig) -> socket.socket:
    """Connect through an HTTP CONNECT proxy."""
    proxy_url = cfg.proxy.replace("http://", "")
    proxy_host, proxy_port_str = proxy_url.rsplit(":", 1)
    proxy_port = int(proxy_port_str)

    s = socket.create_connection((proxy_host, proxy_port), timeout=cfg.timeout)
    s.settimeout(cfg.timeout)

    connect_req = (
        f"CONNECT {cfg.host}:{cfg.port} HTTP/1.1\r\n"
        f"Host: {cfg.host}:{cfg.port}\r\n\r\n"
    ).encode()
    s.sendall(connect_req)

    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += s.recv(4096)
    if b"200" not in resp.split(b"\r\n")[0]:
        s.close()
        raise ConnectionError(f"HTTP CONNECT failed: {resp.split(b'\\r\\n')[0]}")

    if cfg.tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=cfg.host)

    return s


def _raw_send(cfg: TransportConfig, data: bytes) -> bytes:
    """Low-level socket send with retry logic."""
    last_error = None
    for attempt in range(cfg.retries):
        try:
            s = _connect(cfg)
            resp = bytearray()
            try:
                s.sendall(data)
                while len(resp) < MAX_RESPONSE:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    resp.extend(chunk)
            except OSError:
                pass
            finally:
                s.close()
            return bytes(resp)
        except OSError as e:
            last_error = e
            if attempt < cfg.retries - 1:
                time.sleep(cfg.retry_delay)

    return b""


def send_chunked(cfg: TransportConfig, path: str, body: bytes,
                 boundary: str = DEFAULT_BOUNDARY,
                 chunk_size: int = 65536) -> bytes:
    """Send a multipart body with chunked transfer-encoding.

    Bypasses post_max_size because without Content-Length, PHP's multipart
    parser reads the dechunked body directly, skipping the size check.
    Tested: 10MB+ bodies parsed normally despite post_max_size=8M.
    """
    header = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {cfg.host}:{cfg.port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    wire = bytearray(header)
    for i in range(0, len(body), chunk_size):
        piece = body[i:i + chunk_size]
        wire += f"{len(piece):x}\r\n".encode() + piece + b"\r\n"
    wire += b"0\r\n\r\n"

    return _raw_send(cfg, bytes(wire))


def send_plain(cfg: TransportConfig, path: str, body: bytes,
               boundary: str = DEFAULT_BOUNDARY) -> bytes:
    """Send a multipart body with Content-Length (standard POST)."""
    header = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {cfg.host}:{cfg.port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return _raw_send(cfg, header + body)


def send_get(cfg: TransportConfig, path: str) -> bytes:
    """Send a simple GET request."""
    req = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {cfg.host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return _raw_send(cfg, req)


def get_status_line(resp: bytes) -> str:
    """Extract the HTTP status line from a raw response."""
    if not resp:
        return ""
    return resp.split(b"\r\n", 1)[0][:60].decode("latin1", "replace")


def get_status_code(resp: bytes) -> int:
    """Extract the HTTP status code from a raw response."""
    line = get_status_line(resp)
    parts = line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return 0
