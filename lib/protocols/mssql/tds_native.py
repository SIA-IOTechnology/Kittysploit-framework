# -*- coding: utf-8 -*-
"""Minimal TDS client for Kerberos integrated-auth relay (stdlib + ssl only)."""

from __future__ import annotations

import logging
import random
import socket
import ssl
import string
import struct
from typing import Dict, List, Optional, Tuple

LOG = logging.getLogger(__name__)

TDS_SQL_BATCH = 1
TDS_LOGIN7 = 16
TDS_PRE_LOGIN = 18

TDS_STATUS_NORMAL = 0
TDS_STATUS_EOM = 1

TDS_ENCRYPT_OFF = 0
TDS_ENCRYPT_ON = 1
TDS_ENCRYPT_REQ = 3

TDS_INTEGRATED_SECURITY_ON = 0x80
TDS_INIT_LANG_FATAL = 0x01
TDS_ODBC_ON = 0x02

TDS_LOGINACK_TOKEN = 0xAD
TDS_ERROR_TOKEN = 0xAA
TDS_INFO_TOKEN = 0xAB
TDS_ENVCHANGE_TOKEN = 0xE3
TDS_DONE_TOKEN = 0xFD
TDS_DONEPROC_TOKEN = 0xFE
TDS_DONEINPROC_TOKEN = 0xFF
TDS_ROW_TOKEN = 0xD1
TDS_COLMETADATA_TOKEN = 0x81


class TdsError(Exception):
    pass


def _pack_packet(packet_type: int, data: bytes, status: int = TDS_STATUS_EOM, packet_id: int = 1) -> bytes:
    header = struct.pack("<BBHHB B", packet_type, status, len(data) + 8, 0, packet_id, 0)
    return header + data


def _build_prelogin() -> bytes:
    version = b"\x08\x00\x01\x55\x00\x00"
    instance = b"MSSQLServer\x00"
    thread_id = struct.pack("<I", random.randint(0, 65535))
    body = (
        struct.pack(">BHH", 0, 21, len(version))
        + struct.pack(">BHH", 1, 21 + len(version), 1)
        + struct.pack(">BHH", 2, 22 + len(version), len(instance))
        + struct.pack(">BHH", 3, 22 + len(version) + len(instance), 4)
        + struct.pack(">B", 0xFF)
        + version
        + struct.pack("B", TDS_ENCRYPT_OFF)
        + instance
        + thread_id
    )
    return body


def _build_login7(
    server_name: str,
    hostname: str,
    appname: str,
    sspi_blob: bytes,
    packet_size: int = 4096,
) -> bytes:
    host = hostname.encode("utf-16le")
    app = appname.encode("utf-16le")
    server = server_name.encode("utf-16le")
    clt = appname.encode("utf-16le")
    user = b""
    password = b""
    language = b""
    database = b""
    attach = b""
    change_pw = b""
    sspi = sspi_blob

    chunks = [host, user, password, app, server, clt, language, database, sspi, attach, change_pw]
    index = 94
    offsets = []
    for chunk in chunks:
        offsets.append(index)
        index += len(chunk)

    buf = bytearray()
    buf.extend(b"\x00\x00\x00\x00")
    buf.extend(struct.pack(">I", 0x00000071))
    buf.extend(struct.pack("<III", packet_size, 7, random.randint(0, 1024)))
    buf.extend(struct.pack("<I", 0))
    buf.extend(
        struct.pack(
            "<BBBB",
            0xE0,
            TDS_INIT_LANG_FATAL | TDS_ODBC_ON | TDS_INTEGRATED_SECURITY_ON,
            0,
            0,
        )
    )
    buf.extend(struct.pack("<II", 0, 0))
    buf.extend(struct.pack("<HH", offsets[0], len(host) // 2))
    buf.extend(struct.pack("<HH", offsets[1], len(user) // 2))
    buf.extend(struct.pack("<HH", offsets[2], len(password) // 2))
    buf.extend(struct.pack("<HH", offsets[3], len(app) // 2))
    buf.extend(struct.pack("<HH", offsets[4], len(server) // 2))
    buf.extend(struct.pack("<HH", 0, 0))
    buf.extend(struct.pack("<HH", offsets[5], len(clt) // 2))
    buf.extend(struct.pack("<HH", offsets[6], len(language) // 2))
    buf.extend(struct.pack("<HH", offsets[7], len(database) // 2))
    buf.extend(b"\x01\x02\x03\x04\x05\x06")
    buf.extend(struct.pack("<HH", offsets[8], min(len(sspi), 0xFFFF)))
    buf.extend(struct.pack("<HH", offsets[9], len(attach) // 2))
    buf.extend(struct.pack("<HH", offsets[10], len(change_pw) // 2))
    buf.extend(struct.pack("<I", len(sspi) if len(sspi) > 0xFFFF else 0))
    if len(buf) < 94:
        buf.extend(b"\x00" * (94 - len(buf)))
    for chunk in chunks:
        buf.extend(chunk)
    struct.pack_into("<I", buf, 0, len(buf))
    return bytes(buf)


class TdsNativeClient:
    def __init__(self, host: str, port: int = 1433, timeout: float = 30.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.packet_size = 4096
        self._sock: Optional[socket.socket] = None
        self._tls: Optional[ssl.SSLObject] = None
        self._in_bio: Optional[ssl.MemoryBIO] = None
        self._out_bio: Optional[ssl.MemoryBIO] = None
        self._recv_buffer = b""
        self._encryption = TDS_ENCRYPT_OFF

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock = sock

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self._tls = None
        self._in_bio = None
        self._out_bio = None
        self._recv_buffer = b""

    def _send_raw(self, data: bytes) -> None:
        if not self._sock:
            raise TdsError("Not connected")
        if self._tls is not None:
            self._tls.write(data)
            while True:
                try:
                    encrypted = self._out_bio.read(4096)  # type: ignore[union-attr]
                except ssl.SSLWantReadError:
                    break
                if not encrypted:
                    break
                self._sock.sendall(encrypted)
        else:
            self._sock.sendall(data)

    def _recv_raw(self, size: int) -> bytes:
        if not self._sock:
            raise TdsError("Not connected")
        if self._tls is not None:
            while True:
                try:
                    data = self._tls.read(size)
                    if data:
                        return data
                except ssl.SSLWantReadError:
                    chunk = self._sock.recv(size)
                    if not chunk:
                        raise TdsError("Server closed connection during TLS read")
                    self._in_bio.write(chunk)  # type: ignore[union-attr]
            raise TdsError("TLS read failed")
        data = self._sock.recv(size)
        if not data:
            raise TdsError("Server closed connection")
        return data

    def _recv_exact(self, length: int) -> bytes:
        while len(self._recv_buffer) < length:
            self._recv_buffer += self._recv_raw(max(4096, length - len(self._recv_buffer)))
        data = self._recv_buffer[:length]
        self._recv_buffer = self._recv_buffer[length:]
        return data

    def _send_tds(self, packet_type: int, data: bytes, packet_id: int = 1) -> None:
        packet = _pack_packet(packet_type, data, status=TDS_STATUS_EOM, packet_id=packet_id)
        self._send_raw(packet)

    def _recv_tds(self) -> bytes:
        header = self._recv_exact(8)
        packet_len = struct.unpack(">H", header[2:4])[0]
        body = self._recv_exact(packet_len - 8)
        status = header[1]
        while status != TDS_STATUS_EOM:
            header = self._recv_exact(8)
            packet_len = struct.unpack(">H", header[2:4])[0]
            body += self._recv_exact(packet_len - 8)
            status = header[1]
        return body

    def _setup_tls(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        in_bio = ssl.MemoryBIO()
        out_bio = ssl.MemoryBIO()
        tls = context.wrap_bio(in_bio, out_bio, server_side=False)
        while True:
            try:
                tls.do_handshake()
            except ssl.SSLWantReadError:
                data = out_bio.read(4096)
                if data:
                    self._send_raw(_pack_packet(TDS_PRE_LOGIN, data, status=TDS_STATUS_EOM, packet_id=0))
                response_header = self._recv_exact(8)
                response_len = struct.unpack(">H", response_header[2:4])[0]
                response_body = self._recv_exact(response_len - 8)
                in_bio.write(response_body)
            else:
                break
        self._tls = tls
        self._in_bio = in_bio
        self._out_bio = out_bio
        self.packet_size = 16 * 1024 - 1

    def prelogin(self) -> int:
        self._send_tds(TDS_PRE_LOGIN, _build_prelogin(), packet_id=0)
        response = self._recv_tds()
        encryption = TDS_ENCRYPT_OFF
        offset = 0
        while offset + 5 <= len(response):
            token = response[offset]
            if token == 0xFF:
                break
            rec_len = struct.unpack(">H", response[offset + 1 : offset + 3])[0]
            value = response[offset + 3 : offset + 3 + rec_len]
            if token == 0x01 and value:
                encryption = value[0]
            offset += 3 + rec_len
        self._encryption = encryption
        if encryption in (TDS_ENCRYPT_REQ, TDS_ENCRYPT_OFF):
            self._setup_tls()
        return encryption

    def login_integrated(self, sspi_blob: bytes, server_name: Optional[str] = None) -> bool:
        label = "".join(random.choice(string.ascii_letters) for _ in range(8))
        login_data = _build_login7(
            server_name or self.host,
            label,
            label,
            sspi_blob,
            packet_size=self.packet_size,
        )
        self._send_tds(TDS_LOGIN7, login_data)
        if self._encryption == TDS_ENCRYPT_OFF and self._tls is not None:
            self._tls = None
            self._in_bio = None
            self._out_bio = None
        tokens = self._recv_tds()
        return TDS_LOGINACK_TOKEN in tokens

    def execute_sql(self, query: str) -> Tuple[bool, str]:
        sql = (query.rstrip(";") + "\r\n").encode("utf-16le")
        self._send_tds(TDS_SQL_BATCH, sql)
        tokens = self._recv_tds()
        if TDS_ERROR_TOKEN in tokens:
            return False, self._parse_error(tokens)
        rows = self._parse_rows(tokens)
        return True, rows

    @staticmethod
    def _parse_error(tokens: bytes) -> str:
        offset = 0
        while offset < len(tokens):
            token_id = tokens[offset]
            if token_id == TDS_ERROR_TOKEN:
                if offset + 3 > len(tokens):
                    return "MSSQL error"
                length = struct.unpack("<H", tokens[offset + 1 : offset + 3])[0]
                chunk = tokens[offset + 3 : offset + 3 + length]
                if len(chunk) >= 8:
                    msg_len = struct.unpack("<H", chunk[6:8])[0]
                    if len(chunk) >= 8 + msg_len * 2:
                        return chunk[8 : 8 + msg_len * 2].decode("utf-16le", errors="replace")
                return "MSSQL error"
            offset += 1
        return "MSSQL error"

    @staticmethod
    def _parse_rows(tokens: bytes) -> str:
        lines: List[str] = []
        offset = 0
        columns: List[dict] = []
        while offset < len(tokens):
            token_id = tokens[offset]
            if token_id == TDS_COLMETADATA_TOKEN:
                _, offset, columns = TdsNativeClient._skip_colmetadata(tokens, offset)
                continue
            if token_id == TDS_ROW_TOKEN and columns:
                row, offset = TdsNativeClient._parse_row(tokens, offset + 1, columns)
                if row:
                    lines.append("\t".join(row))
                continue
            if token_id in (TDS_DONE_TOKEN, TDS_DONEPROC_TOKEN, TDS_DONEINPROC_TOKEN):
                if offset + 3 <= len(tokens):
                    length = struct.unpack("<H", tokens[offset + 1 : offset + 3])[0]
                    offset += 3 + length
                else:
                    offset += 1
                continue
            if token_id == TDS_ENVCHANGE_TOKEN:
                if offset + 3 <= len(tokens):
                    length = struct.unpack("<H", tokens[offset + 1 : offset + 3])[0]
                    offset += 3 + length
                else:
                    offset += 1
                continue
            offset += 1
        return "\n".join(lines) if lines else "(no rows)"

    @staticmethod
    def _skip_colmetadata(data: bytes, offset: int):
        if offset + 3 > len(data):
            return data, offset + 1, []
        count = struct.unpack("<H", data[offset + 1 : offset + 3])[0]
        pos = offset + 3
        columns = []
        for _ in range(count):
            if pos >= len(data):
                break
            user_type = struct.unpack("<I", data[pos : pos + 4])[0]
            pos += 4
            flags = struct.unpack("<H", data[pos : pos + 2])[0]
            pos += 2
            col_type = data[pos]
            pos += 1
            type_data = b""
            if col_type in (0x26, 0x6A, 0x6C, 0x6D, 0x6E, 0x6F, 0x28, 0x29, 0x2A, 0x2B):
                type_data = data[pos : pos + 1]
                pos += 1
            elif col_type in (0x27, 0x2F, 0xE7, 0xEF, 0x25, 0x2D, 0xA5, 0xA7, 0xAD, 0xAF):
                if pos + 2 <= len(data):
                    char_len = struct.unpack("<H", data[pos : pos + 2])[0]
                    pos += 2
                    type_data = struct.pack("<H", char_len)
            col_name_len = data[pos] if pos < len(data) else 0
            pos += 1
            col_name = ""
            if col_name_len and pos + col_name_len * 2 <= len(data):
                col_name = data[pos : pos + col_name_len * 2].decode("utf-16le", errors="replace")
                pos += col_name_len * 2
            columns.append({"type": col_type, "name": col_name, "type_data": type_data})
        return data, pos, columns

    @staticmethod
    def _parse_row(data: bytes, offset: int, columns: List[dict]) -> Tuple[List[str], int]:
        values: List[str] = []
        pos = offset
        for column in columns:
            if pos >= len(data):
                break
            col_type = column["type"]
            if col_type in (0x38,):  # INT4
                if pos + 4 > len(data):
                    break
                values.append(str(struct.unpack("<i", data[pos : pos + 4])[0]))
                pos += 4
            elif col_type in (0xE7, 0xA7):  # NVARCHAR / BIGVARCHAR
                if pos + 2 > len(data):
                    break
                ln = struct.unpack("<H", data[pos : pos + 2])[0]
                pos += 2
                if ln == 0xFFFF:
                    values.append("NULL")
                    continue
                values.append(data[pos : pos + ln * 2].decode("utf-16le", errors="replace"))
                pos += ln * 2
            elif col_type in (0x2F, 0x27):  # CHAR / VARCHAR
                if pos + 2 > len(data):
                    break
                ln = struct.unpack("<H", data[pos : pos + 2])[0]
                pos += 2
                if ln == 0xFFFF:
                    values.append("NULL")
                    continue
                values.append(data[pos : pos + ln].decode("utf-8", errors="replace"))
                pos += ln
            else:
                if pos + 2 > len(data):
                    break
                ln = struct.unpack("<H", data[pos : pos + 2])[0]
                pos += 2
                if ln == 0xFFFF:
                    values.append("NULL")
                else:
                    values.append(data[pos : pos + ln].hex())
                    pos += ln
        return values, pos
