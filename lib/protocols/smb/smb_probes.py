# -*- coding: utf-8 -*-
"""Sondes SMB bas niveau : SMBv1, signing, null session (sans authentification)."""

import socket
import struct
from typing import Tuple, Optional

# Dialectes SMB2
_SMB2_DIALECT_MAP = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

# SMBv1 Negotiate (NetBIOS + SMB)
_SMB1_NEGOTIATE_PKT = (
    b"\x00\x00\x00\x2f"
    b"\xff\x53\x4d\x42"  # SMB
    b"\x72"  # Negotiate
    b"\x00\x00\x00\x00"
    b"\x18\x01\x28"
    b"\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\xff\xff\xfe\xff\x00\x00\x00\x00"
    b"\x00"
    b"\x0c\x00"
    b"\x02NT LM 0.12\x00"
)


def _smb_recv(sock: socket.socket, length: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < length:
        try:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
    return buf


def _is_conn_reset(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "10054" in msg or "forcibly closed" in msg or "connection reset" in msg or "econnreset" in msg


def smb1_negotiate(host: str, port: int = 445, timeout: float = 3.0) -> bool:
    """Retourne True si le serveur répond à un SMBv1 Negotiate."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(_SMB1_NEGOTIATE_PKT)
            nb = _smb_recv(s, 4, timeout)
            if len(nb) < 4:
                return False
            body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            body = _smb_recv(s, min(body_len, 256), timeout)
            if len(body) < 9:
                return False
            return (
                body[0:4] == b"\xff\x53\x4d\x42"
                and body[4] == 0x72
                and struct.unpack_from("<I", body, 5)[0] == 0
            )
    except Exception:
        return False


def _build_smb2_negotiate() -> bytes:
    dialects = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    dialect_bytes = b"".join(struct.pack("<H", d) for d in dialects)
    preauth_data = struct.pack("<HHH", 1, 0, 0x0001)
    neg_ctx = struct.pack("<HHI", 0x0001, len(preauth_data), 0) + preauth_data
    dialects_end = 64 + 36 + len(dialect_bytes)
    pad_len = (8 - dialects_end % 8) % 8
    neg_ctx_offset = dialects_end + pad_len
    body = (
        struct.pack("<H", 36)
        + struct.pack("<H", len(dialects))
        + struct.pack("<H", 0x0001)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0x0000007F)
        + b"\x00" * 16
        + struct.pack("<I", neg_ctx_offset)
        + struct.pack("<H", 1)
        + struct.pack("<H", 0)
        + dialect_bytes
        + b"\x00" * pad_len
        + neg_ctx
    )
    smb2_hdr = (
        b"\xfeSMB"
        + struct.pack("<H", 64)
        + b"\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00"
        + b"\x1f\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 8
        + b"\x00" * 16
    )
    payload = smb2_hdr + body
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def check_smb_signing(
    host: str, port: int = 445, timeout: float = 3.0
) -> Tuple[str, Optional[str]]:
    """
    Retourne (signing_status, smb_version).
    signing_status: "required" | "enabled_not_required" | "disabled" | "smb2_disabled" | "unreachable" | "error"
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(_build_smb2_negotiate())
            nb = _smb_recv(s, 4, timeout)
            if len(nb) < 4:
                return "smb2_disabled", None
            body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            body = _smb_recv(s, min(body_len, 512), timeout)
            if len(body) < 68 or body[0:4] != b"\xfeSMB":
                return "smb2_disabled", None
            nt_status = struct.unpack_from("<I", body, 8)[0]
            if nt_status != 0:
                return "error", None
            sec_mode = struct.unpack_from("<H", body, 66)[0]
            dialect_code = struct.unpack_from("<H", body, 68)[0] if len(body) >= 70 else None
            ver = _SMB2_DIALECT_MAP.get(dialect_code) if dialect_code is not None else None
            if sec_mode & 0x02:
                return "required", ver
            if sec_mode & 0x01:
                return "enabled_not_required", ver
            return "disabled", ver
    except socket.timeout:
        return "error", None
    except ConnectionRefusedError:
        return "unreachable", None
    except Exception as e:
        if _is_conn_reset(e):
            return "smb2_disabled", None
        return "error", None


# Null session (SMBv1 session setup anonymous)
_NULL_SESSION_PKT = (
    b"\x00\x00\x00\x59"
    b"\xff\x53\x4d\x42"
    b"\x73"  # Session setup
    b"\x00\x00\x00\x00"
    b"\x18"
    b"\x07\xc0"
    b"\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00"
    b"\xff\xff"
    b"\xff\xfe"
    b"\x00\x00"
    b"\x40\x00"
    b"\x0d"
    b"\xff"
    b"\x00"
    b"\x00\x00"
    b"\xff\x00"
    b"\x02\x00"
    b"\x01\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00"
    b"\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x60\x48\x06\x06"
    b"\x11\x00"
    b"\x00"
    b"\x00"
    b"\x57\x69\x6e\x64\x6f\x77\x73\x00"
    b"\x57\x69\x6e\x64\x6f\x77\x73\x00"
)


def check_null_session(host: str, port: int = 445, timeout: float = 3.0) -> bool:
    """Retourne True si une null session (anonyme) est acceptée."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(_NULL_SESSION_PKT)
            resp = _smb_recv(s, 256, timeout)
            if len(resp) >= 13 and resp[4:8] == b"\xff\x53\x4d\x42":
                return struct.unpack_from("<I", resp, 9)[0] == 0
    except Exception:
        pass
    return False


def smb2_negotiate_info(
    host: str, port: int = 445, timeout: float = 3.0
) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    SMB2 negotiate summary (NSE smb2-security-mode / smb-protocols inspired).
    Returns (signing_status, dialect_name, dialect_code).
    """
    status, ver = check_smb_signing(host, port, timeout)
    dialect_code = None
    for code, name in _SMB2_DIALECT_MAP.items():
        if name == ver:
            dialect_code = code
            break
    return status, ver, dialect_code


def probe_smb_os_discovery(host: str, port: int = 445, timeout: float = 5.0) -> dict:
    """
    Best-effort SMB OS / domain discovery (NSE smb-os-discovery).
    Tries pysmb anonymous connect, then falls back to SMB1 negotiate string scrape.
    """
    result = {
        "detected": False,
        "os": "",
        "lan_manager": "",
        "domain": "",
        "server": "",
        "dns_domain": "",
        "fqdn": "",
        "smb1": False,
        "error": "",
    }
    # pysmb path
    try:
        from smb.SMBConnection import SMBConnection

        conn = SMBConnection("", "", "kittysploit", host, use_ntlm_v2=True, is_direct_tcp=True)
        connected = conn.connect(host, int(port), timeout=timeout)
        if connected:
            result["detected"] = True
            # pysmb attributes vary by version
            for attr, key in (
                ("remote_name", "server"),
                ("remoteHost", "server"),
            ):
                val = getattr(conn, attr, None)
                if val:
                    result[key] = str(val)[:120]
            # Some versions expose getServerOS via unsupported API — scrape session
            try:
                # is_supporting_smb2 etc.
                result["smb1"] = not bool(getattr(conn, "is_using_smb2", lambda: True)())
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
    except Exception as exc:
        result["error"] = str(exc)[:120]

    # SMB1 negotiate scrape for domain/OEM strings
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(_SMB1_NEGOTIATE_PKT)
            nb = _smb_recv(s, 4, timeout)
            if len(nb) >= 4:
                body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
                body = _smb_recv(s, min(body_len, 1024), timeout)
                if len(body) >= 9 and body[0:4] == b"\xffSMB":
                    result["smb1"] = True
                    result["detected"] = True
                    # Extract printable ASCII/UTF-16 fragments (domain / OS hints)
                    text_bits = []
                    # ASCII runs
                    cur = bytearray()
                    for b in body[32:]:
                        if 32 <= b < 127:
                            cur.append(b)
                        else:
                            if len(cur) >= 3:
                                text_bits.append(cur.decode("ascii"))
                            cur = bytearray()
                    if len(cur) >= 3:
                        text_bits.append(cur.decode("ascii"))
                    # Prefer NT LM / Windows strings
                    for t in text_bits:
                        low = t.lower()
                        if "windows" in low or "samba" in low:
                            result["os"] = result["os"] or t[:80]
                        elif "lanman" in low or "samba" in low:
                            result["lan_manager"] = result["lan_manager"] or t[:80]
                    # Domain often appears as OEM domain in security blob tail
                    if text_bits and not result["domain"]:
                        # last short uppercase-ish token
                        for t in reversed(text_bits):
                            if t.isupper() and 2 <= len(t) <= 15 and " " not in t:
                                result["domain"] = t
                                break
    except Exception as exc:
        if not result["error"]:
            result["error"] = str(exc)[:120]

    # Enrich with SMB2 dialect
    try:
        signing, dialect, _ = smb2_negotiate_info(host, port, timeout)
        if dialect:
            result["detected"] = True
            if not result["lan_manager"]:
                result["lan_manager"] = dialect
            if signing and signing not in ("error", "unreachable"):
                result["signing"] = signing
    except Exception:
        pass

    return result


def check_samba_cve_2017_7494(host: str, port: int = 445, timeout: float = 5.0) -> dict:
    """
    Non-intrusive SambaCry (CVE-2017-7494) likelihood check (NSE check-version mode).
    Parses Samba version from OS discovery strings; flags known vulnerable ranges.
    Does NOT upload/execute payloads.
    """
    result = {
        "likely_vulnerable": False,
        "checked": False,
        "samba_version": "",
        "os": "",
        "error": "",
    }
    info = probe_smb_os_discovery(host, port, timeout)
    blob = " ".join(
        str(info.get(k) or "")
        for k in ("os", "lan_manager", "server", "domain")
    )
    result["os"] = str(info.get("os") or "")[:120]
    import re

    m = re.search(r"[Ss]amba\s*([0-9]+(?:\.[0-9]+){1,3})", blob)
    if not m:
        # Also try dialect string alone
        m = re.search(r"[Ss]amba[/\s-]*([0-9]+(?:\.[0-9]+){1,3})", blob)
    if not m:
        result["error"] = "samba_version_not_found"
        result["checked"] = bool(info.get("detected"))
        return result
    ver = m.group(1)
    result["samba_version"] = ver
    result["checked"] = True

    def _parts(v: str):
        return tuple(int(x) for x in v.split(".")[:3])

    try:
        p = _parts(ver)
    except Exception:
        result["error"] = "version_parse_failed"
        return result

    # Vulnerable ranges (approximate, from Samba advisories / NSE):
    # 3.5.0 - 3.5.x, 3.6.0 - 3.6.25, 4.0.0 - 4.0.25, 4.1.0 - 4.1.17,
    # 4.2.0 - 4.2.9, 4.3.0 - 4.3.8, 4.4.0 - 4.4.2, and some 4.5/4.6 early
    vulnerable = False
    if p[0] == 3 and p[1] >= 5:
        vulnerable = True
    elif p[0] == 4:
        major_minor = (p[0], p[1])
        patch = p[2] if len(p) > 2 else 0
        ranges = {
            (4, 0): 25,
            (4, 1): 17,
            (4, 2): 9,
            (4, 3): 8,
            (4, 4): 2,
            (4, 5): 2,
            (4, 6): 0,
        }
        if major_minor in ranges and patch <= ranges[major_minor]:
            vulnerable = True
        elif major_minor[1] < 0:
            vulnerable = False
    result["likely_vulnerable"] = vulnerable
    return result


# NTSTATUS codes for MS17-010 check
_STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205
_STATUS_ACCESS_DENIED = 0xC0000022
_STATUS_INVALID_HANDLE = 0xC0000008


def check_ms17_010(host: str, port: int = 445, timeout: float = 5.0) -> dict:
    """
    Unauthenticated MS17-010 (EternalBlue) probe inspired by NSE smb-vuln-ms17-010.
    Performs SMBv1 negotiate → anonymous session → IPC$ tree connect →
    PeekNamedPipe on FID 0. Vulnerable hosts return STATUS_INSUFF_SERVER_RESOURCES.
    """
    result = {
        "vulnerable": False,
        "checked": False,
        "status": None,
        "status_name": "",
        "error": "",
        "smb1": False,
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            # Negotiate
            s.sendall(_SMB1_NEGOTIATE_PKT)
            nb = _smb_recv(s, 4, timeout)
            if len(nb) < 4:
                result["error"] = "no_negotiate_response"
                return result
            body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            body = _smb_recv(s, min(body_len, 512), timeout)
            if len(body) < 9 or body[0:4] != b"\xffSMB":
                result["error"] = "smb1_negotiate_failed"
                return result
            result["smb1"] = True

            # Session Setup AndX (anonymous) — reuse null session packet body after NetBIOS
            s.sendall(_NULL_SESSION_PKT)
            nb = _smb_recv(s, 4, timeout)
            if len(nb) < 4:
                result["error"] = "no_session_response"
                return result
            body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            sess = _smb_recv(s, min(body_len, 512), timeout)
            if len(sess) < 32 or sess[0:4] != b"\xffSMB":
                result["error"] = "session_setup_failed"
                return result
            uid = struct.unpack_from("<H", sess, 28)[0]
            nt_status = struct.unpack_from("<I", sess, 5)[0]
            # Some servers return non-zero but still assign UID
            if nt_status not in (0, 0xC0000016) and uid == 0:
                result["error"] = f"session_status_0x{nt_status:08x}"
                return result

            # Tree Connect AndX to \\host\IPC$
            path = f"\\\\{host}\\IPC$\x00".encode("utf-16-le")
            service = b"?????\x00"
            tree_params = (
                b"\x04"  # WordCount
                + b"\xff\x00"  # AndX no further
                + b"\x00\x00"  # AndXOffset
                + struct.pack("<H", 1)  # PasswordLength = 1
            )
            tree_data = b"\x00" + path + service
            bcc = struct.pack("<H", len(tree_data))
            smb_hdr = (
                b"\xffSMB"
                + b"\x75"  # Tree Connect AndX
                + b"\x00\x00\x00\x00"
                + b"\x18\x01\x28"
                + b"\x00\x00"
                + b"\x00\x00\x00\x00\x00\x00\x00\x00"
                + b"\x00\x00"
                + b"\x00\x00"
                + b"\xff\xfe"
                + struct.pack("<H", uid)
                + b"\x00\x00"
            )
            tree_pkt_body = smb_hdr + tree_params + bcc + tree_data
            s.sendall(b"\x00" + len(tree_pkt_body).to_bytes(3, "big") + tree_pkt_body)
            nb = _smb_recv(s, 4, timeout)
            if len(nb) < 4:
                result["error"] = "no_tree_response"
                return result
            body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            tree = _smb_recv(s, min(body_len, 512), timeout)
            if len(tree) < 32 or tree[0:4] != b"\xffSMB":
                result["error"] = "tree_connect_failed"
                return result
            tree_status = struct.unpack_from("<I", tree, 5)[0]
            if tree_status != 0:
                result["error"] = f"tree_status_0x{tree_status:08x}"
                return result
            tid = struct.unpack_from("<H", tree, 24)[0]

            # SMB_COM_TRANSACTION PeekNamedPipe FID=0
            pipe = b"\\PIPE\\\x00"
            setup = struct.pack("<HH", 0x0023, 0x0000)
            wc = 16  # 14 + 2 setup words
            words = (
                struct.pack("<H", 0)
                + struct.pack("<H", 0)
                + struct.pack("<H", 0xFFFF)
                + struct.pack("<H", 0xFFFF)
                + struct.pack("<B", 0)
                + struct.pack("<B", 0)
                + struct.pack("<H", 0)
                + struct.pack("<I", 0)
                + struct.pack("<H", 0)
                + struct.pack("<H", 0)
                + struct.pack("<H", 0x004A)
                + struct.pack("<H", 0)
                + struct.pack("<H", 0x004A)
                + struct.pack("<B", 2)
                + struct.pack("<B", 0)
                + setup
            )
            byte_count = struct.pack("<H", len(pipe))
            smb_hdr = (
                b"\xffSMB"
                + b"\x25"  # Transaction
                + b"\x00\x00\x00\x00"
                + b"\x18"
                + b"\x01\x28"
                + b"\x00\x00"
                + b"\x00\x00\x00\x00\x00\x00\x00\x00"
                + b"\x00\x00"
                + struct.pack("<H", tid)
                + b"\xff\xfe"
                + struct.pack("<H", uid)
                + b"\x40\x00"
            )
            body = smb_hdr + bytes([wc]) + words + byte_count + pipe
            s.sendall(b"\x00" + len(body).to_bytes(3, "big") + body)
            nb = _smb_recv(s, 4, timeout)
            if len(nb) < 4:
                result["error"] = "no_trans_response"
                return result
            body_len = struct.unpack(">I", nb)[0] & 0x00FFFFFF
            trans = _smb_recv(s, min(body_len, 512), timeout)
            if len(trans) < 9 or trans[0:4] != b"\xffSMB":
                result["error"] = "trans_parse_failed"
                return result
            status = struct.unpack_from("<I", trans, 5)[0]
            result["checked"] = True
            result["status"] = status
            if status == _STATUS_INSUFF_SERVER_RESOURCES:
                result["vulnerable"] = True
                result["status_name"] = "STATUS_INSUFF_SERVER_RESOURCES"
            elif status == _STATUS_ACCESS_DENIED:
                result["status_name"] = "STATUS_ACCESS_DENIED"
            elif status == _STATUS_INVALID_HANDLE:
                result["status_name"] = "STATUS_INVALID_HANDLE"
            else:
                result["status_name"] = f"0x{status:08x}"
            return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
