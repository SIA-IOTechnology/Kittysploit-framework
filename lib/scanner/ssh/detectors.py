#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH Detectors - Helpers pour détecter des serveurs SSH
"""

import re
from typing import Optional


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
