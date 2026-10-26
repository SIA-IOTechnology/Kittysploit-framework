#!/usr/bin/env python3
"""
recon.py — php2shell target fingerprinting (phase 0)

Pure HTTP probes. No exploitation, no file writes on target.
Detects: PHP version, OS, SAPI (mod_php/fpm), MPM (prefork/worker/event),
session.upload_progress status, and whether target is in vulnerable range.

Usage standalone:
    python3 recon.py http://target:port/index.php

Usage from exploit.py:
    from recon import fingerprint
    info = fingerprint("127.0.0.1", 8088, "/index.php")
    if not info["vulnerable"]:
        sys.exit("target not vulnerable")
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl
import sys
import urllib.parse
from dataclasses import dataclass, field


PATCHED_VERSIONS = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

BOUNDARY = "----recon0xdeadbeef"


@dataclass
class TargetInfo:
    url: str = ""
    reachable: bool = False
    php_version: str = ""
    php_version_tuple: tuple = ()
    os_hint: str = ""
    server: str = ""
    sapi: str = ""
    mpm: str = ""
    upload_progress: str = ""
    vulnerable: bool = False
    vulns: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    raw_headers: dict = field(default_factory=dict)

    def summary(self) -> str:
        lines = []
        lines.append(f"Target       : {self.url}")
        lines.append(f"Reachable    : {'yes' if self.reachable else 'NO'}")
        if not self.reachable:
            return "\n".join(lines)
        lines.append(f"PHP Version  : {self.php_version or 'hidden'}")
        lines.append(f"OS Hint      : {self.os_hint or 'unknown'}")
        lines.append(f"Server       : {self.server or 'hidden'}")
        lines.append(f"SAPI         : {self.sapi or 'unknown'}")
        lines.append(f"MPM          : {self.mpm or 'unknown'}")
        lines.append(f"UploadProg   : {self.upload_progress or 'unknown'}")
        lines.append(f"Vulnerable   : {'YES' if self.vulnerable else 'no'}")
        if self.vulns:
            for v in self.vulns:
                lines.append(f"  [!] {v}")
        if self.notes:
            for n in self.notes:
                lines.append(f"  [i] {n}")
        return "\n".join(lines)


def _conn(host: str, port: int, use_tls: bool, timeout: float = 10):
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _get(host: str, port: int, path: str, tls: bool, timeout: float = 10,
         extra_headers: dict | None = None) -> tuple[int, dict, bytes]:
    conn = _conn(host, port, tls, timeout)
    hdrs = {"Host": host, "Connection": "close", "User-Agent": "Mozilla/5.0"}
    if extra_headers:
        hdrs.update(extra_headers)
    try:
        conn.request("GET", path, headers=hdrs)
        r = conn.getresponse()
        body = r.read(1 << 20)
        headers = {k.lower(): v for k, v in r.getheaders()}
        return r.status, headers, body
    except Exception:
        return 0, {}, b""
    finally:
        conn.close()


def _post_multipart(host: str, port: int, path: str, tls: bool,
                    fields: list[tuple[str, str, bytes | None]],
                    timeout: float = 10) -> tuple[int, dict, bytes]:
    parts = []
    for name, value, filename_data in fields:
        if filename_data is not None:
            parts.append(
                f"--{BOUNDARY}\r\nContent-Disposition: form-data; "
                f'name="{name}"; filename="probe.txt"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n".encode()
                + filename_data + b"\r\n"
            )
        else:
            parts.append(
                f"--{BOUNDARY}\r\nContent-Disposition: form-data; "
                f'name="{name}"\r\n\r\n{value}\r\n'.encode()
            )
    body = b"".join(parts) + f"--{BOUNDARY}--\r\n".encode()

    conn = _conn(host, port, tls, timeout)
    try:
        conn.request("POST", path, body=body, headers={
            "Host": host,
            "Connection": "close",
            "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
            "Content-Length": str(len(body)),
            "User-Agent": "Mozilla/5.0",
        })
        r = conn.getresponse()
        resp_body = r.read(1 << 20)
        headers = {k.lower(): v for k, v in r.getheaders()}
        return r.status, headers, resp_body
    except Exception:
        return 0, {}, b""
    finally:
        conn.close()


def _parse_php_version(s: str) -> tuple:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s)
    if m:
        return tuple(int(x) for x in m.groups())
    return ()


def _detect_os(server: str, headers: dict, body: bytes) -> str:
    combined = (server + " " + str(headers) + " " + body.decode("latin1", "replace")).lower()
    if "debian" in combined or "deb" in combined:
        return "Debian/Ubuntu"
    if "ubuntu" in combined:
        return "Ubuntu"
    if "centos" in combined or "el7" in combined or "el8" in combined or "el9" in combined:
        return "CentOS/RHEL"
    if "red hat" in combined or "rhel" in combined:
        return "RHEL"
    if "alpine" in combined:
        return "Alpine"
    if "win" in server.lower() or "iis" in server.lower():
        return "Windows"
    if "unix" in combined or "linux" in combined:
        return "Linux"
    return ""


def _detect_sapi(server: str, headers: dict) -> str:
    s = server.lower()
    if "php/" in s:
        return "mod_php"
    via = headers.get("via", "").lower()
    if "fastcgi" in via or "fpm" in via:
        return "php-fpm"
    xpb = headers.get("x-powered-by", "").lower()
    if "php-fpm" in xpb:
        return "php-fpm"
    if "php/" in xpb and ("apache" in s or "nginx" in s):
        if "apache" in s:
            return "mod_php (probable)"
        return "php-fpm (probable)"
    return ""


def _detect_mpm(host: str, port: int, path: str, tls: bool) -> str:
    try:
        conns = []
        for _ in range(4):
            c = _conn(host, port, tls, timeout=5)
            c.request("GET", path, headers={
                "Host": host, "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0",
            })
            conns.append(c)

        pids = set()
        for c in conns:
            try:
                r = c.getresponse()
                r.read()
                pid_hdr = {k.lower(): v for k, v in r.getheaders()}.get("x-process-id", "")
                if pid_hdr:
                    pids.add(pid_hdr)
            except Exception:
                pass
            finally:
                c.close()

        if len(pids) > 1:
            return "prefork (multiple PIDs)"
    except Exception:
        pass

    # heuristic: server header sometimes reveals MPM
    status, headers, _ = _get(host, port, path, tls)
    server = headers.get("server", "")
    if "prefork" in server.lower():
        return "prefork"
    if "event" in server.lower():
        return "event"
    if "worker" in server.lower():
        return "worker"

    # timing heuristic: send slow requests in parallel
    # prefork with MaxRequestWorkers=1 will serialize them
    try:
        import time
        t0 = time.monotonic()
        socks = []
        for _ in range(3):
            s = socket.create_connection((host, port), timeout=5)
            req = f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            s.sendall(req)
            socks.append(s)
        for s in socks:
            s.recv(4096)
            s.close()
        elapsed = time.monotonic() - t0
        if elapsed > 2.0:
            return "prefork (single-worker behavior)"
    except Exception:
        pass

    return ""


def _probe_upload_progress(host: str, port: int, path: str, tls: bool) -> str:
    status, headers, body = _post_multipart(host, port, path, tls, [
        ("PHP_SESSION_UPLOAD_PROGRESS", "probe_recon", None),
        ("upload", "", b"X" * 256),
    ])
    if status == 0:
        return "unreachable"

    cookies = headers.get("set-cookie", "")
    if "PHPSESSID" in cookies:
        return "ACTIVE (session cookie set on upload progress probe)"

    # try with explicit session id
    status2, headers2, body2 = _post_multipart(host, port, path, tls, [
        ("PHPSESSID", "reconprobe000000000000000000000000", None),
        ("PHP_SESSION_UPLOAD_PROGRESS", "probe_recon", None),
        ("upload", "", b"X" * 256),
    ])
    cookies2 = headers2.get("set-cookie", "")
    if "PHPSESSID" in cookies2:
        return "ACTIVE (session started via form field + progress)"

    return "inactive or hidden"


def fingerprint(host: str, port: int, path: str = "/",
                tls: bool = False, timeout: float = 10) -> TargetInfo:
    info = TargetInfo(url=f"{'https' if tls else 'http'}://{host}:{port}{path}")

    # basic reachability + header grab
    status, headers, body = _get(host, port, path, tls, timeout)
    if status == 0:
        return info
    info.reachable = True
    info.raw_headers = headers

    # PHP version
    xpb = headers.get("x-powered-by", "")
    server = headers.get("server", "")
    info.server = server

    php_str = ""
    if "PHP/" in xpb:
        php_str = xpb
    elif "PHP/" in server:
        php_str = server
    if php_str:
        info.php_version = re.search(r"PHP/[\d.]+", php_str).group() if re.search(r"PHP/[\d.]+", php_str) else php_str
        info.php_version_tuple = _parse_php_version(php_str)
    else:
        info.notes.append("PHP version hidden (X-Powered-By/Server stripped)")
        # try triggering error
        st2, hd2, bd2 = _get(host, port, path + "?=" + "A" * 2000, tls, timeout)
        for src in [hd2.get("x-powered-by", ""), bd2.decode("latin1", "replace")]:
            if "PHP/" in src:
                info.php_version = re.search(r"PHP/[\d.]+", src).group()
                info.php_version_tuple = _parse_php_version(src)
                break

    # OS detection
    info.os_hint = _detect_os(server, headers, body)

    # SAPI detection
    info.sapi = _detect_sapi(server, headers)

    # MPM detection (only if Apache)
    if "apache" in server.lower() or "mod_php" in info.sapi:
        info.mpm = _detect_mpm(host, port, path, tls)

    # upload_progress probe
    info.upload_progress = _probe_upload_progress(host, port, path, tls)

    # vulnerability assessment
    if info.php_version_tuple:
        major_minor = info.php_version_tuple[:2]
        patch_ver = PATCHED_VERSIONS.get(major_minor)

        if major_minor < (8, 2):
            info.vulnerable = True
            info.vulns.append(f"PHP {info.php_version} — EOL, no patch available")
        elif patch_ver and info.php_version_tuple < patch_ver:
            info.vulnerable = True
            pv = ".".join(str(x) for x in patch_ver)
            info.vulns.append(f"PHP {info.php_version} < {pv} — CVE-2026-109618/619 affected")
        elif patch_ver and info.php_version_tuple >= patch_ver:
            info.notes.append(f"PHP {info.php_version} — patched")
        else:
            info.notes.append(f"PHP {info.php_version} — unknown patch status")

    if "ACTIVE" in info.upload_progress:
        info.vulns.append("session.upload_progress.enabled = On (attack vector active)")
    elif info.upload_progress == "inactive or hidden":
        info.notes.append("upload_progress appears disabled or not triggerable")

    if "mod_php" in info.sapi:
        info.vulns.append(f"SAPI: {info.sapi} — direct exploit path (no FPM boundary)")
    elif "fpm" in info.sapi.lower():
        info.notes.append(f"SAPI: {info.sapi} — FPM makes exploitation harder but not impossible")

    if "prefork" in info.mpm.lower():
        info.vulns.append(f"MPM: {info.mpm} — single-process model, heap state predictable")

    if not info.vulnerable and not info.php_version_tuple:
        info.notes.append("Cannot confirm version — manual check recommended")

    return info


BANNER = r"""
  php2shell recon — CVE-2026-109618/619
  Created by: Joas A Santos (@c0d3cr4zy)
"""


def main() -> int:
    print(BANNER)
    if len(sys.argv) < 2:
        print("usage: python3 recon.py <url> [<url> ...]")
        print("  e.g. python3 recon.py http://target:8088/index.php")
        return 1

    for url in sys.argv[1:]:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        tls = parsed.scheme == "https"
        port = parsed.port or (443 if tls else 80)
        path = parsed.path or "/"

        print(f"\n{'='*60}")
        info = fingerprint(host, port, path, tls)
        print(info.summary())

        if info.vulnerable:
            score = 0
            if info.php_version_tuple:
                score += 3
            if "ACTIVE" in info.upload_progress:
                score += 3
            if "mod_php" in info.sapi:
                score += 2
            if "prefork" in info.mpm.lower():
                score += 2
            print(f"\n  Risk Score : {score}/10")
            if score >= 8:
                print("  Assessment : CRITICAL — all conditions met for CVE-2026-109618/619")
            elif score >= 5:
                print("  Assessment : HIGH — likely exploitable, some conditions unconfirmed")
            else:
                print("  Assessment : MEDIUM — version vulnerable but attack surface unclear")
        print(f"{'='*60}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
