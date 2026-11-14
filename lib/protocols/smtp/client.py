#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal blocking SMTP client for exploit delivery."""

from __future__ import annotations

import re
import socket
from typing import Optional, Tuple

from core.framework.base_module import BaseModule


class SmtpError(RuntimeError):
    pass


class SmtpClient:
    def __init__(self, host: str, port: int = 25, timeout: float = 20):
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self.banner = b""

    def connect(self) -> bytes:
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.settimeout(self.timeout)
        self.banner = self._read_reply()
        return self.banner

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.sendall(b"QUIT\r\n")
                self._read_reply()
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _read_reply(self) -> bytes:
        if not self._sock:
            raise SmtpError("not connected")
        buf = b""
        while True:
            chunk = self._sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            lines = buf.split(b"\r\n")
            if lines and lines[-1] == b"":
                complete = [ln for ln in lines if ln]
                if complete and len(complete[-1]) >= 4 and complete[-1][3:4] != b"-":
                    break
        return buf

    def send_cmd(self, line: str) -> bytes:
        if not self._sock:
            raise SmtpError("not connected")
        self._sock.sendall(line.encode() if line.endswith("\r\n") else (line + "\r\n").encode())
        return self._read_reply()

    def ehlo(self, helo: str = "kitty.test") -> bytes:
        return self.send_cmd(f"EHLO {helo}")

    def mail_from(self, addr: str) -> bytes:
        return self.send_cmd(f"MAIL FROM:<{addr}>")

    def rcpt_to(self, addr: str) -> bytes:
        return self.send_cmd(f"RCPT TO:<{addr}>")

    def data(self, mime_bytes: bytes) -> bytes:
        r1 = self.send_cmd("DATA")
        if not r1.startswith(b"354"):
            raise SmtpError(f"DATA rejected: {r1!r}")
        payload = mime_bytes.replace(b"\n.", b"\n..") if mime_bytes.startswith(b".") else mime_bytes
        self._sock.sendall(payload + b"\r\n.\r\n")
        return self._read_reply()

    @staticmethod
    def accepted(reply: bytes) -> bool:
        return bool(reply) and reply[:3] == b"250"


def cisco_asyncos_smtp_check(host: str, port: int = 25) -> Tuple[bool, str]:
    """Return (is_asyncos_seg, message) using EUQ_FULL probe."""
    client = SmtpClient(host, port)
    try:
        client.connect()
        client.ehlo()
        reply = client.send_cmd("EUQ_FULL")
        text = reply.decode(errors="replace")
        if re.search(r"\A(?:250 EUQ not full|491 #4\.9\.1 EUQ database full)", text):
            return True, "Cisco AsyncOS SMTP (likely Secure Email Gateway)"
        if client.banner:
            return False, f"SMTP up but EUQ_FULL mismatch: {text.strip()[:120]}"
        return False, "No SMTP banner"
    except OSError as exc:
        return False, str(exc)
    finally:
        client.close()


class CiscoAsyncOsSmtp(BaseModule):
    """Cisco AsyncOS SMTP helpers for ESA exploit modules."""

    def smtp_rhost(self) -> str:
        raw = str(
            getattr(self, "rhost", None) or getattr(self, "target", "") or ""
        )
        return raw.split("://")[-1].split("/")[0].split(":")[0]

    def smtp_port(self) -> int:
        port = getattr(self, "port", 25)
        if hasattr(port, "value"):
            port = port.value
        return int(port or 25)

    def cisco_asyncos_probe(self) -> Tuple[bool, str]:
        return cisco_asyncos_smtp_check(self.smtp_rhost(), self.smtp_port())

    def smtp_client(self, timeout: float = 20) -> SmtpClient:
        return SmtpClient(self.smtp_rhost(), self.smtp_port(), timeout=timeout)

    def cisco_discover_rcpt(self, client: SmtpClient, nonce: str, forced: str = "") -> str:
        forced = (forced or "").strip()
        if forced:
            return forced
        banner = client.banner.decode(errors="replace")
        host = re.search(r"\A220\s+([^\s]+)", banner)
        labels = host.group(1).split(".") if host else [self.smtp_rhost()]
        for idx in range(len(labels)):
            domain = ".".join(labels[idx:])
            if domain.count(".") < 1:
                continue
            address = f"{nonce}@{domain}"
            client.ehlo(nonce)
            sender = f"{nonce}@{domain}"
            if not client.send_cmd(f"MAIL FROM:<{sender}>").startswith(b"250"):
                continue
            rep = client.send_cmd(f"RCPT TO:<{address}>")
            client.send_cmd("RSET")
            if rep.startswith(b"250"):
                return address
        raise SmtpError("Could not discover RCPT — set rcpt_to")