#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ClickHouse HTTP query probe helpers."""

from __future__ import annotations

import re
import socket
import urllib.parse
from typing import Dict, List


def probe_clickhouse_query(
    host: str,
    port: int = 8123,
    query: str = "SELECT 1",
    timeout: float = 5.0,
) -> Dict[str, object]:
    result: Dict[str, object] = {"detected": False, "rows": [], "error": ""}
    path = "/?" + urllib.parse.urlencode({"query": query})
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(request)
        chunks: List[bytes] = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            if len(b"".join(chunks)) > 65536:
                break
        raw = b"".join(chunks)
        if b"\r\n\r\n" not in raw:
            result["error"] = "short_response"
            return result
        header_blob, body = raw.split(b"\r\n\r\n", 1)
        headers = header_blob.decode("utf-8", errors="replace")
        text = body.decode("utf-8", errors="replace").strip()
        status_line = headers.split("\r\n", 1)[0]
        lower = text.lower()

        # Reject generic web server pages (common FP when RPORT is 80/443).
        if (
            lower.startswith("<!doctype")
            or lower.startswith("<html")
            or "<html" in lower[:200]
            or "plain http request was sent to https" in lower
            or "moved permanently" in lower
            or "bad request" in lower
        ):
            result["error"] = "http_html_response"
            return result

        clickhouse_headers = (
            "x-clickhouse-summary" in headers.lower()
            or "x-clickhouse-query-id" in headers.lower()
            or "x-clickhouse-format" in headers.lower()
            or "text/tab-separated-values" in headers.lower()
        )
        # SELECT 1 -> "1"; SELECT version() -> "23.8.1.1" style; ping -> "Ok."
        select_one = text == "1" or text.startswith("1\n")
        version_like = bool(re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", text.split("\n", 1)[0].strip()))
        ping_ok = text == "Ok." or text.startswith("Ok.\n")
        ch_exception = "Code:" in text and "DB::" in text

        if clickhouse_headers or select_one or version_like or ping_ok or ch_exception:
            if "200" not in status_line and not ch_exception and not clickhouse_headers:
                result["error"] = f"unexpected_status:{status_line!r}"
                return result
            result["detected"] = True
            result["rows"] = [line for line in text.splitlines() if line.strip()][:20]
            return result
        result["error"] = "unexpected_body"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
