#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Kafka broker detection via ApiVersions (TCP/9092)."""

from __future__ import annotations

import socket
import struct
from typing import Dict, List


def _kafka_string(value: bytes) -> bytes:
    return struct.pack(">h", len(value)) + value


def _build_api_versions_request(correlation_id: int = 1, client_id: bytes = b"kittysploit") -> bytes:
    # ApiVersions api_key=18, api_version=0
    header = struct.pack(">hhi", 18, 0, correlation_id) + _kafka_string(client_id)
    return struct.pack(">i", len(header)) + header


def _parse_api_versions_response(data: bytes, expect_correlation: int = 1) -> Dict[str, object]:
    result: Dict[str, object] = {
        "ok": False,
        "correlation_id": None,
        "error_code": None,
        "api_keys": [],
        "error": "",
    }
    if len(data) < 8:
        result["error"] = "short_response"
        return result
    # First int32 may be length-prefixed framing already stripped by reader
    offset = 0
    if len(data) >= 4:
        # Heuristic: if first field equals remaining-4, treat as length prefix
        length = struct.unpack_from(">i", data, 0)[0]
        if length == len(data) - 4 and length > 0:
            offset = 4
    if len(data) - offset < 4:
        result["error"] = "no_correlation"
        return result
    correlation_id = struct.unpack_from(">i", data, offset)[0]
    offset += 4
    result["correlation_id"] = correlation_id
    if correlation_id != expect_correlation:
        # Still may be Kafka with different framing; continue carefully
        pass
    if len(data) - offset < 2:
        result["error"] = "no_error_code"
        return result
    error_code = struct.unpack_from(">h", data, offset)[0]
    offset += 2
    result["error_code"] = error_code
    if len(data) - offset < 4:
        result["error"] = "no_api_array"
        return result
    count = struct.unpack_from(">i", data, offset)[0]
    offset += 4
    if count < 0 or count > 512:
        result["error"] = f"bad_api_count={count}"
        return result
    apis: List[Dict[str, int]] = []
    for _ in range(count):
        if len(data) - offset < 6:
            break
        api_key, min_v, max_v = struct.unpack_from(">hhh", data, offset)
        offset += 6
        apis.append({"api_key": api_key, "min": min_v, "max": max_v})
    if not apis and error_code not in (0, 35):  # 35 = UNSUPPORTED_VERSION sometimes still Kafka
        result["error"] = "empty_api_list"
        return result
    result["api_keys"] = apis
    result["ok"] = True
    return result


def probe_kafka_broker(host: str, port: int = 9092, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "api_count": 0,
        "error_code": None,
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        req = _build_api_versions_request()
        sock.sendall(req)
        chunks = b""
        while len(chunks) < 4:
            part = sock.recv(4096)
            if not part:
                break
            chunks += part
        if len(chunks) < 4:
            result["error"] = "no_data"
            return result
        msg_len = struct.unpack(">i", chunks[:4])[0]
        if msg_len < 0 or msg_len > 1_000_000:
            result["error"] = f"bad_length={msg_len}"
            return result
        while len(chunks) < 4 + msg_len:
            part = sock.recv(4096)
            if not part:
                break
            chunks += part
        payload = chunks[: 4 + msg_len]
        parsed = _parse_api_versions_response(payload, expect_correlation=1)
        if not parsed.get("ok"):
            result["error"] = str(parsed.get("error") or "parse_failed")
            return result
        result["detected"] = True
        result["api_count"] = len(parsed.get("api_keys") or [])
        result["error_code"] = parsed.get("error_code")
        return result
    except socket.timeout:
        result["error"] = "timeout"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass
