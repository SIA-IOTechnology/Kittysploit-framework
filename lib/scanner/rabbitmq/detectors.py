#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RabbitMQ AMQP protocol detection helpers."""

from __future__ import annotations

import socket
from typing import Dict


AMQP_HEADER = b"AMQP\x00\x00\x09\x01"


def probe_rabbitmq_amqp(host: str, port: int = 5672, timeout: float = 5.0) -> Dict[str, object]:
    result: Dict[str, object] = {"detected": False, "banner": "", "error": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(AMQP_HEADER)
        data = sock.recv(128)
        if not data:
            result["error"] = "empty_response"
            return result
        if data.startswith(b"AMQP") or b"RabbitMQ" in data:
            result["detected"] = True
            result["banner"] = data.decode("utf-8", errors="replace")[:120]
            return result
        result["error"] = "unexpected_amqp_response"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        sock.close()
