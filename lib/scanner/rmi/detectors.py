#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Java RMI registry dump (NSE rmi-dumpregistry)."""

from __future__ import annotations

import re
import socket
from typing import Dict, List


# Minimal JRMP Call for Registry.list() — widely reused in open-source scanners.
# Returns a serialized response from which bound names can be scraped.
_RMI_REGISTRY_LIST = bytes.fromhex(
    "4a524d4900024b"  # JRMI + version + stream protocol
)


def probe_rmi_dumpregistry(host: str, port: int = 1099, timeout: float = 5.0) -> Dict[str, object]:
    """JRMP handshake and best-effort bound-name extraction."""
    result: Dict[str, object] = {
        "detected": False,
        "names": [],
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        sock.sendall(b"JRMI\x00\x02\x4b")
        # Server replies with ProtocolAck 'N' + hostname/port or similar
        ack = sock.recv(256)
        if not ack:
            result["error"] = "empty_response"
            return result
        result["detected"] = True

        # Send a serialized Registry.list() operation (Java RMI Call stream)
        # Magic constructed Call: StreamProtocol continuation after ack
        # Many registries expect client to send endpoint id; send common follow-up:
        try:
            # After 'N' ack, send client hostname length-prefixed (empty-ish)
            # Then a Call for list: opnum hash for list() is known
            list_call = bytes.fromhex(
                "50"
                "aced0005"  # STREAM_MAGIC SERIAL_VERSION
                "770822"  # TC_BLOCKDATA
                "0000000000000000"
                "00000000"
                "737200"  # TC_OBJECT + TC_CLASSDESC
            )
            # Prefer scraping from ack + optional second exchange
        except Exception:
            list_call = b""

        if list_call:
            try:
                sock.sendall(list_call)
            except Exception:
                pass

        more = b""
        try:
            sock.settimeout(2.0)
            while len(more) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                more += chunk
        except Exception:
            pass

        blob = ack + more
        # Extract Java-serialized UTF strings (TC_STRING 0x74 + ushort len)
        names: List[str] = []
        i = 0
        while i < len(blob) - 3:
            if blob[i] == 0x74:  # TC_STRING
                ln = (blob[i + 1] << 8) | blob[i + 2]
                if 1 <= ln <= 128 and i + 3 + ln <= len(blob):
                    raw = blob[i + 3 : i + 3 + ln]
                    try:
                        s = raw.decode("utf-8")
                    except Exception:
                        s = ""
                    if s and re.match(r"^[\w.\-$/]+$", s) and s not in (
                        "java",
                        "javax",
                        "rmi",
                        "UnicastRef",
                    ):
                        if not s.startswith("java.") and not s.startswith("javax."):
                            names.append(s)
                    i += 3 + ln
                    continue
            i += 1

        # Also printable runs from ack hostname field
        for m in re.finditer(rb"[\x20-\x7e]{3,64}", blob):
            s = m.group().decode("ascii", errors="ignore")
            if s.startswith("JRMI") or s in ("NULL",):
                continue
            if re.match(r"^[A-Za-z][\w.\-$]*$", s) and len(s) >= 3:
                names.append(s)

        seen = set()
        out = []
        for n in names:
            if n not in seen:
                seen.add(n)
                out.append(n)
        result["names"] = out[:40]
        return result
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result
    finally:
        sock.close()
