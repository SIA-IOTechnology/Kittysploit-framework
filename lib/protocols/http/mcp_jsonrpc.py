#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic MCP JSON-RPC over HTTP mixin (POST message / streamable HTTP endpoints)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from core.framework.base_module import BaseModule
from core.framework.option import OptString


class Mcp_jsonrpc(BaseModule):
    """
    MCP JSON-RPC mixin — combine with :class:`Http_client`.

    Example::

        class Module(Scanner, Http_client, Mcp_jsonrpc):
            def run(self):
                tools = self.mcp_tools_list()
    """

    mcp_jsonrpc_path = OptString(
        "/mcp",
        "MCP JSON-RPC HTTP path",
        required=False,
        advanced=True,
    )

    @staticmethod
    def mcp_join_path(base_path: str, suffix: str) -> str:
        base = (base_path or "/").rstrip("/")
        suffix = (suffix or "/mcp").strip() or "/mcp"
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return suffix if base in ("", "/") else f"{base}{suffix}"

    def _mcp_option_value(self, option, default: str = "") -> str:
        if option is None:
            return default
        if hasattr(option, "value"):
            val = option.value
            return str(val if val is not None else default)
        return str(option if option is not None else default)

    def mcp_timeout(self) -> int:
        raw = getattr(self, "timeout", 10)
        if hasattr(raw, "value"):
            raw = raw.value
        try:
            return max(int(raw or 10), 1)
        except (TypeError, ValueError):
            return 10

    def mcp_default_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }

    def mcp_jsonrpc_endpoint(self) -> str:
        suffix = self._mcp_option_value(getattr(self, "mcp_jsonrpc_path", None), "/mcp")
        base = self._mcp_option_value(getattr(self, "path", None), "/")
        return self.mcp_join_path(base, suffix)

    @classmethod
    def mcp_parse_response(cls, response) -> Optional[Dict[str, Any]]:
        if not response:
            return None
        text = (getattr(response, "text", None) or "").strip()
        if text.startswith("data:"):
            text = "".join(
                line[5:].strip() for line in text.splitlines() if line.startswith("data:")
            )
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def mcp_rpc(
        self,
        method: str,
        params: Optional[dict] = None,
        *,
        path: Optional[str] = None,
        rid: int = 1,
        headers: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
        if not hasattr(self, "http_request"):
            raise AttributeError("Mcp_jsonrpc mixin requires Http_client (http_request missing)")
        hdrs = self.mcp_default_headers()
        if headers:
            hdrs.update(headers)
        response = self.http_request(
            method="POST",
            path=path or self.mcp_jsonrpc_endpoint(),
            json={
                "jsonrpc": "2.0",
                "id": rid,
                "method": method,
                "params": params if params is not None else {},
            },
            headers=hdrs,
            allow_redirects=False,
            timeout=timeout or self.mcp_timeout(),
        )
        return response, self.mcp_parse_response(response)

    def mcp_get_json(
        self,
        path: str,
        *,
        timeout: Optional[int] = None,
        headers: Optional[dict] = None,
    ) -> Optional[Dict[str, Any]]:
        if not hasattr(self, "http_request"):
            raise AttributeError("Mcp_jsonrpc mixin requires Http_client (http_request missing)")
        hdrs = headers or {}
        response = self.http_request(
            method="GET",
            path=path,
            headers=hdrs,
            allow_redirects=False,
            timeout=timeout or self.mcp_timeout(),
        )
        return self.mcp_parse_response(response)

    def mcp_tools_list(
        self,
        *,
        path: Optional[str] = None,
        rid: int = 1,
        timeout: Optional[int] = None,
    ) -> List[str]:
        _resp, parsed = self.mcp_rpc("tools/list", path=path, rid=rid, timeout=timeout)
        return self.mcp_tool_names(parsed)

    def mcp_call_tool(
        self,
        name: str,
        arguments: Optional[dict] = None,
        *,
        path: Optional[str] = None,
        rid: int = 1,
        timeout: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        _resp, parsed = self.mcp_rpc(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
            path=path,
            rid=rid,
            timeout=timeout,
        )
        return parsed

    @staticmethod
    def mcp_tool_names(parsed: Optional[Dict[str, Any]]) -> List[str]:
        if not isinstance(parsed, dict):
            return []
        raw = (parsed.get("result") or {}).get("tools") or []
        return [str(t.get("name") or "") for t in raw if isinstance(t, dict)]

    @staticmethod
    def mcp_result_text(parsed: Optional[Dict[str, Any]]) -> str:
        if not isinstance(parsed, dict):
            return ""
        result = parsed.get("result") or {}
        content = result.get("content") if isinstance(result, dict) else None
        if not isinstance(content, list):
            return ""
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                return block["text"].strip()
        return ""

    @classmethod
    def mcp_nested_command_output(cls, parsed: Optional[Dict[str, Any]]) -> str:
        """
        Walk MCP ``content[].text`` JSON chains until a dict exposes ``output``.

        Some bridges double-encode tool results as JSON strings inside text blocks.
        """
        if not isinstance(parsed, dict):
            return ""
        try:
            result = parsed.get("result") or {}
            content = result.get("content") if isinstance(result, dict) else None
            if not isinstance(content, list) or not content:
                return ""
            outer_text = content[0].get("text")
            if not isinstance(outer_text, str):
                return ""
            middle = json.loads(outer_text)
            inner_block = (middle.get("content") or [{}])[0]
            inner_text = inner_block.get("text")
            if not isinstance(inner_text, str):
                return ""
            inner = json.loads(inner_text)
            return str(inner.get("output") or "").strip()
        except Exception:
            return cls.mcp_result_text(parsed)


__all__ = ["Mcp_jsonrpc"]
