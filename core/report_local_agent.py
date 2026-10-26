#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Local KittyReports Desktop agent discovery (loopback sync).

The desktop app writes ~/.kittysploit/local-report-agent.json when CLI sync
is enabled. The framework reads it to push findings without cloud E2EE.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

LOCAL_REPORT_AGENT_FILENAME = "local-report-agent.json"
LOCAL_AGENT_CLIENT_HEADER = "framework-cli"
LOCAL_TRANSPORT = "local"
CLOUD_TRANSPORT = "cloud"


class ReportLocalAgentError(Exception):
    """Local agent unavailable or misconfigured."""


def kittysploit_config_dir() -> Path:
    return Path(os.path.expanduser("~")) / ".kittysploit"


def local_report_agent_discovery_path() -> Path:
    return kittysploit_config_dir() / LOCAL_REPORT_AGENT_FILENAME


def normalize_base_url(url: str) -> str:
    return (url or "").strip().rstrip("/")


def _pid_alive(pid: Any) -> bool:
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return True
    if pid_int <= 0:
        return True
    try:
        os.kill(pid_int, 0)
    except OSError:
        return False
    return True


def load_local_report_agent_discovery() -> Optional[Dict[str, Any]]:
    path = local_report_agent_discovery_path()
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def resolve_local_report_agent(
    base_url_override: Optional[str] = None,
    *,
    require_alive_pid: bool = True,
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Return (base_url, bearer_token, discovery_record).

    Raises ReportLocalAgentError with an operator-facing message on failure.
    """
    discovery = load_local_report_agent_discovery()
    if discovery is None and not base_url_override:
        raise ReportLocalAgentError(
            "Local Report Agent not found. Enable CLI sync in KittyReports Desktop "
            f"(expected {local_report_agent_discovery_path()})."
        )

    token = ""
    if discovery:
        token = str(discovery.get("token") or discovery.get("bearer_token") or "").strip()
        if require_alive_pid and not _pid_alive(discovery.get("pid")):
            raise ReportLocalAgentError(
                "Local Report Agent discovery file is stale (desktop process not running). "
                "Re-enable CLI sync in KittyReports Desktop."
            )

    base_url = normalize_base_url(base_url_override or "")
    if not base_url and discovery:
        base_url = normalize_base_url(
            str(discovery.get("base_url") or discovery.get("url") or "")
        )

    if not base_url:
        raise ReportLocalAgentError(
            "Local agent base URL missing. Enable CLI sync in KittyReports Desktop "
            "or pass report --local-url http://127.0.0.1:<port>."
        )

    if not token:
        raise ReportLocalAgentError(
            "Local agent token missing in discovery file. Re-enable CLI sync "
            "in KittyReports Desktop to regenerate the token."
        )

    if not base_url.startswith("http://127.0.0.1:") and not base_url.startswith("http://localhost:"):
        raise ReportLocalAgentError(
            f"Refusing non-loopback local agent URL: {base_url}. "
            "Only http://127.0.0.1:<port> or http://localhost:<port> are allowed."
        )

    return base_url, token, discovery or {}


def ping_local_report_agent(
    base_url: str,
    token: str,
    *,
    timeout: float = 10.0,
    framework_version: str = "1.0.0",
) -> Dict[str, Any]:
    """GET /api/v1/status on the local agent."""
    url = f"{normalize_base_url(base_url)}/api/v1/status"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": f"KittySploit-Framework/{framework_version}",
        "X-KittySploit-Client": LOCAL_AGENT_CLIENT_HEADER,
        "X-KittySploit-Transport": LOCAL_TRANSPORT,
    }
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
    except requests.exceptions.ConnectionError as exc:
        raise ReportLocalAgentError(
            "Cannot connect to the local Report Agent. Is CLI sync enabled in "
            "KittyReports Desktop?"
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise ReportLocalAgentError("Local Report Agent connection timed out.") from exc

    if response.status_code == 401:
        raise ReportLocalAgentError(
            "Local agent rejected the token. Re-enable CLI sync in KittyReports Desktop."
        )
    if response.status_code != 200:
        snippet = (response.text or "")[:160]
        raise ReportLocalAgentError(
            f"Local agent status check failed (HTTP {response.status_code}): {snippet}"
        )

    try:
        body = response.json()
    except ValueError as exc:
        raise ReportLocalAgentError("Local agent returned invalid JSON for /api/v1/status.") from exc
    if not isinstance(body, dict):
        raise ReportLocalAgentError("Local agent status response must be a JSON object.")
    return body
