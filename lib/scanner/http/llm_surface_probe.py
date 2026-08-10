#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed LLM chat/completion endpoints suitable for prompt injection testing."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

_LLM_PATHS: tuple = (
    ("/v1/chat/completions", "openai_compatible"),
    ("/v1/completions", "openai_completions"),
    ("/api/chat", "generic_chat"),
    ("/api/v1/chat", "generic_chat_v1"),
    ("/ollama/api/chat", "ollama"),
    ("/ollama/api/generate", "ollama_generate"),
    ("/api/generate", "ollama_style"),
    ("/v1/messages", "anthropic_style"),
    ("/api/predict", "predict_endpoint"),
    ("/api/inference", "inference_endpoint"),
    ("/chat/completions", "chat_completions_alt"),
)

_PROBE_MESSAGE = {
    "model": "probe",
    "messages": [{"role": "user", "content": "kittysploit-probe"}],
    "max_tokens": 8,
    "stream": False,
}

_AUTH_MARKERS = (
    "invalid_api_key",
    "incorrect api key",
    "authentication",
    "unauthorized",
    "api key",
    "bearer",
    "ollama",
    "openai",
    "anthropic",
)


def _is_llm_json(data: Any, flavor: str) -> bool:
    if not isinstance(data, dict):
        return False
    # OpenAI-compatible success/error shapes
    if isinstance(data.get("choices"), list):
        return True
    err = data.get("error")
    if isinstance(err, dict) and any(
        k in err for k in ("message", "type", "code", "param")
    ):
        return True
    if isinstance(err, str) and err.strip():
        return True
    # Ollama
    if flavor.startswith("ollama") or flavor in ("ollama_style", "generic_chat", "generic_chat_v1"):
        if isinstance(data.get("response"), str):
            return True
        msg = data.get("message")
        if isinstance(msg, dict) and ("content" in msg or "role" in msg):
            return True
    # Anthropic-ish
    if flavor == "anthropic_style" and (
        data.get("type") in ("message", "error") or isinstance(data.get("content"), list)
    ):
        return True
    # Generic predict/inference: require model/output-ish keys, not HTML catch-alls
    if flavor in ("predict_endpoint", "inference_endpoint"):
        return any(k in data for k in ("prediction", "output", "outputs", "generated_text", "model"))
    # Object mentions object=chat.completion / list
    obj = str(data.get("object") or "")
    if "completion" in obj or obj == "list":
        return True
    return False


def probe_llm_endpoint(
    http_request: Callable[..., Any],
    path: str,
    flavor: str,
) -> Optional[Dict[str, Any]]:
    payload = dict(_PROBE_MESSAGE)
    if flavor.startswith("ollama") or flavor == "ollama_style":
        payload = {"model": "probe", "prompt": "kittysploit-probe", "stream": False}
    response = http_request(
        method="POST",
        path=path,
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        allow_redirects=False,
        timeout=15,
    )
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    if status not in (200, 201, 401, 403, 422):
        return None

    ctype = ""
    headers = getattr(response, "headers", None) or {}
    try:
        ctype = str(headers.get("Content-Type") or headers.get("content-type") or "").lower()
    except Exception:
        ctype = ""

    lowered = body.lower()
    indicators: List[str] = []

    data = None
    try:
        data = json.loads(body)
    except Exception:
        data = None

    if data is not None and _is_llm_json(data, flavor):
        indicators.append("llm_json_shape")
        if status in (200, 201):
            indicators.append("unauthenticated_completion")
        elif status in (401, 403, 422):
            indicators.append("auth_or_validation_error")
    elif status in (401, 403) and (
        "json" in ctype or any(m in lowered for m in _AUTH_MARKERS)
    ):
        # Reachable LLM-ish auth wall (not a random HTML 401 soft page alone).
        indicators.append("auth_required_but_reachable")
    else:
        # Reject HTML catch-all / router soft-404 pages that merely contain
        # words like "content", "message", or "response".
        return None

    return {
        "path": path,
        "flavor": flavor,
        "kind": "llm_chat_surface",
        "status_code": status,
        "indicators": indicators,
        "severity": "critical" if "unauthenticated_completion" in indicators else "medium",
        "preview": body[:400],
    }


def scan_llm_surfaces(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path, flavor in _LLM_PATHS:
        hit = probe_llm_endpoint(http_request, path, flavor)
        if hit:
            findings.append(hit)
    return findings


__all__ = ["scan_llm_surfaces", "probe_llm_endpoint"]
