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


def probe_llm_endpoint(
    http_request: Callable[..., Any],
    path: str,
    flavor: str,
) -> Optional[Dict[str, Any]]:
    payload = dict(_PROBE_MESSAGE)
    if flavor.startswith("ollama"):
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
    indicators: List[str] = []
    lowered = body.lower()
    if status in (200, 201):
        indicators.append("unauthenticated_completion")
    if any(m in lowered for m in ("choices", "completion", "content", "response", "message")):
        indicators.append("llm_response_shape")
    if "model" in lowered and ("error" not in lowered or status == 422):
        indicators.append("model_field_reflected")
    if not indicators and status in (401, 403):
        indicators.append("auth_required_but_reachable")
    if not indicators:
        return None
    return {
        "path": path,
        "flavor": flavor,
        "kind": "llm_chat_surface",
        "status_code": status,
        "indicators": indicators,
        "severity": "critical" if status in (200, 201) else "medium",
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
