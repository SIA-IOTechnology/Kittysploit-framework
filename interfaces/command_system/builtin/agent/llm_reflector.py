#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Reflector: retry malformed LLM JSON with a corrective pass (PentAGI Reflector pattern)."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Mapping, Optional

from interfaces.command_system.builtin.agent.redaction import sanitize_nested

DEFAULT_REFLECTOR_INSTRUCTION = (
    "You returned invalid structure for a KittySploit agent tool call. "
    "Reply with ONLY a single JSON object. No markdown fences, no prose."
)


def extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    raw = str(text or "").strip()
    if not raw:
        return None
    if raw.startswith("```"):
        lines = raw.splitlines()
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines).strip()
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", raw)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def reflect_structured_json(
    raw_response: Any,
    *,
    parse_fn: Callable[[Mapping[str, Any]], Optional[Dict[str, Any]]],
    llm_query: Optional[Callable[..., Optional[Dict[str, Any]]]] = None,
    instruction: str = DEFAULT_REFLECTOR_INSTRUCTION,
    required_keys: Optional[List[str]] = None,
    endpoint: str = "",
    model: str = "",
    timeout: int = 20,
) -> Optional[Dict[str, Any]]:
    """
    Parse LLM output; on failure optionally run a short reflector pass via ``llm_query``.
    ``llm_query`` signature: (endpoint, model, instruction, payload, timeout) -> dict|None.
    """
    if isinstance(raw_response, dict):
        parsed = parse_fn(raw_response)
        if parsed is not None:
            return parsed
        payload = raw_response
    else:
        payload = extract_json_object(str(raw_response or ""))
        if payload is not None:
            parsed = parse_fn(payload)
            if parsed is not None:
                return parsed

    if llm_query is None or not endpoint or not model:
        return None

    keys = required_keys or []
    reflect_payload = sanitize_nested({
        "invalid_output": str(raw_response)[:1500] if not isinstance(raw_response, dict) else raw_response,
        "required_keys": keys,
        "hint": "Return minified JSON only.",
    })
    fixed = llm_query(
        endpoint=endpoint,
        model=model,
        instruction=instruction,
        payload=reflect_payload,
        timeout=timeout,
    )
    if isinstance(fixed, dict):
        parsed = parse_fn(fixed)
        if parsed is not None:
            return parsed
    if isinstance(fixed, str):
        obj = extract_json_object(fixed)
        if obj is not None:
            return parse_fn(obj)
    return None
