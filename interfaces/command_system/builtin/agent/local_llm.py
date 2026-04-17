#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HTTP client for local Ollama-compatible chat/generate endpoints."""

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


class LocalLLMService:
    """Query a local LLM for JSON-shaped planning responses."""

    def __init__(self) -> None:
        self.last_error: Optional[str] = None

    def query_json(
        self,
        endpoint: str,
        model: str,
        instruction: str,
        payload: Dict[str, Any],
        timeout: int = 20,
    ) -> Optional[Dict[str, Any]]:
        self.last_error = None
        fallback_endpoint = endpoint
        if endpoint.endswith("/api/chat"):
            fallback_endpoint = endpoint.replace("/api/chat", "/api/generate")
        elif endpoint.endswith("/api/generate"):
            fallback_endpoint = endpoint.replace("/api/generate", "/api/chat")
        endpoints = [endpoint] if fallback_endpoint == endpoint else [endpoint, fallback_endpoint]

        for current_endpoint in endpoints:
            try:
                is_generate = current_endpoint.endswith("/api/generate")
                if is_generate:
                    body = {
                        "model": model,
                        "prompt": f"{instruction}\n\n{json.dumps(payload)}",
                        "format": "json",
                        "stream": False,
                    }
                else:
                    body = {
                        "model": model,
                        "messages": [
                            {"role": "system", "content": instruction},
                            {"role": "user", "content": json.dumps(payload)},
                        ],
                        "format": "json",
                        "stream": False,
                    }

                request = urllib.request.Request(
                    current_endpoint,
                    data=json.dumps(body).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    raw = response.read().decode("utf-8", errors="replace")
                parsed = json.loads(raw)

                content = (
                    str(parsed.get("message", {}).get("content", "")).strip()
                    or str(parsed.get("response", "")).strip()
                )
                if not content:
                    self.last_error = f"Empty content in Ollama response from {current_endpoint}."
                    continue

                if content.startswith("```"):
                    lines = content.splitlines()
                    if lines and lines[0].strip().startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].strip().startswith("```"):
                        lines = lines[:-1]
                    content = "\n".join(lines).strip()

                try:
                    parsed_content = json.loads(content)
                except json.JSONDecodeError:
                    json_start = content.find("{")
                    json_end = content.rfind("}")
                    if json_start == -1 or json_end == -1 or json_end <= json_start:
                        self.last_error = (
                            f"Model response did not contain JSON object (endpoint={current_endpoint})."
                        )
                        continue
                    maybe_json = content[json_start : json_end + 1]
                    try:
                        parsed_content = json.loads(maybe_json)
                    except json.JSONDecodeError as parse_exc:
                        self.last_error = (
                            f"Could not parse model JSON payload (endpoint={current_endpoint}): {parse_exc}"
                        )
                        continue

                if isinstance(parsed_content, dict):
                    selected_paths = parsed_content.get("selected_paths", [])
                    rationale = parsed_content.get("rationale", "LLM plan generated.")
                    if not isinstance(selected_paths, list):
                        selected_paths = []
                    return {
                        "selected_paths": [p for p in selected_paths if isinstance(p, str)],
                        "rationale": str(rationale),
                        "next_actions": parsed_content.get("next_actions", []),
                        "max_requests_next_phase": parsed_content.get("max_requests_next_phase", 10),
                        "stop_conditions": parsed_content.get("stop_conditions", []),
                        "reasoning_confidence": parsed_content.get("reasoning_confidence", 0.7),
                    }

                self.last_error = f"Parsed JSON is not an object (endpoint={current_endpoint})."
            except urllib.error.HTTPError as exc:
                self.last_error = f"HTTP error on {current_endpoint}: {exc}"
                continue
            except urllib.error.URLError as exc:
                self.last_error = f"Connection error to {current_endpoint}: {exc}"
                continue
            except Exception as exc:
                self.last_error = f"Unexpected LLM error on {current_endpoint}: {exc}"
                continue

        return None

    def query_local_llm(
        self, endpoint: str, model: str, payload: Dict[str, Any], timeout: int = 20
    ) -> Optional[Dict[str, Any]]:
        instruction = (
            "You are a pentest planning assistant. "
            "Reply ONLY a valid JSON object. "
            "Required keys: selected_paths (array), rationale (string). "
            "Optional keys: next_actions (array of {type,path,priority,options}), "
            "max_requests_next_phase (int), stop_conditions (array), reasoning_confidence (0..1)."
            "Allowed next_actions.type values: prioritize, run_followup, run_exploit, skip. "
            "Use run_followup when manual verification is needed for potential vulnerabilities."
        )
        return self.query_json(
            endpoint=endpoint,
            model=model,
            instruction=instruction,
            payload=payload,
            timeout=timeout,
        )
