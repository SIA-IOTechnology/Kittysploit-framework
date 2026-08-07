#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic Gradio HTTP API mixin and helpers (no gradio-client dependency)."""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Iterable, List, Optional, Sequence

from core.framework.base_module import BaseModule
from core.framework.option import OptString

HttpRequestFn = Callable[..., Any]


def gradio_join_path(base_path: str, suffix: str) -> str:
    base = (base_path or "/").strip() or "/"
    if not base.startswith("/"):
        base = f"/{base}"
    base = base.rstrip("/")
    suffix = suffix if suffix.startswith("/") else f"/{suffix}"
    return suffix if base in ("", "/") else f"{base}{suffix}"


def _extract_output(raw: Any) -> Any:
    if raw is None:
        return None
    if isinstance(raw, list):
        return raw[0] if len(raw) == 1 else raw
    if isinstance(raw, dict):
        if "data" in raw:
            return _extract_output(raw["data"])
        if "output" in raw:
            return _extract_output(raw["output"])
    return raw


def _parse_sse(text: str) -> Any:
    for block in (text or "").split("\n\n"):
        data_line = None
        for line in block.splitlines():
            if line.startswith("data:"):
                data_line = line[5:].strip()
        if not data_line or data_line == "null":
            continue
        try:
            parsed = json.loads(data_line)
        except json.JSONDecodeError:
            return data_line
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            msg = parsed.get("msg")
            if msg in ("process_completed", "process_generating"):
                output = parsed.get("output")
                if isinstance(output, dict) and "data" in output:
                    return output["data"]
                if output is not None:
                    return output
            if "data" in parsed:
                return parsed["data"]
    return None


def fetch_gradio_config(http_request: HttpRequestFn, base_path: str = "/") -> dict:
    for path in (
        gradio_join_path(base_path, "/config"),
        gradio_join_path(base_path, "/gradio_api/config"),
        "/config",
    ):
        try:
            response = http_request(method="GET", path=path, timeout=15)
        except Exception:
            continue
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        try:
            body = response.json()
        except Exception:
            continue
        if isinstance(body, dict) and body.get("dependencies") is not None:
            return body
    return {}


def list_gradio_api_names(config: dict) -> List[str]:
    names: List[str] = []
    for dep in config.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        api = str(dep.get("api_name") or "").strip()
        if api:
            names.append(api)
    return names


def find_gradio_api_name(
    config: dict,
    needles: Sequence[str],
    default: str = "",
) -> str:
    """Return the first ``api_name`` containing any needle (case-insensitive)."""
    patterns = [str(n).lower() for n in needles if str(n).strip()]
    for api in list_gradio_api_names(config):
        lower = api.lower()
        if any(p in lower for p in patterns):
            return api
    return default


def gradio_call(
    http_request: HttpRequestFn,
    base_path: str,
    api_name: str,
    data: List[Any],
    timeout: float = 90.0,
) -> Any:
    """Invoke a named Gradio handler (POST + poll, no gradio-client)."""
    api = str(api_name or "").lstrip("/")
    call_paths = [
        gradio_join_path(base_path, f"/gradio_api/call/{api}"),
        gradio_join_path(base_path, f"/call/{api}"),
        f"/gradio_api/call/{api}",
        f"/call/{api}",
    ]
    last_error = "Gradio call failed"
    for call_path in call_paths:
        try:
            response = http_request(
                method="POST",
                path=call_path,
                json={"data": data},
                timeout=max(int(timeout), 15),
            )
        except Exception as exc:
            last_error = str(exc)
            continue
        if not response:
            last_error = f"no response from POST {call_path}"
            continue
        status = int(getattr(response, "status_code", 0) or 0)
        if status == 404:
            continue
        if status >= 400:
            last_error = f"HTTP {status} on POST {call_path}"
            continue
        try:
            body = response.json() if (response.text or "").strip() else {}
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        event_id = body.get("event_id")
        if not event_id:
            extracted = _extract_output(body.get("data", body))
            if extracted is not None:
                return extracted
            last_error = f"unexpected sync body from {call_path}"
            continue

        poll_path = f"{call_path}/{event_id}"
        deadline = time.time() + float(timeout)
        while time.time() < deadline:
            try:
                poll = http_request(method="GET", path=poll_path, timeout=30, stream=True)
            except Exception as exc:
                last_error = str(exc)
                time.sleep(0.35)
                continue
            if not poll:
                time.sleep(0.35)
                continue
            ctype = str(getattr(poll, "headers", {}).get("content-type", "")).lower()
            text = getattr(poll, "text", "") or ""
            if "text/event-stream" in ctype or "event:" in text:
                extracted = _parse_sse(text)
                if extracted is not None:
                    return _extract_output(extracted)
            else:
                try:
                    payload = poll.json()
                except Exception:
                    payload = None
                if isinstance(payload, dict):
                    if payload.get("event") == "complete" or "data" in payload:
                        extracted = _extract_output(payload.get("data", payload))
                        if extracted is not None:
                            return extracted
                elif isinstance(payload, list):
                    return _extract_output(payload)
            time.sleep(0.35)
        last_error = f"poll timeout on {poll_path}"
    raise RuntimeError(last_error)


class GradioClient:
    """Standalone Gradio HTTP client (use directly or via :class:`Gradio` mixin)."""

    def __init__(
        self,
        http_request: HttpRequestFn,
        base_path: str = "/",
        timeout: float = 90.0,
    ):
        self.http_request = http_request
        self.base_path = base_path or "/"
        self.timeout = float(timeout or 90.0)
        self._config: dict = {}

    def refresh_config(self) -> dict:
        self._config = fetch_gradio_config(self.http_request, self.base_path)
        return self._config

    @property
    def config(self) -> dict:
        if not self._config:
            self.refresh_config()
        return self._config

    def api_names(self) -> List[str]:
        return list_gradio_api_names(self.config)

    def find_api(self, *needles: str, default: str = "") -> str:
        return find_gradio_api_name(self.config, needles, default=default)

    def predict(self, api_name: str, data: Iterable[Any]) -> Any:
        return gradio_call(
            self.http_request,
            self.base_path,
            api_name,
            list(data),
            timeout=self.timeout,
        )

    def looks_like_gradio(self, extra_markers: Iterable[str] = ()) -> bool:
        markers = ("gradio-app", "__gradio_mode__", *extra_markers)
        for path in (gradio_join_path(self.base_path, "/"), gradio_join_path(self.base_path, "/config")):
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    timeout=10,
                    allow_redirects=True,
                )
            except Exception:
                continue
            if not response or int(getattr(response, "status_code", 0) or 0) != 200:
                continue
            text = (getattr(response, "text", "") or "").lower()
            if any(m.lower() in text for m in markers):
                return True
        return bool(self.config.get("dependencies"))


class Gradio(BaseModule):
    """
    Gradio HTTP API mixin — combine with :class:`Http_client`.

    Example::

        class Module(Exploit, Http_client, Gradio):
            ...
            def run(self):
                self.gradio_predict("/my_handler", ["arg1"])
    """

    gradio_base_path = OptString(
        "",
        "Gradio mount path (falls back to BASE_PATH or PATH when empty)",
        False,
        advanced=True,
    )

    def _gradio_opt(self, option, default=""):
        if hasattr(option, "value"):
            return option.value if option.value is not None else default
        return option if option is not None else default

    def _gradio_bool(self, option, default=False) -> bool:
        value = self._gradio_opt(option, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("true", "yes", "y", "1", "on")
        return bool(value)

    def gradio_mount_path(self) -> str:
        for candidate in (
            self._gradio_opt(getattr(self, "gradio_base_path", ""), ""),
            self._gradio_opt(getattr(self, "base_path", ""), ""),
            self._gradio_opt(getattr(self, "path", ""), "/"),
        ):
            base = str(candidate or "").strip() or "/"
            if base != "/":
                return base if base.startswith("/") else f"/{base}"
        return "/"

    def gradio_timeout(self) -> float:
        try:
            return max(15.0, float(self._gradio_opt(getattr(self, "timeout", 30), 30) or 30))
        except Exception:
            return 90.0

    def gradio_client(self) -> GradioClient:
        if not hasattr(self, "http_request"):
            raise AttributeError("Gradio mixin requires Http_client (http_request missing)")
        return GradioClient(
            self.http_request,
            self.gradio_mount_path(),
            timeout=self.gradio_timeout(),
        )

    def gradio_refresh_config(self) -> dict:
        return self.gradio_client().refresh_config()

    def gradio_api_names(self) -> List[str]:
        return self.gradio_client().api_names()

    def gradio_find_api(self, *needles: str, default: str = "") -> str:
        return self.gradio_client().find_api(*needles, default=default)

    def gradio_predict(self, api_name: str, data: Iterable[Any]) -> Any:
        return self.gradio_client().predict(api_name, data)

    def gradio_looks_like(self, extra_markers: Iterable[str] = ()) -> bool:
        return self.gradio_client().looks_like_gradio(extra_markers)
