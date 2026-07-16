#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Captured HTTP request intelligence for the autonomous agent."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from collections import Counter
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import urllib3

from interfaces.command_system.builtin.agent.network_budget import consume_network_request
from interfaces.command_system.builtin.agent.runtime_policy import (
    MUTATING_HTTP_METHODS,
    active_runtime_policy,
    active_scope_guard,
)


SAFE_REPLAY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ACTIVE_REPLAY_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})

DROP_OUTGOING_HEADERS = frozenset({
    "accept-encoding",
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "sec-websocket-accept",
    "sec-websocket-key",
    "sec-websocket-version",
    "te",
    "transfer-encoding",
    "upgrade",
})

SENSITIVE_REPLAY_HEADERS = frozenset({"authorization", "cookie"})

AUTH_TOKENS = (
    "admin",
    "auth",
    "csrf",
    "login",
    "logout",
    "password",
    "session",
    "signin",
    "token",
    "wp-login.php",
)

IDOR_PARAM_TOKENS = frozenset({
    "account_id",
    "case_id",
    "customer_id",
    "doc_id",
    "document_id",
    "file_id",
    "id",
    "invoice_id",
    "item_id",
    "order_id",
    "post_id",
    "product_id",
    "ref",
    "request_id",
    "ticket_id",
    "uid",
    "user_id",
    "userid",
})

REDIRECT_PARAM_TOKENS = frozenset({
    "callback",
    "continue",
    "dest",
    "destination",
    "link",
    "next",
    "redirect",
    "return",
    "return_to",
    "target",
    "to",
    "uri",
    "url",
})

FILE_PARAM_TOKENS = frozenset({
    "file",
    "filename",
    "folder",
    "include",
    "page",
    "path",
    "template",
    "view",
})

CMD_PARAM_TOKENS = frozenset({
    "cmd",
    "command",
    "exec",
    "execute",
    "host",
    "ip",
    "ping",
    "query",
    "q",
    "run",
    "shell",
    "system",
})

# Low-noise paths for default active GET discovery (any campaign goal).
SAFE_PROBE_PATHS: Tuple[str, ...] = (
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/api",
    "/api/v1",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/login",
    "/health",
    "/docs",
    "/redoc",
    # Common training / lab apps (Metasploitable2, DVWA docker, etc.)
    "/dvwa/",
    "/dvwa/login.php",
    "/phpMyAdmin/",
    "/mutillidae/",
)

# Config leak / admin / debug paths — only with obtain-shell or --shell-hunter
# and explicit ``--approve-risk intrusive``.
SENSITIVE_SHELL_PROBE_PATHS: Tuple[str, ...] = (
    "/api/v2",
    "/swagger",
    "/admin",
    "/wp-login.php",
    "/login.php",
    "/xmlrpc.php",
    "/readme.html",
    "/wp-json/",
    "/actuator",
    "/actuator/health",
    "/.env",
    "/server-status",
    "/phpinfo.php",
)

# Backward-compatible alias (full list); prefer ``resolve_active_probe_paths``.
SHELL_PROBE_PATHS: Tuple[str, ...] = SAFE_PROBE_PATHS + SENSITIVE_SHELL_PROBE_PATHS


def _normalize_probe_path(raw: Any) -> str:
    path = str(raw or "").strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    return path.split("?", 1)[0] or "/"


def resolve_active_probe_paths(
    *,
    shell_mode: bool = False,
    intrusive_approved: bool = False,
    extra_paths: Optional[Iterable[str]] = None,
    limit: int = 14,
) -> Tuple[List[str], str]:
    """
    Build ordered GET probe paths and a tier label (``safe`` or ``shell``).

    Sensitive paths are appended only when ``shell_mode`` and ``intrusive_approved``.
    """
    ordered: List[str] = []
    seen: set = set()
    cap = max(1, int(limit or 1))

    def _add(raw: Any) -> None:
        path = _normalize_probe_path(raw)
        if not path or path in seen:
            return
        seen.add(path)
        ordered.append(path)

    for raw in extra_paths or []:
        _add(raw)
        if len(ordered) >= cap:
            return ordered[:cap], "safe"

    for raw in SAFE_PROBE_PATHS:
        _add(raw)
        if len(ordered) >= cap:
            return ordered[:cap], "safe"

    tier = "safe"
    if shell_mode and intrusive_approved:
        tier = "shell"
        for raw in SENSITIVE_SHELL_PROBE_PATHS:
            _add(raw)
            if len(ordered) >= cap:
                break

    return ordered[:cap], tier

from interfaces.command_system.builtin.agent.waf_signals import is_actionable_waf_signal


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _decode_b64(value: Any) -> bytes:
    if not value:
        return b""
    if isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", errors="replace")
    try:
        return base64.b64decode(raw)
    except Exception:
        return b""


def _decode_body_preview(value: Any, limit: int = 16000) -> str:
    return _decode_b64(value)[:limit].decode("utf-8", errors="replace")


def _normalize_headers(headers: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(headers, dict):
        return out
    for key, value in list(headers.items())[:120]:
        name = _as_text(key).strip()
        if not name:
            continue
        out[name] = _as_text(value).strip()
    return out


def _header_value(headers: Dict[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return str(value or "")
    return ""


def _parse_cookie_header(raw: Any) -> Dict[str, str]:
    text = _as_text(raw).strip()
    if not text:
        return {}
    cookies: Dict[str, str] = {}
    for chunk in text.split(";"):
        part = chunk.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            cookies[key[:80]] = value[:512]
    return cookies


def _default_port_for_scheme(scheme: str) -> int:
    return 443 if str(scheme).lower() == "https" else 80


class EvasionEngine:
    """Provides adaptive HTTP evasion strategies."""

    def __init__(self) -> None:
        self.strategies = [
            self._evade_headers,
            self._evade_url_encoding,
            self._evade_double_encoding,
            self._evade_chunked,
        ]

    def apply_random(self, method: str, url: str, headers: Dict[str, str], body: bytes) -> Tuple[str, Dict[str, str], bytes]:
        import random
        strategy = random.choice(self.strategies)
        return strategy(method, url, headers, body)

    def _evade_headers(self, method: str, url: str, headers: Dict[str, str], body: bytes) -> Tuple[str, Dict[str, str], bytes]:
        new_headers = dict(headers)
        new_headers["X-Forwarded-For"] = "127.0.0.1"
        new_headers["X-Originating-IP"] = "127.0.0.1"
        new_headers["X-Real-IP"] = "127.0.0.1"
        return url, new_headers, body

    def _evade_url_encoding(self, method: str, url: str, headers: Dict[str, str], body: bytes) -> Tuple[str, Dict[str, str], bytes]:
        # Minimal URL encoding change
        return url.replace(" ", "%20"), headers, body

    def _evade_double_encoding(self, method: str, url: str, headers: Dict[str, str], body: bytes) -> Tuple[str, Dict[str, str], bytes]:
        # Example: encode % as %25
        return url.replace("%", "%25"), headers, body

    def _evade_chunked(self, method: str, url: str, headers: Dict[str, str], body: bytes) -> Tuple[str, Dict[str, str], bytes]:
        new_headers = dict(headers)
        if method in ("POST", "PUT", "PATCH") and body:
            new_headers["Transfer-Encoding"] = "chunked"
        return url, new_headers, body


class HttpRequestIntelligence:
    """Analyze captured HTTP flows and optionally replay bounded request candidates."""

    def __init__(self, framework: Any = None) -> None:
        self.framework = framework
        self.evasion = EvasionEngine()
        self._llm: Optional[Any] = None
        self._llm_endpoint: str = ""
        self._llm_model: str = ""
        if framework and hasattr(framework, "llm_service"):
            self._llm = framework.llm_service

    def configure_llm(self, *, endpoint: str = "", model: str = "") -> None:
        """Bind agent LLM endpoint/model for adaptive HTTP probes."""
        if endpoint:
            self._llm_endpoint = str(endpoint)
        if model:
            self._llm_model = str(model)

    def _resolve_llm_endpoint(self, llm_endpoint: str = "") -> str:
        endpoint = (
            llm_endpoint
            or self._llm_endpoint
            or "http://127.0.0.1:11434/api/generate"
        )
        if endpoint.endswith("/api/chat"):
            return endpoint.replace("/api/chat", "/api/generate")
        return endpoint

    def _resolve_llm_model(self, llm_model: str = "") -> str:
        return llm_model or self._llm_model or "llama3.1:8b"

    def empty_summary(self, enabled: bool = True, error: str = "") -> Dict[str, Any]:
        return {
            "enabled": enabled,
            "source": "kittyproxy",
            "error": error,
            "matched_flows": 0,
            "analyzed_flows": 0,
            "method_counts": {},
            "status_counts": {},
            "content_types": {},
            "discovered_endpoints": [],
            "discovered_params": [],
            "login_paths": [],
            "tech_hints": [],
            "risk_signals": [],
            "interesting_requests": [],
            "candidate_requests": [],
            "auth_context": {},
            "sent_requests": [],
            "dom_xss_potential": [],
            "login_fidelity": {},
            "extracted_secrets": [],
            "calibration": {},
            "probe_results": [],
        }

    def build_target_base_url(self, target_info: Dict[str, Any]) -> str:
        scheme = str((target_info or {}).get("scheme") or "http").lower()
        host = str((target_info or {}).get("hostname") or "").strip()
        if not host:
            return ""
        try:
            port = int((target_info or {}).get("port") or _default_port_for_scheme(scheme))
        except Exception:
            port = _default_port_for_scheme(scheme)
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def merge_intel_summaries(self, base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
        """Merge proxy + active probe summaries into one KB-compatible payload."""
        if not isinstance(base, dict):
            base = self.empty_summary()
        if not isinstance(extra, dict) or not extra:
            return dict(base)

        out = dict(base)
        out["analyzed_flows"] = int(base.get("analyzed_flows", 0) or 0) + int(extra.get("analyzed_flows", 0) or 0)
        out["matched_flows"] = int(base.get("matched_flows", 0) or 0) + int(extra.get("matched_flows", 0) or 0)

        def _merge_list(key: str, limit: int) -> None:
            seen: set = set()
            merged: List[Any] = []
            for row in list(base.get(key) or []) + list(extra.get(key) or []):
                if isinstance(row, dict):
                    token = str(row.get("path") or row.get("endpoint") or row.get("url") or row)
                else:
                    token = str(row)
                if token in seen:
                    continue
                seen.add(token)
                merged.append(row)
            out[key] = merged[:limit]

        def _merge_set(key: str, limit: int) -> None:
            values = set(str(x) for x in list(base.get(key) or []) + list(extra.get(key) or []) if str(x).strip())
            out[key] = sorted(values)[:limit]

        _merge_set("discovered_endpoints", 300)
        _merge_set("discovered_params", 200)
        _merge_set("login_paths", 40)
        _merge_set("tech_hints", 40)
        _merge_set("risk_signals", 80)
        _merge_list("interesting_requests", 24)
        _merge_list("candidate_requests", 24)
        _merge_list("probe_results", 40)
        out["dom_xss_potential"] = list(base.get("dom_xss_potential") or []) + list(extra.get("dom_xss_potential") or [])
        out["extracted_secrets"] = list(base.get("extracted_secrets") or []) + list(extra.get("extracted_secrets") or [])
        out["active_probe"] = bool(base.get("active_probe") or extra.get("active_probe") or extra.get("source") == "active_probe")
        return out

    def probe_direct_surface(
        self,
        target_info: Dict[str, Any],
        *,
        extra_paths: Optional[Iterable[str]] = None,
        probe_paths: Optional[Iterable[str]] = None,
        limit: int = 14,
        user_agent: str = "",
        timeout: float = 8.0,
        on_request: Optional[Callable[[], bool]] = None,
        throttle_seconds: float = 0.0,
        on_throttle: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Send bounded GET requests to map API/admin/login surfaces without proxy traffic."""
        summary = self.empty_summary(enabled=True)
        summary["source"] = "active_probe"
        base_url = self.build_target_base_url(target_info)
        if not base_url:
            summary["error"] = "missing target hostname"
            return summary

        if probe_paths is not None:
            cap = max(1, int(limit or 1))
            ordered_paths = []
            seen: set = set()
            for raw in probe_paths:
                path = _normalize_probe_path(raw)
                if not path or path in seen:
                    continue
                seen.add(path)
                ordered_paths.append(path)
                if len(ordered_paths) >= cap:
                    break
            tier = "safe"
        else:
            ordered_paths, tier = resolve_active_probe_paths(
                extra_paths=extra_paths,
                limit=max(1, int(limit or 1)),
            )
        summary["probe_tier"] = tier

        guard = active_scope_guard()
        policy = active_runtime_policy()
        verify = policy.tls_verify_value() if policy is not None else True
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        proxies = self._build_proxy_dict()
        headers = {"User-Agent": user_agent or "KittysploitAgent/1.0 (+authorized-testing)"}

        analyzed = 0
        for idx, path in enumerate(ordered_paths):
            if idx > 0:
                if on_throttle is not None:
                    try:
                        on_throttle(path)
                    except Exception:
                        pass
                elif float(throttle_seconds or 0.0) > 0:
                    time.sleep(float(throttle_seconds))
            if on_request is not None and not on_request():
                break
            url = base_url.rstrip("/") + (path if path.startswith("/") else f"/{path}")
            if guard is not None:
                allowed, reason = guard.validate_url(url)
                if not allowed:
                    summary["probe_results"].append({
                        "status": "blocked",
                        "method": "GET",
                        "url": url,
                        "path": path,
                        "error": reason,
                    })
                    continue
            started = time.time()
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=max(1.0, float(timeout or 8.0)),
                    allow_redirects=False,
                    proxies=proxies or None,
                    verify=verify,
                )
                elapsed_ms = int((time.time() - started) * 1000)
                item = self._summarize_direct_response(
                    url=url,
                    path=path,
                    status_code=int(response.status_code or 0),
                    response_headers=_normalize_headers(dict(response.headers)),
                    response_body=response.text[:24000],
                    duration_ms=elapsed_ms,
                )
            except Exception as exc:
                summary["probe_results"].append({
                    "status": "error",
                    "method": "GET",
                    "url": url,
                    "path": path,
                    "error": str(exc),
                })
                continue

            if not item:
                continue
            analyzed += 1
            summary["probe_results"].append({
                "status": "ok",
                "method": "GET",
                "url": url,
                "path": path,
                "status_code": item.get("status_code"),
                "response_length": item.get("response_length"),
                "reasons": item.get("reasons", [])[:8],
            })
            if item.get("endpoint"):
                summary["discovered_endpoints"].append(item["endpoint"])
            summary["discovered_endpoints"].extend(item.get("discovered_endpoints", []) or [])
            summary["discovered_params"].extend(item.get("param_names", []) or [])
            summary["login_paths"].extend(item.get("login_paths", []) or [])
            summary["tech_hints"] = sorted(set(summary["tech_hints"]) | set(item.get("tech_hints", []) or []))
            summary["risk_signals"] = sorted(set(summary["risk_signals"]) | set(item.get("risk_signals", []) or []))
            if int(item.get("interesting_score", 0) or 0) > 0:
                summary["interesting_requests"].append(self._interesting_view(item))
            candidate = self._candidate_from_item(item)
            if candidate:
                summary["candidate_requests"].append(candidate)
            for secret in item.get("extracted_secrets", []) or []:
                summary["extracted_secrets"].append(secret)

        summary["analyzed_flows"] = analyzed
        summary["matched_flows"] = analyzed
        summary["discovered_endpoints"] = sorted(set(summary["discovered_endpoints"]))[:300]
        summary["discovered_params"] = sorted(set(summary["discovered_params"]))[:200]
        summary["login_paths"] = sorted(set(summary["login_paths"]))[:40]
        summary["tech_hints"] = sorted(set(summary["tech_hints"]))
        summary["risk_signals"] = sorted(set(summary["risk_signals"]))
        summary["interesting_requests"] = sorted(
            summary["interesting_requests"],
            key=lambda row: int(row.get("interesting_score", 0) or 0),
            reverse=True,
        )[:24]
        summary["candidate_requests"] = sorted(
            summary["candidate_requests"],
            key=lambda row: int(row.get("interesting_score", 0) or 0),
            reverse=True,
        )[:24]
        return summary

    def _summarize_direct_response(
        self,
        *,
        url: str,
        path: str,
        status_code: int,
        response_headers: Dict[str, str],
        response_body: str,
        duration_ms: int = 0,
    ) -> Dict[str, Any]:
        endpoint = path or "/"
        tech_hints = list(self._infer_tech_hints(url, {}, response_headers, "", response_body))
        risk_signals, reasons = self._classify_request(
            method="GET",
            endpoint=endpoint,
            status_code=status_code,
            param_names=[],
            request_headers={},
            response_headers=response_headers,
            request_content_type="",
            response_content_type=_header_value(response_headers, "Content-Type").split(";", 1)[0].strip().lower(),
            request_body="",
            response_body=response_body,
        )
        discovered_endpoints = self._endpoint_hints_from_body(response_body)
        interesting_score = self._score_reasons(reasons, "GET")
        if status_code in (200, 301, 302, 401, 403, 500):
            interesting_score += 1
        secrets = self.extract_secrets(response_body)
        if secrets:
            risk_signals = set(risk_signals)
            risk_signals.add("leaked_secrets_detected")
            reasons.append("secrets in response body")
        return {
            "flow_id": f"active:{endpoint}",
            "method": "GET",
            "url": url,
            "endpoint": endpoint,
            "status_code": status_code,
            "content_type": _header_value(response_headers, "Content-Type").split(";", 1)[0].strip().lower(),
            "response_length": len(response_body or ""),
            "duration_ms": duration_ms,
            "request_headers": {},
            "response_headers": response_headers,
            "body_b64": "",
            "param_names": [],
            "discovered_endpoints": discovered_endpoints,
            "tech_hints": tech_hints,
            "risk_signals": sorted(set(risk_signals)),
            "reasons": reasons,
            "interesting_score": interesting_score,
            "replay_safe": True,
            "has_cookie": False,
            "has_authorization": False,
            "login_paths": self._login_paths_from_request(endpoint, [], reasons),
            "extracted_secrets": secrets[:12],
        }

    def _endpoint_hints_from_body(self, response_body: str) -> List[str]:
        endpoints: set = set()
        body = response_body or ""
        for marker in ("/api/", "/graphql", "/swagger", "/wp-json/", "/admin", "/login"):
            if marker in body.lower():
                endpoints.add(marker.rstrip("/") or "/")
        for src in re.findall(r"""<script[^>]+src=["']([^"']+)["']""", body, flags=re.IGNORECASE):
            endpoint = self._endpoint_from_url_or_path(src)
            if endpoint:
                endpoints.add(endpoint.split("?", 1)[0])
        for href in re.findall(r"""href=["']([^"'#]+)["']""", body, flags=re.IGNORECASE)[:80]:
            endpoint = self._endpoint_from_url_or_path(href)
            if endpoint:
                endpoints.add(endpoint.split("?", 1)[0])
        return sorted(endpoints)[:80]

    @staticmethod
    def _looks_like_directory_listing(response_body: str) -> bool:
        body = (response_body or "")[:12000].lower()
        return (
            "index of /" in body
            or "<title>index of /" in body
            or "directory listing" in body
        )

    def collect_from_proxy(
        self,
        target_info: Dict[str, Any],
        *,
        limit: int = 40,
        include_auth_context: bool = False,
    ) -> Dict[str, Any]:
        summary = self.empty_summary(enabled=True)
        limit = max(0, int(limit or 0))
        if limit <= 0:
            return summary

        try:
            from core.utils.kittyproxy_path import ensure_kittyproxy_path

            ensure_kittyproxy_path()
            from kittyproxy.flow_manager import flow_manager
        except Exception as exc:
            summary["error"] = f"KittyProxy flow manager unavailable: {exc}"
            return summary

        try:
            flows = list(flow_manager.get_flows())
        except Exception as exc:
            summary["error"] = f"Could not read KittyProxy flows: {exc}"
            return summary

        method_counts: Counter = Counter()
        status_counts: Counter = Counter()
        content_types: Counter = Counter()
        endpoints = set()
        params = set()
        login_paths = set()
        tech_hints = set()
        risk_signals = set()
        interesting: List[Dict[str, Any]] = []
        candidates: List[Dict[str, Any]] = []
        auth_contexts: List[Dict[str, Any]] = []
        dom_xss_potential: List[Dict[str, Any]] = []
        login_fidelity_map: Dict[str, Dict[str, Any]] = {}
        extracted_secrets: List[Dict[str, Any]] = []
        timing_anomalies: List[str] = []

        analyzed = 0
        matched = 0
        for row in flows:
            if matched >= limit:
                break
            if not isinstance(row, dict) or not self._flow_matches_target(row, target_info):
                continue
            matched += 1
            flow_id = str(row.get("id") or "").strip()
            detail = row
            if flow_id:
                try:
                    detail = flow_manager.get_flow(flow_id) or row
                except Exception:
                    detail = row
            if not isinstance(detail, dict) or not self._flow_matches_target(detail, target_info):
                continue

            item = self._summarize_flow(detail)
            if not item:
                continue

            analyzed += 1
            method_counts[item["method"]] += 1
            if item.get("status_code"):
                status_counts[str(item.get("status_code"))] += 1
            if item.get("content_type"):
                content_types[item["content_type"]] += 1

            if item.get("endpoint"):
                endpoints.add(item["endpoint"])
            for endpoint in item.get("discovered_endpoints", []):
                endpoints.add(endpoint)
            for name in item.get("param_names", []):
                params.add(str(name).lower())
            for path in item.get("login_paths", []):
                login_paths.add(path)
            tech_hints.update(item.get("tech_hints", []))
            risk_signals.update(item.get("risk_signals", []))

            if item.get("interesting_score", 0) > 0:
                interesting.append(self._interesting_view(item))

            candidate = self._candidate_from_item(item)
            if candidate:
                candidates.append(candidate)

            auth_context = self._auth_context_from_item(item)
            if include_auth_context and auth_context:
                auth_contexts.append(auth_context)

            if item.get("dom_xss_potential"):
                for xss in item["dom_xss_potential"]:
                    xss["endpoint"] = item["endpoint"]
                    dom_xss_potential.append(xss)
            
            if item.get("login_fidelity") and item.get("endpoint"):
                login_fidelity_map[item["endpoint"]] = item["login_fidelity"]

            if item.get("extracted_secrets"):
                extracted_secrets.extend(item["extracted_secrets"])
            
            if item.get("duration_anomaly"):
                timing_anomalies.append(item.get("endpoint", "unknown"))

        interesting.sort(
            key=lambda item: (
                int(item.get("interesting_score", 0) or 0),
                int(item.get("status_code", 0) or 0),
                str(item.get("path", "")),
            ),
            reverse=True,
        )
        candidates.sort(
            key=lambda item: (
                int(item.get("interesting_score", 0) or 0),
                1 if item.get("replay_safe") else 0,
                str(item.get("path", "")),
            ),
            reverse=True,
        )

        summary.update({
            "matched_flows": matched,
            "analyzed_flows": analyzed,
            "method_counts": dict(method_counts),
            "status_counts": dict(status_counts),
            "content_types": dict(content_types.most_common(12)),
            "discovered_endpoints": sorted(endpoints)[:300],
            "discovered_params": sorted(params)[:200],
            "login_paths": sorted(login_paths)[:40],
            "tech_hints": sorted(tech_hints),
            "risk_signals": sorted(risk_signals),
            "interesting_requests": interesting[:18],
            "candidate_requests": candidates[:18],
            "dom_xss_potential": dom_xss_potential[:40],
            "login_fidelity": login_fidelity_map,
            "extracted_secrets": extracted_secrets[:50],
            "timing_anomalies": timing_anomalies,
        })

        if include_auth_context and auth_contexts:
            auth_contexts.sort(key=self._auth_context_score, reverse=True)
            summary["auth_context"] = auth_contexts[0]

        return summary

    def _flow_matches_target(self, flow: Dict[str, Any], target_info: Dict[str, Any]) -> bool:
        target_host = str((target_info or {}).get("hostname") or "").lower().strip()
        if not target_host:
            return False
        target_scheme = str((target_info or {}).get("scheme") or "http").lower()
        try:
            target_port = int((target_info or {}).get("port") or _default_port_for_scheme(target_scheme))
        except Exception:
            target_port = _default_port_for_scheme(target_scheme)

        url = str(flow.get("url") or (flow.get("request") or {}).get("url") or "")
        host = str(flow.get("host") or "").lower().strip()
        scheme = str(flow.get("scheme") or "").lower().strip()
        port: Optional[int] = None
        if url:
            try:
                parsed = urlparse(url)
                host = (parsed.hostname or host or "").lower().strip()
                scheme = parsed.scheme.lower() or scheme
                port = parsed.port
            except Exception:
                pass
        if not host:
            return False
        if host != target_host and not (
            host == f"www.{target_host}" or target_host == f"www.{host}"
        ):
            return False
        if not scheme:
            scheme = target_scheme
        flow_port = port or _default_port_for_scheme(scheme)
        if int(target_port) in (80, 443) and int(flow_port) in (80, 443):
            return True
        return int(flow_port) == int(target_port)

    def _summarize_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        req = flow.get("request") if isinstance(flow.get("request"), dict) else {}
        res = flow.get("response") if isinstance(flow.get("response"), dict) else {}
        url = str(flow.get("url") or req.get("url") or "").strip()
        if not url:
            return {}
        method = str(flow.get("method") or req.get("method") or "GET").upper()
        req_headers = _normalize_headers(req.get("headers") or {})
        res_headers = _normalize_headers(res.get("headers") or {})
        body_b64 = str(req.get("content_bs64") or req.get("content") or "")
        response_b64 = str(res.get("content_bs64") or "")
        request_body = _decode_body_preview(body_b64, limit=8000)
        response_body = _decode_body_preview(response_b64, limit=16000)
        parsed = urlparse(url)
        path = parsed.path or "/"
        endpoint = path + (f"?{parsed.query}" if parsed.query else "")
        status_code = self._safe_int(flow.get("status_code") or res.get("status_code"))
        duration_ms = self._safe_int(flow.get("duration_ms"))
        content_type = _header_value(res_headers, "Content-Type").split(";", 1)[0].strip().lower()
        request_content_type = _header_value(req_headers, "Content-Type").split(";", 1)[0].strip().lower()
        response_length = self._safe_int(res.get("content_length") or flow.get("response_size"))

        params = self._extract_params(url, method, req_headers, body_b64, response_b64)
        param_names = sorted({
            str(p.get("name") or "").strip().lower()
            for p in params
            if str(p.get("name") or "").strip()
        })
        discovered_endpoints = self._endpoint_hints_from_flow(flow, response_body)
        tech_hints = self._infer_tech_hints(url, req_headers, res_headers, request_body, response_body)
        risk_signals, reasons = self._classify_request(
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            param_names=param_names,
            request_headers=req_headers,
            response_headers=res_headers,
            request_content_type=request_content_type,
            response_content_type=content_type,
            request_body=request_body,
            response_body=response_body,
        )
        login_paths = self._login_paths_from_request(endpoint, param_names, reasons)
        interesting_score = self._score_reasons(reasons, method)

        return {
            "flow_id": str(flow.get("id") or ""),
            "method": method,
            "url": url,
            "scheme": parsed.scheme,
            "host": parsed.hostname or flow.get("host") or "",
            "path": path,
            "endpoint": endpoint[:260],
            "status_code": status_code,
            "duration_ms": duration_ms,
            "response_length": response_length,
            "content_type": content_type,
            "request_content_type": request_content_type,
            "request_headers": req_headers,
            "response_headers": res_headers,
            "body_b64": body_b64,
            "param_names": param_names,
            "params": params[:40],
            "discovered_endpoints": discovered_endpoints,
            "login_paths": login_paths,
            "tech_hints": sorted(tech_hints),
            "risk_signals": sorted(risk_signals),
            "reasons": reasons,
            "interesting_score": interesting_score,
            "replay_safe": method in SAFE_REPLAY_METHODS and not body_b64,
            "has_cookie": bool(_header_value(req_headers, "Cookie")),
            "has_authorization": bool(_header_value(req_headers, "Authorization")),
            "dom_xss_potential": self._detect_dom_xss_potential(params, response_body),
            "login_fidelity": self._assess_login_page_fidelity(endpoint, status_code, res_headers, response_body) if "authentication surface" in reasons else {},
            "extracted_secrets": self.extract_secrets(response_body),
            "duration_anomaly": duration_ms > 1500, # Initial simplistic check
        }

    def _extract_params(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body_b64: str,
        response_b64: str,
    ) -> List[Dict[str, Any]]:
        try:
            from core.utils.kittyproxy_path import ensure_kittyproxy_path

            ensure_kittyproxy_path()
            from kittyproxy.reflection_checker import get_all_fuzzable_params

            return get_all_fuzzable_params(url, method, headers, body_b64, response_b64)
        except Exception:
            return []

    def _endpoint_hints_from_flow(self, flow: Dict[str, Any], response_body: str) -> List[str]:
        endpoints = set()
        raw_values = flow.get("discovered_endpoints")
        if isinstance(raw_values, list):
            for value in raw_values:
                endpoint = self._endpoint_from_url_or_path(value)
                if endpoint:
                    endpoints.add(endpoint)
        endpoint_groups = flow.get("endpoints")
        if isinstance(endpoint_groups, dict):
            for values in endpoint_groups.values():
                if not isinstance(values, list):
                    continue
                for value in values:
                    endpoint = self._endpoint_from_url_or_path(value)
                    if endpoint:
                        endpoints.add(endpoint)
        for marker in ("/api/", "/graphql", "/swagger", "/wp-json/", "/admin", "/login"):
            if marker in response_body.lower():
                endpoints.add(marker.rstrip("/") or "/")
        for src in re.findall(r"""<script[^>]+src=["']([^"']+)["']""", response_body, flags=re.IGNORECASE):
            endpoint = self._endpoint_from_url_or_path(src)
            if endpoint:
                endpoints.add(endpoint.split("?", 1)[0])
        for href in re.findall(r"""href=["']([^"'#]+)["']""", response_body, flags=re.IGNORECASE)[:80]:
            endpoint = self._endpoint_from_url_or_path(href)
            if endpoint:
                endpoints.add(endpoint.split("?", 1)[0])
        return sorted(endpoints)[:80]

    def _endpoint_from_url_or_path(self, value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        low = raw.lower()
        if low.startswith(("#", "javascript:", "mailto:", "data:", "tel:")):
            return ""
        try:
            parsed = urlparse(raw)
            if parsed.scheme or parsed.netloc:
                path = parsed.path or "/"
                query = f"?{parsed.query}" if parsed.query else ""
                return (path + query)[:260]
        except Exception:
            pass
        if raw.startswith("/"):
            path = raw
        else:
            # Apache "Index of /" and relative HTML links (e.g. payroll_app.php).
            path = "/" + raw.lstrip("/")
        if ".." in path.split("/"):
            return ""
        return path.split("#", 1)[0][:260]

    def _infer_tech_hints(
        self,
        url: str,
        request_headers: Dict[str, str],
        response_headers: Dict[str, str],
        request_body: str,
        response_body: str,
    ) -> Iterable[str]:
        blob = " ".join([
            url,
            str(request_headers),
            str(response_headers),
            request_body[:3000],
            response_body[:12000],
        ]).lower()
        hints = set()
        token_map = {
            "angular": ("ng-version", "ng-app", "ng-controller", "_ngcontent-", "angular.min.js", "platform-browser", "zone.js"),
            "api": ("/api/", "application/json", "openapi", "swagger", "graphql"),
            "apache": ("server': 'apache", "server: apache", "apache"),
            "django": ("csrftoken", "django", "sessionid"),
            "drupal": ("drupal", "x-drupal-cache", "sites/default"),
            "dvwa": ("dvwa", "damn vulnerable web application"),
            "fastapi": ("fastapi", "uvicorn"),
            "flask": ("flask", "werkzeug"),
            "graphql": ("graphql",),
            "joomla": ("joomla", "com_content"),
            "nginx": ("server': 'nginx", "server: nginx", "nginx"),
            "nodejs": ("express", "node.js", "x-powered-by': 'express", "x-powered-by: express"),
            "nextjs": (
                "__next_data__",
                "/_next/",
                "/_next/static/",
                "next-route-announcer",
                "next-head-count",
                "nextjs",
                "next.js",
                "x-nextjs-cache",
                "x-nextjs-matched-path",
                "x-middleware-rewrite",
                "x-middleware-next",
            ),
            "php": ("phpsessid", "x-powered-by': 'php", "x-powered-by: php"),
            "phpmyadmin": ("phpmyadmin",),
            "swagger": ("swagger", "openapi"),
            "wordpress": ("wp-content", "wp-includes", "wp-json", "wordpress", "wp-login.php"),
        }
        for hint, markers in token_map.items():
            if any(marker in blob for marker in markers):
                hints.add(hint)

        react_markers = (
            r"data-reactroot\b",
            r"data-reactid\b",
            r"__react(?:fiber|props|container)?\b",
            r"_reactrootcontainer",
            r"\breact-dom\b",
            r"\breact(?:\.production|\.development|\.min){0,2}\.js\b",
            r"\breact/jsx-runtime\b",
            r"__next_data__",
            r"id=[\"']__next[\"']",
            r"id=[\"']___gatsby[\"']",
            r"gatsby-",
        )
        if any(re.search(marker, blob, re.IGNORECASE) for marker in react_markers):
            hints.add("react")
        if "nextjs" in hints:
            hints.add("react")
            hints.add("nodejs")

        vue_markers = (
            r"\bdata-v-[a-f0-9]{4,}",
            r"\bdata-v-app\b",
            r"__vue__",
            r"\bv-(?:if|for|bind|model|show|on)\b",
            r"vue(?:\.runtime)?(?:\.global|\.esm-browser|\.min)?\.js",
            r"__nuxt__",
            r"id=[\"']__nuxt[\"']",
        )
        if any(re.search(marker, blob, re.IGNORECASE) for marker in vue_markers):
            hints.add("vue")
        return hints

    def _classify_request(
        self,
        *,
        method: str,
        endpoint: str,
        status_code: int,
        param_names: List[str],
        request_headers: Dict[str, str],
        response_headers: Dict[str, str],
        request_content_type: str,
        response_content_type: str,
        request_body: str,
        response_body: str,
    ) -> Tuple[Iterable[str], List[str]]:
        low_endpoint = endpoint.lower()
        param_set = {str(p).lower() for p in param_names}
        blob = f"{low_endpoint} {request_body[:2000].lower()} {response_body[:4000].lower()}"
        reasons: List[str] = []
        signals = set()

        if method not in SAFE_REPLAY_METHODS:
            reasons.append("state-changing request")
            signals.add("captured_state_changing_request")
        if param_names:
            reasons.append(f"{len(param_names)} parameter(s)")
            signals.add("parameterized_request")
        if any(token in low_endpoint for token in AUTH_TOKENS) or param_set.intersection(AUTH_TOKENS):
            reasons.append("authentication surface")
            signals.add("login_surface_detected")
        if any(p in IDOR_PARAM_TOKENS or p.endswith("_id") or p.endswith("id") for p in param_set):
            reasons.append("object-id parameter")
            signals.add("idor_candidate_params")
        if param_set.intersection(REDIRECT_PARAM_TOKENS):
            reasons.append("redirect/url parameter")
            signals.add("redirect_or_ssrf_params")
        if param_set.intersection(FILE_PARAM_TOKENS):
            reasons.append("file/path parameter")
            signals.add("file_path_params")
        if (
            param_set.intersection(CMD_PARAM_TOKENS)
            or any(token in low_endpoint for token in ("cmd", "exec", "ping", "shell"))
        ):
            reasons.append("command injection candidate")
            signals.add("rce_candidate_params")
        if "/api" in low_endpoint or "json" in response_content_type or "json" in request_content_type:
            reasons.append("API/JSON surface")
            signals.add("api_surface_detected")
        if "graphql" in low_endpoint or "graphql" in blob:
            reasons.append("GraphQL surface")
            signals.add("graphql_surface_detected")
        if "swagger" in low_endpoint or "openapi" in blob:
            reasons.append("Swagger/OpenAPI surface")
            signals.add("swagger_surface_detected")
        if "upload" in low_endpoint or "multipart/form-data" in request_content_type:
            reasons.append("upload surface")
            signals.add("upload_surface_detected")
        if status_code in (301, 302, 303, 307, 308):
            reasons.append(f"redirect status {status_code}")
            signals.add("redirect_observed")
        if status_code in (401, 403):
            reasons.append(f"auth boundary status {status_code}")
            signals.add("auth_boundary_detected")
        if status_code >= 500:
            reasons.append(f"server error status {status_code}")
            signals.add("server_error_observed")
        if self._looks_like_directory_listing(response_body):
            reasons.append("directory listing")
            signals.add("directory_listing_detected")
        if is_actionable_waf_signal(
            status_code=status_code,
            body=blob,
            message=" ".join(reasons),
            details=response_headers,
        ):
            reasons.append("blocking/WAF signal")
            signals.add("waf_or_blocking_detected")
        if _header_value(request_headers, "Cookie"):
            reasons.append("cookie-authenticated request")
            signals.add("session_cookie_observed")
        if _header_value(response_headers, "Set-Cookie"):
            signals.add("session_cookie_issued")

        return signals, reasons

    def _login_paths_from_request(self, endpoint: str, param_names: List[str], reasons: List[str]) -> List[str]:
        if "authentication surface" not in reasons:
            return []
        path = endpoint.split("?", 1)[0]
        if path.startswith("/"):
            return [path[:200]]
        return []

    def _score_reasons(self, reasons: List[str], method: str) -> int:
        score = 0
        joined = " ".join(reasons)
        weights = {
            "authentication surface": 8,
            "cookie-authenticated request": 6,
            "object-id parameter": 6,
            "redirect/url parameter": 5,
            "file/path parameter": 5,
            "command injection candidate": 7,
            "API/JSON surface": 4,
            "GraphQL surface": 4,
            "Swagger/OpenAPI surface": 4,
            "server error status": 4,
            "auth boundary status": 3,
            "upload surface": 3,
            "parameter(s)": 2,
        }
        for token, weight in weights.items():
            if token in joined:
                score += weight
        if method in SAFE_REPLAY_METHODS:
            score += 2
        return score

    def _interesting_view(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "flow_id": item.get("flow_id"),
            "method": item.get("method"),
            "path": item.get("endpoint"),
            "status_code": item.get("status_code"),
            "content_type": item.get("content_type"),
            "param_names": item.get("param_names", [])[:18],
            "reasons": item.get("reasons", [])[:8],
            "interesting_score": item.get("interesting_score", 0),
            "replay_safe": item.get("replay_safe", False),
            "has_cookie": item.get("has_cookie", False),
        }

    def _candidate_from_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        if int(item.get("interesting_score", 0) or 0) <= 0:
            return {}
        method = str(item.get("method") or "GET").upper()
        if method not in ACTIVE_REPLAY_METHODS:
            return {}
        return {
            "flow_id": item.get("flow_id"),
            "method": method,
            "url": item.get("url"),
            "path": item.get("endpoint"),
            "status_code": item.get("status_code"),
            "headers": item.get("request_headers", {}),
            "body_b64": item.get("body_b64", ""),
            "reasons": item.get("reasons", [])[:8],
            "interesting_score": item.get("interesting_score", 0),
            "replay_safe": bool(item.get("replay_safe")),
            "has_sensitive_headers": bool(item.get("has_cookie") or item.get("has_authorization")),
        }

    def _auth_context_from_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        headers = item.get("request_headers") if isinstance(item.get("request_headers"), dict) else {}
        cookies = _parse_cookie_header(_header_value(headers, "Cookie"))
        if not cookies:
            return {}
        status_code = int(item.get("status_code") or 0)
        if status_code in (401, 403) or status_code >= 500:
            return {}
        endpoint = str(item.get("endpoint") or "/")
        return {
            "source_module": "agent/http_request_intel",
            "username": "",
            "password": "",
            "login_path": endpoint.split("?", 1)[0] if any(t in endpoint.lower() for t in AUTH_TOKENS) else "",
            "final_url": str(item.get("url") or "")[:512],
            "final_path": endpoint.split("?", 1)[0],
            "post_login_snippet": "",
            "cookies": cookies,
            "cookie_header": _header_value(headers, "Cookie")[:4000],
            "username_field": "",
            "password_field": "",
            "extra_fields": "",
        }

    def _auth_context_score(self, context: Dict[str, Any]) -> int:
        score = 0
        if context.get("cookies"):
            score += 5
        if context.get("login_path"):
            score += 2
        if context.get("final_path"):
            score += 1
        return score

    def send_candidate(
        self,
        candidate: Dict[str, Any],
        *,
        mode: str = "safe",
        timeout: float = 8.0,
        include_sensitive_headers: bool = False,
        include_body: bool = False,
        evasion: bool = False,
    ) -> Dict[str, Any]:
        method = str(candidate.get("method") or "GET").upper()
        mode = str(mode or "safe").lower()
        if mode == "off":
            return {"status": "skipped", "error": "HTTP replay disabled"}
        if mode == "safe" and method not in SAFE_REPLAY_METHODS:
            return {"status": "skipped", "error": f"safe replay skips {method}"}
        if mode == "active" and method not in ACTIVE_REPLAY_METHODS:
            return {"status": "skipped", "error": f"unsupported replay method {method}"}
        policy = active_runtime_policy()
        if method in MUTATING_HTTP_METHODS and (
            policy is None or not policy.approve_active_replay
        ):
            return {
                "status": "skipped",
                "error": "mutating HTTP replay requires explicit approval",
            }

        url = str(candidate.get("url") or "").strip()
        if not url:
            return {"status": "error", "error": "missing URL"}
        guard = active_scope_guard()
        if guard is not None:
            allowed, reason = guard.validate_url(url)
            if not allowed:
                return {"status": "blocked", "error": reason, "url": url}

        headers = self._clean_outgoing_headers(
            candidate.get("headers") or {},
            include_sensitive=include_sensitive_headers,
        )
        body = b""
        if mode == "active" and method not in SAFE_REPLAY_METHODS:
            body = _decode_b64(candidate.get("body_b64") or "")

        if evasion:
            url, headers, body = self.evasion.apply_random(method, url, headers, body)

        proxies = self._build_proxy_dict()
        verify = policy.tls_verify_value() if policy is not None else True
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        started = time.time()
        request_hash = hashlib.sha256(
            json.dumps(
                {
                    "method": method,
                    "url": url,
                    "headers": sorted(headers),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body if body else None,
                timeout=max(1.0, float(timeout or 8.0)),
                allow_redirects=False,
                proxies=proxies or None,
                verify=verify,
            )
            elapsed_ms = int((time.time() - started) * 1000)
            if guard is not None:
                allowed, reason = guard.validate_redirect_chain(
                    url,
                    str(response.url or url),
                    response.history,
                )
                if not allowed:
                    response.close()
                    return {
                        "status": "blocked",
                        "error": reason,
                        "request_hash": request_hash,
                    }
            return {
                "status": "ok",
                "flow_id": candidate.get("flow_id"),
                "method": method,
                "url": url,
                "path": candidate.get("path"),
                "status_code": int(response.status_code or 0),
                "reason": str(response.reason or ""),
                "duration_ms": elapsed_ms,
                "response_length": len(response.content or b""),
                "content_type": str(response.headers.get("Content-Type", "")).split(";", 1)[0],
                "final_url": str(response.url or ""),
                "used_proxy": bool(proxies),
                "original_status_code": candidate.get("status_code"),
                "request_hash": request_hash,
                "response_body": response.text if include_body else None,
            }
        except Exception as exc:
            return {
                "status": "error",
                "flow_id": candidate.get("flow_id"),
                "method": method,
                "url": url,
                "path": candidate.get("path"),
                "error": str(exc),
                "used_proxy": bool(proxies),
                "request_hash": request_hash,
            }

    def _clean_outgoing_headers(self, headers: Any, *, include_sensitive: bool) -> Dict[str, str]:
        clean: Dict[str, str] = {}
        for key, value in _normalize_headers(headers).items():
            low = key.lower()
            if low in DROP_OUTGOING_HEADERS:
                continue
            if low in SENSITIVE_REPLAY_HEADERS and not include_sensitive:
                continue
            clean[key] = value
        clean.setdefault("User-Agent", "KittysploitAgent/1.0 (+authorized-testing)")
        return clean

    def _build_proxy_dict(self) -> Dict[str, str]:
        framework = self.framework
        if framework is not None and hasattr(framework, "is_tor_enabled"):
            try:
                if framework.is_tor_enabled():
                    tor_proxies = framework.tor_manager.get_tor_proxy_dict()
                    if tor_proxies:
                        return tor_proxies
            except Exception:
                pass

        if framework is not None and hasattr(framework, "is_proxy_enabled"):
            try:
                if framework.is_proxy_enabled():
                    proxy_url = framework.get_proxy_url()
                    if proxy_url:
                        return {"http": proxy_url, "https": proxy_url}
            except Exception:
                pass

        runtime_proxy = self._runtime_proxy_url()
        if runtime_proxy:
            return {"http": runtime_proxy, "https": runtime_proxy}
        return {}

    def _runtime_proxy_url(self) -> str:
        framework = self.framework
        state = getattr(framework, "kittyproxy_runtime", None) if framework is not None else None
        if not isinstance(state, dict):
            return ""
        instance = state.get("instance")
        thread = getattr(instance, "thread", None)
        if not thread or not thread.is_alive():
            return ""
        host = str(state.get("host") or "127.0.0.1").strip()
        if host in ("0.0.0.0", "::", ""):
            host = "127.0.0.1"
        try:
            port = int(state.get("port") or 8080)
        except Exception:
            port = 8080
        return f"http://{host}:{port}"

    def _detect_dom_xss_potential(self, params: List[Dict[str, Any]], response_body: str) -> List[Dict[str, Any]]:
        if not params or not response_body:
            return []
        
        results = []
        for p in params:
            name = p.get("name")
            value = p.get("value")
            if not name or not value or len(str(value)) < 3:
                continue
            
            val_str = str(value)
            if val_str not in response_body:
                continue
            
            # Context detection
            contexts = []
            if f"<script" in response_body.lower() and val_str in response_body:
                # Basic check for reflection inside script tags
                script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', response_body, re.DOTALL | re.IGNORECASE)
                for block in script_blocks:
                    if val_str in block:
                        contexts.append("script_block")
                        break
            
            if re.search(f'on\\w+\\s*=\\s*["\'][^"\']*?{re.escape(val_str)}', response_body, re.IGNORECASE):
                contexts.append("attribute_event")
            
            if re.search(f'href\\s*=\\s*["\']javascript:[^"\']*?{re.escape(val_str)}', response_body, re.IGNORECASE):
                contexts.append("javascript_uri")
                
            if not contexts and val_str in response_body:
                contexts.append("html_body")
                
            if contexts:
                results.append({
                    "param": name,
                    "value_reflected": val_str,
                    "contexts": contexts,
                    "is_likely_vulnerable": any(c in ("script_block", "attribute_event", "javascript_uri") for c in contexts)
                })
        return results

    def _assess_login_page_fidelity(self, endpoint: str, status_code: int, headers: Dict[str, str], body: str) -> Dict[str, Any]:
        fidelity = {
            "is_https": endpoint.startswith("https") or _header_value(headers, "Strict-Transport-Security") != "",
            "has_csrf_protection": any(t in body.lower() for t in ("csrf", "xsrf", "authenticity_token")),
            "security_headers": {
                "hsts": bool(_header_value(headers, "Strict-Transport-Security")),
                "csp": bool(_header_value(headers, "Content-Security-Policy")),
                "xfo": bool(_header_value(headers, "X-Frame-Options")),
            },
            "fidelity_score": 0,
            "fidelity_class": "unknown",
            "signals": []
        }
        
        score = 0
        if fidelity["is_https"]: score += 20
        if fidelity["has_csrf_protection"]: score += 30
        if fidelity["security_headers"]["hsts"]: score += 10
        if fidelity["security_headers"]["csp"]: score += 20
        if fidelity["security_headers"]["xfo"]: score += 10
        
        # Negative signals
        low_body = body.lower()
        if "password" in low_body and "type=\"password\"" not in low_body:
            fidelity["signals"].append("suspicious_password_field")
            score -= 15
            
        if status_code == 200:
            score += 10
            
        fidelity["fidelity_score"] = max(0, min(100, score))
        if score >= 80: fidelity["fidelity_class"] = "high"
        elif score >= 50: fidelity["fidelity_class"] = "medium"
        else: fidelity["fidelity_class"] = "low"
        
        return fidelity

    def probe_reflection_canary(
        self,
        candidate: Dict[str, Any],
        param_name: str,
        canary: str = "ksploit_canary_789",
        mode: str = "safe",
        timeout: float = 8.0,
    ) -> Dict[str, Any]:
        """Send a modified request with a canary to confirm reflection."""
        method = str(candidate.get("method") or "GET").upper()
        url = str(candidate.get("url") or "").strip()
        if not url or not param_name:
            return {"status": "error", "error": "missing URL or parameter name"}

        # Modify URL or Body
        new_url = url
        new_body_b64 = candidate.get("body_b64") or ""
        
        # Simple URL parameter replacement
        if f"{param_name}=" in url:
            new_url = re.sub(f"({re.escape(param_name)}=)[^&]*", f"\\1{canary}", url)
        
        # If POST and body contains param
        if method == "POST" and new_body_b64:
            try:
                body_text = _decode_b64(new_body_b64).decode("utf-8", errors="ignore")
                if f"{param_name}=" in body_text:
                    new_body_text = re.sub(f"({re.escape(param_name)}=)[^&]*", f"\\1{canary}", body_text)
                    new_body_b64 = base64.b64encode(new_body_text.encode("utf-8")).decode("utf-8")
            except Exception:
                pass

        # Use send_candidate with the modified data
        modified_candidate = dict(candidate)
        modified_candidate["url"] = new_url
        modified_candidate["body_b64"] = new_body_b64
        
        result = self.send_candidate(
            modified_candidate, 
            mode=mode, 
            timeout=timeout, 
            include_sensitive_headers=True,
            include_body=True
        )
        if result.get("status") == "ok" and result.get("response_body"):
            body = result["response_body"]
            if canary in body:
                result["reflection_confirmed"] = True
                # Detect context again for the canary
                result["canary_contexts"] = self._detect_dom_xss_potential(
                    [{"name": param_name, "value": canary}], 
                    body
                )
            else:
                result["reflection_confirmed"] = False
            
        return result

    def generate_adaptive_payload(
        self,
        context: str,
        param_name: str,
        *,
        llm_endpoint: str = "",
        llm_model: str = "",
    ) -> str:
        """Use LLM to generate a payload tailored to the reflection context."""
        if not self._llm:
            return ""
        try:
            if not hasattr(self._llm, "query_text"):
                return ""
            response = self._llm.query_text(
                self._resolve_llm_endpoint(llm_endpoint),
                self._resolve_llm_model(llm_model),
                "Return one minimal test payload as plain text.",
                {"context": context, "parameter": param_name},
            )
            return str(response).strip().strip('`').strip()
        except Exception:
            return ""

    def test_session_validity(self, cookies: Dict[str, str], target_url: str) -> Dict[str, Any]:
        """Test if a set of cookies provides authenticated access."""
        endpoints = ["/admin", "/api/user", "/profile", "/settings", "/config"]
        base_url = "/".join(target_url.split("/")[:3])
        
        results = {}
        for ep in endpoints:
            url = base_url + ep
            try:
                guard = active_scope_guard()
                if guard is not None and not guard.validate_url(url)[0]:
                    continue
                policy = active_runtime_policy()
                res = requests.get(
                    url,
                    cookies=cookies,
                    timeout=5,
                    allow_redirects=False,
                    verify=policy.tls_verify_value() if policy is not None else True,
                )
                if res.status_code == 200 or (res.status_code == 302 and "/login" not in res.headers.get("Location", "")):
                    results[ep] = {
                        "status": "active",
                        "status_code": res.status_code,
                        "length": len(res.content),
                        "is_admin": "admin" in ep or "admin" in res.text.lower()
                    }
            except Exception:
                pass
        return results

    def calibrate_responses(self, target_url: str) -> Dict[str, Any]:
        """Send requests to non-existent paths to establish a baseline for errors."""
        random_path = f"/ksploit_check_{base64.b64encode(os.urandom(6)).decode().lower()}"
        base_url = "/".join(target_url.split("/")[:3])
        url = base_url + random_path
        
        try:
            guard = active_scope_guard()
            if guard is not None:
                allowed, reason = guard.validate_url(url)
                if not allowed:
                    return {"error": reason}
            policy = active_runtime_policy()
            res = requests.get(
                url,
                timeout=5,
                allow_redirects=False,
                verify=policy.tls_verify_value() if policy is not None else True,
            )
            return {
                "status_code": res.status_code,
                "length": len(res.content),
                "headers": dict(res.headers),
                "is_custom_error": "error" in res.text.lower() or res.status_code != 404
            }
        except Exception:
            return {}

    def infer_hidden_parameters(
        self,
        known_params: List[str],
        *,
        llm_endpoint: str = "",
        llm_model: str = "",
    ) -> List[str]:
        """Use LLM to guess potential hidden or interesting parameters."""
        if not self._llm or not known_params:
            return []
        try:
            if not hasattr(self._llm, "query_text"):
                return []
            response = self._llm.query_text(
                self._resolve_llm_endpoint(llm_endpoint),
                self._resolve_llm_model(llm_model),
                "Return at most five parameter names separated by commas.",
                {"known_parameters": known_params},
            )
            suggested = [p.strip() for p in str(response).split(",") if p.strip()]
            return suggested
        except Exception:
            return []

    def extract_secrets(self, body: str) -> List[Dict[str, str]]:
        """Extract JWT, API keys, and other secrets from the response body."""
        patterns = {
            "jwt": r"eyJh[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "google_api": r"AIza[0-9A-Za-z-_]{35}",
            "bearer_token": r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)",
            "generic_secret": r"(?i)(key|secret|password|token|auth)\s*[:=]\s*[\"']([A-Za-z0-9\-._~+/]{8,})[\"']"
        }
        
        found = []
        for name, pattern in patterns.items():
            matches = re.findall(pattern, body)
            for m in matches:
                if isinstance(m, tuple):
                    m = m[1]
                found.append({"type": name, "value": m})
        return found

    def _safe_int(self, value: Any) -> int:
        try:
            return int(value or 0)
        except Exception:
            return 0


class PayloadMutationEngine:
    """Generates mutated payloads for command injection and other vulnerabilities."""

    def __init__(self) -> None:
        pass

    def mutate_command(self, cmd: str) -> List[str]:
        """Generate multiple variations of a shell command."""
        variants = [cmd]
        
        # Space bypasses
        variants.append(cmd.replace(" ", "${IFS}"))
        variants.append(cmd.replace(" ", "$IFS$9"))
        variants.append(cmd.replace(" ", "%20"))
        
        # Obfuscation (simple)
        if len(cmd) > 2:
            obf = cmd[0] + "''" + cmd[1:]
            variants.append(obf)
            
        # Slash bypass for paths
        if "/" in cmd:
            variants.append(cmd.replace("/", "${HOME:0:1}"))
            
        # Multi-command prefixes
        prefixes = [";", "&&", "||", "|", "\n"]
        extended = []
        for v in variants:
            for p in prefixes:
                extended.append(p + v)
        
        return list(set(variants + extended))
