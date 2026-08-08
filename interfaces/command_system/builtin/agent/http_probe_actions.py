#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared HTTP probe primitives for legacy and adaptive agent loops."""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from interfaces.command_system.builtin.agent.network_budget import try_consume_budget

MAX_HTTP_REQUESTS_PER_TURN = 5
DEFAULT_PROBE_PATHS: Sequence[str] = (
    "/",
    "/api",
    "/api/v1",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/robots.txt",
)


def sanitize_http_request_action_options(options: Any) -> Dict[str, Any]:
    if not isinstance(options, dict):
        return {"method": "GET"}
    method = str(options.get("method") or "GET").strip().upper()
    if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        method = "GET"
    safe: Dict[str, Any] = {"method": method}
    headers = options.get("headers")
    if isinstance(headers, dict):
        cleaned_headers: Dict[str, str] = {}
        for key, value in list(headers.items())[:8]:
            key_s = str(key or "").strip()
            value_s = str(value or "").strip()
            if not key_s or len(key_s) > 64 or "\n" in key_s or "\r" in key_s:
                continue
            if "\n" in value_s or "\r" in value_s:
                continue
            if key_s.lower() in {"host", "content-length", "connection"}:
                continue
            cleaned_headers[key_s] = value_s[:512]
        if cleaned_headers:
            safe["headers"] = cleaned_headers
    if "body" in options:
        safe["body"] = str(options.get("body") or "")[:4096]
    if "timeout" in options:
        try:
            safe["timeout"] = max(1.0, min(float(options.get("timeout") or 5.0), 15.0))
        except Exception:
            safe["timeout"] = 5.0
    return safe


def sanitize_surface_scan_action_options(options: Any) -> Dict[str, Any]:
    if not isinstance(options, dict):
        return {"limit": 6}
    safe: Dict[str, Any] = {}
    try:
        safe["limit"] = max(1, min(int(options.get("limit") or 6), 12))
    except Exception:
        safe["limit"] = 6
    protocol = str(options.get("protocol") or "").strip().lower()
    if protocol in {"http", "https", "tcp", "ssh", "ftp", "smb", "cloud", "telecom"}:
        safe["protocol"] = protocol
    tags = options.get("tags")
    if isinstance(tags, str):
        tag_values = [t.strip().lower() for t in tags.split(",") if t.strip()]
    elif isinstance(tags, (list, tuple)):
        tag_values = [str(t).strip().lower() for t in tags if str(t).strip()]
    else:
        tag_values = []
    if tag_values:
        safe["tags"] = tag_values[:6]
    return safe


def build_agent_http_request_url(state: Any, path_or_url: str) -> str:
    raw = str(path_or_url or "").strip()
    if not raw:
        return ""
    target = state.target_info if isinstance(getattr(state, "target_info", None), dict) else {}
    scheme = str(target.get("scheme") or getattr(state, "protocol", None) or "http").strip().lower() or "http"
    hostname = str(target.get("hostname") or "").strip()
    try:
        port = int(target.get("port") or (443 if scheme == "https" else 80))
    except Exception:
        port = 443 if scheme == "https" else 80
    try:
        parsed = urllib.parse.urlsplit(raw)
    except Exception:
        return ""
    if parsed.scheme:
        if parsed.scheme.lower() not in {"http", "https"}:
            return ""
        target_host = (hostname or "").lower()
        request_host = (parsed.hostname or "").lower()
        if target_host and request_host and request_host != target_host:
            return ""
        return raw
    if not hostname:
        return ""
    path = raw if raw.startswith("/") else f"/{raw}"
    netloc = hostname
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"
    return urllib.parse.urlunsplit((scheme, netloc, path, "", ""))


def default_http_headers(state: Any) -> Dict[str, str]:
    ua = "Mozilla/5.0 (compatible; KittySploitAgent/1.0)"
    try:
        custom = getattr(state, "user_agent", None)
        if custom:
            ua = str(custom)
    except Exception:
        pass
    return {"User-Agent": ua}


def default_ssl_context(state: Any) -> ssl.SSLContext:
    policy = getattr(state, "runtime_policy", None)
    if policy is not None and not getattr(policy, "tls_verify", True):
        ctx = ssl._create_unverified_context()
    else:
        cafile = getattr(policy, "tls_ca_bundle", None) if policy is not None else None
        ctx = ssl.create_default_context(cafile=cafile)
    return ctx


def _proxy_dict_from_state(state: Any) -> Dict[str, str]:
    """Route agent HTTP probes through KittyProxy/Tor when enabled."""
    framework = getattr(state, "framework", None)
    if framework is None:
        return {}
    try:
        from interfaces.command_system.builtin.agent.http_intelligence import HttpRequestIntelligence

        return HttpRequestIntelligence(framework).proxy_dict_for_state(state)
    except Exception:
        return {}


def _tls_verify_from_state(state: Any) -> bool:
    policy = getattr(state, "runtime_policy", None)
    if policy is not None and not getattr(policy, "tls_verify", True):
        return False
    return True


def _execute_http_via_requests(
    *,
    method: str,
    url: str,
    req_headers: Dict[str, str],
    data: Optional[bytes],
    timeout_s: float,
    proxies: Dict[str, str],
    verify: bool,
) -> tuple[int, Dict[str, str], str, str]:
    import requests

    if not verify:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.request(
        method,
        url,
        headers=req_headers,
        data=data,
        timeout=timeout_s,
        allow_redirects=False,
        proxies=proxies or None,
        verify=verify,
    )
    body = (response.text or "")[:8192]
    status = int(response.status_code or 0)
    response_headers = {k.lower(): str(v) for k, v in response.headers.items()}
    final_url = str(response.url or url)
    return status, response_headers, body, final_url


def ingest_http_probe_result(state: Any, raw: Mapping[str, Any]) -> bool:
    """
    Analyze an agent HTTP exchange and merge intel into the knowledge base.

    Returns True when the response warrants replanning (interesting surface).
    """
    kb = getattr(state, "knowledge_base", None)
    if not isinstance(kb, dict):
        return False
    framework = getattr(state, "framework", None)
    if framework is None:
        return False
    try:
        from interfaces.command_system.builtin.agent.http_intelligence import HttpRequestIntelligence

        intel = HttpRequestIntelligence(framework)
        merged = intel.ingest_agent_http_result(kb, raw, state=state)
        state.knowledge_base = kb
        last = merged.get("last_agent_item") if isinstance(merged, dict) else {}
        return int((last or {}).get("interesting_score", 0) or 0) > 0
    except Exception:
        return False


def execute_agent_http_request(
    state: Any,
    action: Mapping[str, Any],
    *,
    headers: Optional[Mapping[str, str]] = None,
    sleep_fn: Optional[Callable[[], None]] = None,
    ssl_context_fn: Optional[Callable[[], ssl.SSLContext]] = None,
    consume_network: Optional[Callable[[int, str], bool]] = None,
) -> Dict[str, Any]:
    """Execute one bounded in-scope HTTP request (shared by legacy + adaptive)."""
    path = str(action.get("path") or "").strip()
    options = sanitize_http_request_action_options(action.get("options", {}))
    method = str(options.get("method") or "GET").upper()
    url = build_agent_http_request_url(state, path)
    result: Dict[str, Any] = {
        "module": "agent/http_request",
        "path": f"agent/http_request:{method} {path}",
        "status": "error",
        "vulnerable": False,
        "message": "",
        "details": {
            "method": method,
            "requested_path": path,
            "url": url,
        },
    }
    if not url:
        result["message"] = "Invalid or out-of-target HTTP request path"
        return result

    guard = getattr(state, "scope_guard", None)
    if guard is not None:
        allowed, reason = guard.validate_url(url)
        if not allowed:
            result["status"] = "skipped"
            result["message"] = f"Scope blocked HTTP request: {reason}"
            return result

    if method not in {"GET", "HEAD", "OPTIONS"}:
        policy = getattr(state, "runtime_policy", None)
        if policy is None or not getattr(policy, "approve_active_replay", False):
            result["status"] = "skipped"
            result["message"] = f"HTTP {method} request requires --approve-active-replay"
            return result

    reason = f"LLM requested HTTP {method} {url}"
    if consume_network is not None:
        ok = consume_network(1, reason)
    else:
        ok = try_consume_budget(state, 1, reason=reason, phase=getattr(state, "current_phase", "") or "act")
    if not ok:
        result["status"] = "skipped"
        result["message"] = "request budget exhausted before HTTP request"
        return result

    req_headers = dict(headers or default_http_headers(state))
    extra = options.get("headers") if isinstance(options.get("headers"), dict) else {}
    req_headers.update(extra)
    data = None
    request_body = ""
    if method not in {"GET", "HEAD", "OPTIONS"} and "body" in options:
        request_body = str(options.get("body") or "")
        data = request_body.encode("utf-8")
    timeout_s = float(options.get("timeout") or 5.0)
    proxies = _proxy_dict_from_state(state)
    verify = _tls_verify_from_state(state)
    status = 0
    response_headers: Dict[str, str] = {}
    body = ""
    final_url = url

    if sleep_fn is not None:
        sleep_fn()
    else:
        delay = float(getattr(state, "request_delay_min", 0) or 0)
        if delay > 0:
            time.sleep(min(delay, 2.0))

    sent = False
    try:
        status, response_headers, body, final_url = _execute_http_via_requests(
            method=method,
            url=url,
            req_headers=req_headers,
            data=data,
            timeout_s=timeout_s,
            proxies=proxies,
            verify=verify,
        )
        sent = True
    except ImportError:
        pass
    except Exception as exc:
        module = str(getattr(type(exc), "__module__", "") or "")
        if module.startswith("requests.") or "HTTPError" in type(exc).__name__:
            if hasattr(exc, "response") and getattr(exc, "response", None) is not None:
                resp = exc.response
                status = int(getattr(resp, "status_code", 0) or 0)
                response_headers = {k.lower(): str(v) for k, v in resp.headers.items()}
                body = (getattr(resp, "text", "") or "")[:8192]
                final_url = str(getattr(resp, "url", "") or url)
                sent = True
        if not sent:
            pass  # fall through to urllib

    if not sent:
        request = urllib.request.Request(url, data=data, headers=req_headers, method=method)

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
                return None

        handlers: List[Any] = [_NoRedirect()]
        if url.startswith("https://"):
            ctx_fn = ssl_context_fn or (lambda: default_ssl_context(state))
            handlers.append(urllib.request.HTTPSHandler(context=ctx_fn()))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(request, timeout=timeout_s) as response:
                body = response.read(8192).decode("utf-8", errors="ignore")
                status = int(getattr(response, "status", 0) or response.getcode() or 0)
                response_headers = {k.lower(): str(v) for k, v in response.headers.items()}
                final_url = str(response.geturl() or "")
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(8192).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            status = int(exc.code or 0)
            response_headers = {k.lower(): str(v) for k, v in (exc.headers.items() if exc.headers else [])}
            final_url = str(getattr(exc, "url", "") or url)
        except Exception as exc:
            result["message"] = f"HTTP request failed: {exc}"
            return result

    result["status"] = "ok" if 200 <= status < 500 else "error"
    result["message"] = f"HTTP {method} {path} -> {status}"
    result["details"].update({
        "status_code": status,
        "headers": response_headers,
        "request_headers": req_headers,
        "request_body": request_body[:4096],
        "body_sample": body[:2000],
        "body_length_sampled": len(body),
        "final_url": final_url,
        "via_proxy": bool(proxies),
    })
    return result


def record_llm_http_requests(kb: Dict[str, Any], results: Sequence[Mapping[str, Any]], *, limit: int = 20) -> None:
    prior = list(kb.get("llm_http_requests") or [])
    for row in results:
        if not isinstance(row, dict):
            continue
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        prior.append({
            "method": details.get("method"),
            "url": details.get("url"),
            "status_code": details.get("status_code"),
            "final_url": details.get("final_url"),
            "body_sample": str(details.get("body_sample") or "")[:1000],
            "headers": {
                k: details.get("headers", {}).get(k)
                for k in ("content-type", "server", "x-powered-by")
                if isinstance(details.get("headers"), dict) and details.get("headers", {}).get(k)
            },
        })
    kb["llm_http_requests"] = prior[-limit:]


def execute_plan_http_requests(
    state: Any,
    actions: Sequence[Mapping[str, Any]],
    budget: int,
    *,
    headers: Optional[Mapping[str, str]] = None,
    sleep_fn: Optional[Callable[[Mapping[str, Any]], None]] = None,
    ssl_context_fn: Optional[Callable[[], ssl.SSLContext]] = None,
    consume_network: Optional[Callable[[int, str], bool]] = None,
    max_per_turn: int = MAX_HTTP_REQUESTS_PER_TURN,
) -> List[Dict[str, Any]]:
    selected = [
        action for action in actions
        if isinstance(action, dict) and str(action.get("type", "")).lower() == "http_request"
    ][: max(0, min(int(budget or 0), int(max_per_turn or MAX_HTTP_REQUESTS_PER_TURN)))]
    if not selected:
        return []
    results: List[Dict[str, Any]] = []
    for action in selected:
        def _sleep(act=action) -> None:
            if sleep_fn is not None:
                sleep_fn(act)

        results.append(
            execute_agent_http_request(
                state,
                action,
                headers=headers,
                sleep_fn=_sleep if sleep_fn is not None else None,
                ssl_context_fn=ssl_context_fn,
                consume_network=consume_network,
            )
        )
    kb = getattr(state, "knowledge_base", None)
    if isinstance(kb, dict):
        record_llm_http_requests(kb, results)
        for row in results:
            ingest_http_probe_result(state, row)
        state.knowledge_base = kb
    return results


def http_surface_observed(kb: Mapping[str, Any], state: Any = None) -> bool:
    protocol = str(getattr(state, "protocol", "") or (kb.get("protocol") if isinstance(kb, Mapping) else "") or "").lower()
    if protocol in {"http", "https"}:
        return True
    scheme = ""
    target = getattr(state, "target_info", None) if state is not None else None
    if isinstance(target, dict):
        scheme = str(target.get("scheme") or "").lower()
    if scheme in {"http", "https"}:
        return True
    signals = {str(s).lower() for s in (kb.get("risk_signals") or [])}
    if signals.intersection({
        "api_surface_detected",
        "graphql_surface_detected",
        "swagger_surface_detected",
        "login_surface_detected",
        "active_web_probe_completed",
    }):
        return True
    if kb.get("discovered_endpoints") or kb.get("request_intel"):
        return True
    return False


def api_surface_ambiguous(kb: Mapping[str, Any], state: Any = None) -> bool:
    """True when HTTP is visible but API/module choice is still unclear."""
    if not http_surface_observed(kb, state):
        return False
    try:
        from interfaces.command_system.builtin.agent.goal_planner import kb_api_surface_ready
        if kb_api_surface_ready(kb):
            return False
    except Exception:
        pass
    weak = False
    endpoints = [str(e).lower() for e in (kb.get("discovered_endpoints") or [])]
    if any(tok in ep for ep in endpoints for tok in ("/api", "json", "rest", "v1", "v2")):
        weak = True
    hints = " ".join(str(h).lower() for h in (kb.get("tech_hints") or []))
    if any(tok in hints for tok in ("api", "json", "swagger", "graphql", "openapi")):
        weak = True
    conf = kb.get("tech_confidence") or {}
    if 0.15 <= float(conf.get("api", 0.0) or 0.0) < 0.45:
        weak = True
    llm_reqs = kb.get("llm_http_requests") or []
    if llm_reqs and not kb.get("api_modules_ranked"):
        weak = True
    return weak


def suggest_probe_paths(kb: Mapping[str, Any]) -> List[str]:
    paths: List[str] = []
    seen: set = set()

    def _add(path: str) -> None:
        p = str(path or "").strip()
        if not p:
            return
        if not p.startswith("/") and not p.startswith("http"):
            p = f"/{p}"
        if p in seen:
            return
        seen.add(p)
        paths.append(p)

    for ep in (kb.get("discovered_endpoints") or [])[:12]:
        _add(str(ep))
    for row in (kb.get("llm_http_requests") or [])[-6:]:
        if isinstance(row, dict) and row.get("url"):
            try:
                parsed = urllib.parse.urlsplit(str(row["url"]))
                if parsed.path:
                    _add(parsed.path)
            except Exception:
                pass
    for default in DEFAULT_PROBE_PATHS:
        _add(default)
    return paths[:12]


def llm_connected(state: Any) -> bool:
    if getattr(state, "local_llm", None) is not None:
        return True
    if getattr(state, "llm_local", False):
        return True
    if getattr(state, "llm_client", None) is not None:
        return True
    return bool(str(getattr(state, "llm_endpoint", "") or "").strip())
