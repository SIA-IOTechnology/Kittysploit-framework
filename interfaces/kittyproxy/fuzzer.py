#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fuzzer engine - Async XSS/SQLi fuzzing with encodings, custom payloads, high concurrency.
Uses reflection_checker for param parsing and request building.
"""

import asyncio
import base64
import json
import re
import uuid
from typing import Dict, List, Optional, Any, AsyncGenerator
from pathlib import Path
from urllib.parse import quote_plus, quote, unquote_plus, unquote, urlparse, urlunparse, parse_qs, urlencode

# Reuse reflection_checker for param parsing and request building
from .reflection_checker import (
    get_all_fuzzable_params,
    build_request_with_canary,
)

# Payloads directory (next to this file)
PAYLOADS_DIR = Path(__file__).resolve().parent / "payloads"
XSS_PAYLOADS_FILE = PAYLOADS_DIR / "xss.txt"
SQLI_PAYLOADS_FILE = PAYLOADS_DIR / "sqli.txt"

# XSS: payload appears in response + script/onerror etc.
XSS_INDICATORS_RE = re.compile(
    r"<script|onerror\s*=|onload\s*=|alert\s*\(|javascript:",
    re.IGNORECASE,
)

# Payloads that contain active XSS primitives (not plain text probes)
XSS_PAYLOAD_PRIMITIVES_RE = re.compile(
    r"<script|on[a-z0-9_]+\s*=|javascript:|alert\s*\(|confirm\s*\(|prompt\s*\(|<img|<svg",
    re.IGNORECASE,
)

# SQLi: common error messages in response
SQL_ERROR_PATTERNS_RE = re.compile(
    r"SQL (syntax|error|warning|query)|mysql_fetch|mysqli?|ORA-\d+|PostgreSQL|SQLite|ODBC|JDBC|"
    r"Warning:.*mysql|Fatal error.*mysql|Unclosed quotation|quoted string not properly terminated|"
    r"you have an error in your sql syntax|syntax error.*sql|invalid query",
    re.IGNORECASE,
)

# Time-based SQLi: delay threshold (ms) to consider potential sleep
TIME_BASED_DELAY_MS = 4000

# DOM-based XSS sinks: if response contains these patterns, the page may be vulnerable to DOM XSS
DOM_XSS_SINKS_RE = re.compile(
    r"\.innerHTML\s*[=+]|\.outerHTML\s*[=+]|document\.write\s*\(|document\.writeln\s*\("
    r"|\.insertAdjacentHTML\s*\(|eval\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]"
    r"|jQuery\s*\(\s*['\"]<|\.html\s*\(",
    re.IGNORECASE,
)

# DOM XSS sources that are attacker-controlled in browser context
DOM_XSS_SOURCES_RE = re.compile(
    r"location\.(?:hash|search|href)|document\.URL|documentURI|document\.location"
    r"|document\.referrer|window\.name|postMessage|URLSearchParams\s*\(|new\s+URL\s*\(",
    re.IGNORECASE,
)


def _reflection_variants(payload: str, encoding: str) -> List[str]:
    """Generate robust reflection candidates to reduce false negatives without token-only matching."""
    if not payload:
        return []
    variants = {
        payload,
        quote(payload, safe=""),
        quote_plus(payload),
        payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace('"', "&quot;").replace("'", "&#39;"),
    }
    if encoding and encoding != "none":
        variants.add(_encode_payload(payload, encoding))
    # Decoded variants help when app/server normalizes URL-encoded values before rendering.
    variants.add(unquote(payload))
    variants.add(unquote_plus(payload))
    return [v for v in variants if v]


def _payload_seems_active_xss(payload: str) -> bool:
    return bool(payload and XSS_PAYLOAD_PRIMITIVES_RE.search(payload))


def _reflection_is_html_escaped(payload: str, body_text: str) -> bool:
    """Detect common case where payload is rendered as text (&lt;...&gt;) and is not executable."""
    if not payload or not body_text or "<" not in payload:
        return False
    basic = payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    quoted = basic.replace('"', "&quot;").replace("'", "&#39;")
    if payload in body_text:
        return False
    return basic in body_text or quoted in body_text


def _has_dom_xss_pattern(body_text: str) -> bool:
    if not body_text:
        return False
    return bool(DOM_XSS_SINKS_RE.search(body_text) and DOM_XSS_SOURCES_RE.search(body_text))


def _encode_payload(payload: str, encoding: str) -> str:
    """Apply encoding to payload. encoding: none, url, double_url, html, base64."""
    if not encoding or encoding == "none":
        return payload
    if encoding == "url":
        return quote(payload, safe="")
    if encoding == "double_url":
        return quote(quote(payload, safe=""), safe="")
    if encoding == "html":
        return (
            payload.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
    if encoding == "base64":
        return base64.b64encode(payload.encode("utf-8", errors="replace")).decode("ascii")
    return payload


def _load_payloads_from_file(path: Path) -> List[str]:
    """Load payloads from file, one per line, skip empty and comments."""
    payloads = []
    if not path.exists():
        return payloads
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            payloads.append(line)
    return payloads


def _load_payloads(fuzz_type: str, custom_list: Optional[List[str]] = None) -> List[str]:
    """Load payloads for fuzz_type (xss, sqli). If custom_list is non-empty, use ONLY those; else use built-in."""
    custom = [p.strip() for p in (custom_list or []) if p and isinstance(p, str) and p.strip()]
    if custom:
        return list(dict.fromkeys(custom))
    builtin = []
    if fuzz_type == "xss":
        builtin = _load_payloads_from_file(XSS_PAYLOADS_FILE)
    elif fuzz_type == "sqli":
        builtin = _load_payloads_from_file(SQLI_PAYLOADS_FILE)
    return builtin


def _normalize_headers(headers: Dict) -> Dict[str, str]:
    out = {}
    for k, v in (headers or {}).items():
        key = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
        val = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
        out[key] = val
    return out


async def _send_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: bytes,
    proxy: Optional[str],
    timeout: float,
    session: "aiohttp.ClientSession",
) -> tuple:
    """Send one request. proxy=None = direct to target; else use proxy. Returns (status_code, body_text, duration_ms, error)."""
    import time
    start = time.perf_counter()
    try:
        async with session.request(
            method,
            url,
            headers=headers,
            data=body if body else None,
            proxy=proxy,
            ssl=False,
            timeout=timeout,
        ) as resp:
            body_bytes = await resp.read()
            body_text = body_bytes.decode("utf-8", errors="replace")
            duration_ms = int((time.perf_counter() - start) * 1000)
            return resp.status, body_text, duration_ms, None
    except Exception as e:
        duration_ms = int((time.perf_counter() - start) * 1000)
        return 0, "", duration_ms, str(e)


def _prepare_inject(payload: str, param_location: str, encoding: str) -> str:
    """Apply encoding then form-encode if needed for body_form."""
    encoded = _encode_payload(payload, encoding)
    if param_location == "body_form":
        encoded = quote_plus(encoded)
    return encoded


async def run_xss_fuzz(
    flow_data: Dict[str, Any],
    param_names: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
    encoding: str = "none",
    concurrency: int = 20,
    timeout: float = 10.0,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
    use_proxy: bool = True,
    on_result: Optional[Any] = None,
    cancel_event: Optional[asyncio.Event] = None,
) -> List[Dict[str, Any]]:
    """Run XSS fuzzing. use_proxy=False = direct request (no proxy)."""
    payloads = payloads or _load_payloads("xss")
    return await _run_fuzz_impl(
        flow_data=flow_data,
        param_names=param_names,
        payloads=payloads,
        encoding=encoding,
        concurrency=concurrency,
        timeout=timeout,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        use_proxy=use_proxy,
        on_result=on_result,
        cancel_event=cancel_event,
        fuzz_type="xss",
    )


async def run_sqli_fuzz(
    flow_data: Dict[str, Any],
    param_names: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
    encoding: str = "none",
    concurrency: int = 20,
    timeout: float = 10.0,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
    use_proxy: bool = True,
    on_result: Optional[Any] = None,
    cancel_event: Optional[asyncio.Event] = None,
) -> List[Dict[str, Any]]:
    """Run SQLi fuzzing. use_proxy=False = direct request."""
    payloads = payloads or _load_payloads("sqli")
    return await _run_fuzz_impl(
        flow_data=flow_data,
        param_names=param_names,
        payloads=payloads,
        encoding=encoding,
        concurrency=concurrency,
        timeout=timeout,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        use_proxy=use_proxy,
        on_result=on_result,
        cancel_event=cancel_event,
        fuzz_type="sqli",
    )


async def _run_fuzz_impl(
    flow_data: Dict[str, Any],
    param_names: Optional[List[str]] = None,
    payloads: Optional[List[str]] = None,
    encoding: str = "none",
    concurrency: int = 20,
    timeout: float = 10.0,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
    use_proxy: bool = True,
    on_result: Optional[Any] = None,
    cancel_event: Optional[asyncio.Event] = None,
    fuzz_type: str = "xss",
) -> List[Dict[str, Any]]:
    try:
        import aiohttp
    except ImportError:
        raise RuntimeError("aiohttp is required for fuzzing: pip install aiohttp")

    req = flow_data.get("request") or {}
    resp = flow_data.get("response") or {}
    url = req.get("url") or ""
    method = (req.get("method") or "GET").upper()
    headers = _normalize_headers(req.get("headers") or {})
    body_b64 = req.get("content_bs64") or req.get("content") or ""
    response_body_b64 = resp.get("content_bs64") or ""

    params_list = get_all_fuzzable_params(url, method, req.get("headers") or {}, body_b64, response_body_b64)
    if not params_list:
        return []

    if param_names:
        params_list = [p for p in params_list if p.get("name") in param_names]
    if not params_list:
        return []

    payloads = payloads or []
    if not payloads:
        return []

    proxy = f"http://{proxy_host}:{proxy_port}" if use_proxy else None
    # Marquer les requêtes fuzzing pour ne pas les ajouter aux Discovered APIs
    if use_proxy and headers is not None:
        headers = dict(headers)
        headers["X-KittyProxy-Source"] = "fuzzing"
    results: List[Dict[str, Any]] = []
    sem = asyncio.Semaphore(concurrency)
    cancel_event = cancel_event or asyncio.Event()
    dom_xss_checked = {"risk": False}

    def _resolve_method_and_location(param: Dict) -> tuple:
        """Determine the effective HTTP method and param location for this param.
        Follows HTML spec: no method attr → GET. Explicit method → use it."""
        fm = param.get("form_method")
        loc = param.get("location", "query")
        if fm == "post":
            return "POST", "body_form"
        if fm == "get" or (param.get("source") == "form"):
            return "GET", "query"
        return method, loc

    def _check_reflected(payload: str, body_text: str) -> bool:
        if not body_text:
            return False
        return any(candidate in body_text for candidate in _reflection_variants(payload, encoding))

    def _check_xss(payload: str, body_text: str, reflected: bool) -> bool:
        if not reflected or not body_text:
            return False
        if not _payload_seems_active_xss(payload):
            return False
        if _reflection_is_html_escaped(payload, body_text):
            return False
        payload_lower = payload.lower()
        body_lower = body_text.lower()

        # Tie the indicator to this payload category to avoid "any <script> on page" false positives.
        if "<script" in payload_lower and "<script" in body_lower:
            return True
        if "javascript:" in payload_lower and "javascript:" in body_lower:
            return True
        handler_matches = re.findall(r"on[a-z0-9_]+\s*=", payload_lower)
        if handler_matches and any(h in body_lower for h in handler_matches):
            return True
        if re.search(r"\b(?:alert|confirm|prompt)\s*\(", payload_lower) and re.search(r"\b(?:alert|confirm|prompt)\s*\(", body_lower):
            return True
        return False

    def _build_request_with_form_context(
        request_url: str,
        eff_method: str,
        eff_location: str,
        param: Dict[str, Any],
        inject: str,
    ) -> tuple:
        """
        Build request while preserving sibling form fields discovered in HTML.
        This avoids sending incomplete form submissions (common false-negative cause).
        """
        form_fields = param.get("form_fields")
        if not isinstance(form_fields, dict) or not form_fields:
            return build_request_with_canary(
                request_url, eff_method, headers, body_b64,
                eff_location, param["name"], inject,
            )

        merged = {str(k): str(v) for k, v in form_fields.items() if k}
        merged[param["name"]] = inject

        new_headers = dict(headers)
        if eff_location == "query":
            parsed = urlparse(request_url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for k, v in merged.items():
                qs[k] = [v]
            new_query = urlencode(qs, doseq=True)
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment,
            ))
            return new_url, new_headers, b""

        if eff_location == "body_form":
            new_body = urlencode(merged, doseq=True).encode("utf-8", errors="replace")
            if "content-type" not in {k.lower() for k in new_headers}:
                new_headers["Content-Type"] = "application/x-www-form-urlencoded"
            return request_url, new_headers, new_body

        return build_request_with_canary(
            request_url, eff_method, headers, body_b64,
            eff_location, param["name"], inject,
        )

    async def _do_send(session, eff_method, request_url, eff_location, param, inject):
        """Build and send one fuzz request. Returns (new_url, new_headers, new_body, status, body_text, duration_ms, err, eff_method)."""
        new_url, new_headers, new_body = request_url, {}, b""
        try:
            if param.get("source") == "form":
                new_url, new_headers, new_body = _build_request_with_form_context(
                    request_url, eff_method, eff_location, param, inject,
                )
            else:
                new_url, new_headers, new_body = build_request_with_canary(
                    request_url, eff_method, headers, body_b64,
                    eff_location, param["name"], inject,
                )
            status, body_text, duration_ms, err = await _send_request(
                eff_method, new_url, new_headers, new_body, proxy, timeout, session,
            )
        except Exception as e:
            status, body_text, duration_ms, err = 0, "", 0, str(e)
            new_url = request_url
        return new_url, new_headers, new_body, status, body_text, duration_ms, err

    async def one_request(session: aiohttp.ClientSession, param: Dict, payload: str) -> Dict[str, Any]:
        async with sem:
            if cancel_event.is_set():
                return {}

            eff_method, eff_location = _resolve_method_and_location(param)
            if param.get("source") == "form" and isinstance(param.get("form_fields"), dict):
                # For form-context requests, urlencode() is done at build step, so keep raw encoded payload here.
                inject = _encode_payload(payload, encoding)
            else:
                inject = _prepare_inject(payload, eff_location, encoding)
            request_url = param.get("form_action") or url

            new_url, new_headers, new_body, status, body_text, duration_ms, err = \
                await _do_send(session, eff_method, request_url, eff_location, param, inject)

            # Auto-retry: if 405 Method Not Allowed, flip GET↔POST
            if status == 405:
                alt_method = "POST" if eff_method == "GET" else "GET"
                alt_location = "body_form" if alt_method == "POST" else "query"
                if param.get("source") == "form" and isinstance(param.get("form_fields"), dict):
                    alt_inject = _encode_payload(payload, encoding)
                else:
                    alt_inject = _prepare_inject(payload, alt_location, encoding)
                new_url, new_headers, new_body, status, body_text, duration_ms, err = \
                    await _do_send(session, alt_method, request_url, alt_location, param, alt_inject)
                eff_method = alt_method
                eff_location = alt_location

            if cancel_event.is_set():
                return {}

            reflected = _check_reflected(payload, body_text)

            # Stored XSS: if not reflected in immediate response, follow-up GET
            if fuzz_type == "xss" and not reflected and status and status != 0:
                try:
                    followup_url = param.get("form_action") or url
                    _, followup_body, _, followup_err = await _send_request(
                        "GET", followup_url, headers, b"", proxy, timeout, session,
                    )
                    if not followup_err and followup_body:
                        reflected = _check_reflected(payload, followup_body)
                        if reflected:
                            body_text = followup_body
                except Exception:
                    pass

            # DOM XSS risk is page-level: require both source and sink; keep OR across responses.
            if fuzz_type == "xss" and body_text and not dom_xss_checked["risk"]:
                dom_xss_checked["risk"] = _has_dom_xss_pattern(body_text)

            snippet = body_text[:300] if body_text else ""

            r = {
                "param": param["name"],
                "location": eff_location,
                "payload": payload[:200],
                "status": status,
                "duration_ms": duration_ms,
                "reflected": reflected,
                "error": err,
                "response_length": len(body_text),
                "request_url": new_url,
                "request_method": eff_method,
                "request_body_b64": base64.b64encode(new_body).decode("ascii") if new_body else "",
                "response_snippet": snippet,
            }
            if fuzz_type == "xss":
                r["xss_like"] = _check_xss(payload, body_text, reflected)
            else:
                r["xss_like"] = False
            if fuzz_type == "sqli":
                sql_error = bool(SQL_ERROR_PATTERNS_RE.search(body_text)) if body_text else False
                time_delay = duration_ms >= TIME_BASED_DELAY_MS
                r["sqli_like"] = sql_error or time_delay
            else:
                r["sqli_like"] = False
            if on_result:
                try:
                    on_result(r)
                except Exception:
                    pass
            return r

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for param in params_list:
            for payload in payloads:
                if cancel_event.is_set():
                    break
                tasks.append(one_request(session, param, payload))

        done = []
        for coro in asyncio.as_completed(tasks):
            if cancel_event.is_set():
                break
            try:
                r = await coro
                if r:
                    results.append(r)
                    done.append(r)
            except Exception:
                pass

    # Mark DOM XSS candidates: page has sinks but payload not in response → suggest manual check
    if fuzz_type == "xss" and dom_xss_checked.get("risk"):
        for r in results:
            if r.get("status") in (200, 201) and not r.get("reflected"):
                r["dom_xss_candidate"] = True

    return results, dom_xss_checked.get("risk", False)


# In-memory job store
_fuzz_jobs: Dict[str, Dict] = {}
_fuzz_jobs_lock = asyncio.Lock() if hasattr(asyncio, 'Lock') else None


def _get_lock():
    try:
        return asyncio.get_event_loop().run_until_complete(asyncio.Lock()) if not _fuzz_jobs_lock else _fuzz_jobs_lock
    except Exception:
        import threading
        return threading.Lock()


def create_fuzz_job(
    flow_data: Dict,
    fuzz_type: str = "xss",
    param_names: Optional[List[str]] = None,
    custom_payloads: Optional[List[str]] = None,
    encoding: str = "none",
    concurrency: int = 20,
    timeout: float = 10.0,
    proxy_port: int = 8080,
    use_proxy: bool = True,
) -> str:
    """Create a fuzz job. custom_payloads merged with built-in. encoding: none, url, double_url, html, base64."""
    import threading
    job_id = str(uuid.uuid4())[:8]
    cancel_ev = asyncio.Event()
    results = []
    status = {"running": True, "total_sent": 0, "total_ok": 0, "started_at": None}

    def on_result(r):
        results.append(r)
        status["total_sent"] = len(results)
        if r.get("status", 0) in (200, 201, 302, 301):
            status["total_ok"] = status.get("total_ok", 0) + 1

    payloads = _load_payloads(fuzz_type, custom_payloads)

    async def run():
        import time
        status["started_at"] = time.time()
        try:
            if fuzz_type == "sqli":
                _, dom_risk = await run_sqli_fuzz(
                    flow_data,
                    param_names=param_names,
                    payloads=payloads,
                    encoding=encoding,
                    concurrency=concurrency,
                    timeout=max(timeout, 6.0),
                    proxy_port=proxy_port,
                    use_proxy=use_proxy,
                    on_result=on_result,
                    cancel_event=cancel_ev,
                )
            else:
                _, dom_risk = await run_xss_fuzz(
                    flow_data,
                    param_names=param_names,
                    payloads=payloads,
                    encoding=encoding,
                    concurrency=concurrency,
                    timeout=timeout,
                    proxy_port=proxy_port,
                    use_proxy=use_proxy,
                    on_result=on_result,
                    cancel_event=cancel_ev,
                )
            status["dom_xss_risk"] = dom_risk
        except asyncio.CancelledError:
            pass
        except Exception as e:
            results.append({"error": str(e), "param": "", "payload": ""})
        finally:
            status["running"] = False

    def run_in_thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run())
        except asyncio.CancelledError:
            pass
        finally:
            loop.close()

    thread = threading.Thread(target=run_in_thread, daemon=True)
    thread.start()

    _fuzz_jobs[job_id] = {
        "thread": thread,
        "cancel_event": cancel_ev,
        "results": results,
        "status": status,
        "fuzz_type": fuzz_type,
        "param_names": param_names,
    }
    return job_id


def get_fuzz_job_status(job_id: str) -> Optional[Dict]:
    j = _fuzz_jobs.get(job_id)
    if not j:
        return None
    s = j["status"]
    return {
        "job_id": job_id,
        "running": s.get("running", False),
        "total_sent": s.get("total_sent", 0),
        "total_ok": s.get("total_ok", 0),
        "started_at": s.get("started_at"),
        "dom_xss_risk": s.get("dom_xss_risk", False),
        "fuzz_type": j.get("fuzz_type"),
    }


def get_fuzz_job_results(job_id: str) -> Optional[List[Dict]]:
    j = _fuzz_jobs.get(job_id)
    if not j:
        return None
    return list(j["results"])


def stop_fuzz_job(job_id: str) -> bool:
    j = _fuzz_jobs.get(job_id)
    if not j:
        return False
    j["cancel_event"].set()
    j["status"]["running"] = False
    return True
