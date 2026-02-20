#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reflection checker - Injects a unique canary in request parameters and checks if it appears in the response.
Used to detect reflected parameters (XSS, injection points, etc.).
"""

import json
import base64
import secrets
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, urljoin


def _generate_canary() -> str:
    """Generate a unique canary string unlikely to appear naturally."""
    return "r3fl3ct_" + secrets.token_hex(8) + "_kp"


def _get_content_type(headers: Dict) -> str:
    if not headers or not isinstance(headers, dict):
        return ""
    for k, v in headers.items():
        key = (k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)).lower()
        if key == "content-type":
            return (v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)) or ""
    return ""


def parse_request_params(
    url: str,
    method: str,
    headers: Dict,
    body_b64: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Parse all injectable parameters from request: query string, form body, JSON body.
    Returns list of { 'location': 'query'|'body_form'|'body_json', 'name': str, 'value': str, 'original_value': str }.
    """
    params = []
    parsed = urlparse(url)

    # Query string
    if parsed.query:
        for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
            if name:
                value = values[0] if values else ""
                params.append({
                    "location": "query",
                    "name": name,
                    "value": value,
                    "original_value": value,
                })

    # Body
    body_raw = b""
    if body_b64:
        try:
            body_raw = base64.b64decode(body_b64)
        except Exception:
            pass
    if not body_raw:
        return params

    ct = _get_content_type(headers).lower()
    try:
        body_str = body_raw.decode("utf-8", errors="replace")
    except Exception:
        return params

    body_params_count_before = len(params)
    if "application/x-www-form-urlencoded" in ct:
        for part in body_str.split("&"):
            if "=" in part:
                k, _, v = part.partition("=")
                name = k.strip()
                if name:
                    params.append({
                        "location": "body_form",
                        "name": name,
                        "value": v.strip(),
                        "original_value": v.strip(),
                    })
    elif "application/json" in ct:
        try:
            data = json.loads(body_str)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(k, str):
                        params.append({
                            "location": "body_json",
                            "name": k,
                            "value": json.dumps(v) if not isinstance(v, (str, int, float, bool)) else str(v),
                            "original_value": v,
                        })
        except (json.JSONDecodeError, TypeError):
            pass

    # Fallback for POST/PUT/PATCH: if no body params were found (e.g. Content-Type missing or wrong), try form then JSON
    if method.upper() in ("POST", "PUT", "PATCH") and len(params) == body_params_count_before:
        # Try form-urlencoded (common for forms)
        for part in body_str.split("&"):
            if "=" in part:
                k, _, v = part.partition("=")
                name = k.strip()
                if name:
                    params.append({
                        "location": "body_form",
                        "name": name,
                        "value": v.strip(),
                        "original_value": v.strip(),
                    })
        # If still none, try JSON
        if len(params) == body_params_count_before:
            try:
                data = json.loads(body_str)
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(k, str):
                            params.append({
                                "location": "body_json",
                                "name": k,
                                "value": json.dumps(v) if not isinstance(v, (str, int, float, bool)) else str(v),
                                "original_value": v,
                            })
            except (json.JSONDecodeError, TypeError):
                pass

    return params


def parse_params_from_response_html(html: str, base_url: str) -> List[Dict[str, Any]]:
    """
    Discover parameters from the response HTML: form fields (GET/POST) and query strings in links.
    Use case: user loaded a page that contains a form to https://example.com/page?query= but never
    submitted it; we still want to offer "query" as a parameter to fuzz.
    Returns list of { 'location': 'query'|'body_form', 'name': str, 'value': '', 'original_value': '', 'source': 'form'|'link' }.
    """
    params: List[Dict[str, Any]] = []
    if not html or not base_url:
        return params
    seen: set = set()  # (name, location) to avoid duplicates

    # Forms: <form method="GET|POST" action="..."> with <input>, <textarea>, <select>, <button> name="...">
    form_open_re = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
    form_close_re = re.compile(r"</form\s*>", re.IGNORECASE)
    form_method_re = re.compile(r"\bmethod\s*=\s*['\"]?(get|post)['\"]?", re.IGNORECASE)
    form_action_re = re.compile(r"\baction\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
    field_tag_re = re.compile(r"<(input|textarea|select|button)\b([^>]*)>", re.IGNORECASE | re.DOTALL)
    name_attr_re = re.compile(r"\bname\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
    value_attr_re = re.compile(r"\bvalue\s*=\s*['\"]([^'\"]*)['\"]", re.IGNORECASE)
    textarea_close_re = re.compile(r"</textarea\s*>", re.IGNORECASE)
    select_close_re = re.compile(r"</select\s*>", re.IGNORECASE)
    option_selected_re = re.compile(
        r"<option\b[^>]*\bselected\b[^>]*\bvalue\s*=\s*['\"]([^'\"]*)['\"]",
        re.IGNORECASE,
    )
    option_value_re = re.compile(r"<option\b[^>]*\bvalue\s*=\s*['\"]([^'\"]*)['\"]", re.IGNORECASE)

    def _extract_form_fields(fragment: str) -> Dict[str, str]:
        fields: Dict[str, str] = {}
        for m in field_tag_re.finditer(fragment):
            tag = (m.group(1) or "").lower()
            attrs = m.group(2) or ""
            name_match = name_attr_re.search(attrs)
            if not name_match:
                continue
            name = name_match.group(1).strip()
            if not name:
                continue
            value = ""
            value_match = value_attr_re.search(attrs)
            if value_match:
                value = value_match.group(1)

            if tag == "textarea":
                sub = fragment[m.end():]
                close_m = textarea_close_re.search(sub)
                if close_m:
                    value = sub[:close_m.start()].strip()
            elif tag == "select" and not value:
                sub = fragment[m.end():]
                close_m = select_close_re.search(sub)
                select_inner = sub[:close_m.start()] if close_m else sub
                selected_m = option_selected_re.search(select_inner)
                if selected_m:
                    value = selected_m.group(1)
                else:
                    first_m = option_value_re.search(select_inner)
                    if first_m:
                        value = first_m.group(1)

            if name not in fields:
                fields[name] = value
        return fields

    # Build form ranges: for each <form>, content ends at </form> or next <form> or EOF
    form_opens = list(form_open_re.finditer(html))
    form_closes = list(form_close_re.finditer(html))
    covered_ranges = []  # (start, end) of content covered by a form

    for i, fo in enumerate(form_opens):
        form_tag = fo.group(0)
        content_start = fo.end()
        # end = closest </form> after content_start, or next <form>, or EOF
        end_pos = len(html)
        for fc in form_closes:
            if fc.start() >= content_start:
                end_pos = fc.start()
                break
        if i + 1 < len(form_opens):
            next_form_pos = form_opens[i + 1].start()
            if next_form_pos < end_pos:
                end_pos = next_form_pos
        form_content = html[content_start:end_pos]
        covered_ranges.append((fo.start(), end_pos))

        method_match = form_method_re.search(form_tag)
        method_specified = bool(method_match)
        method = (method_match.group(1) if method_match else "get").lower()
        location = "body_form" if method == "post" else "query"
        action_match = form_action_re.search(form_tag)
        form_action_url = urljoin(base_url, action_match.group(1).strip()) if action_match else base_url

        form_fields = _extract_form_fields(form_content)
        for name in form_fields.keys():
            if name and (name, location) not in seen:
                seen.add((name, location))
                params.append({
                    "location": location,
                    "name": name,
                    "value": form_fields.get(name, ""),
                    "original_value": form_fields.get(name, ""),
                    "source": "form",
                    "form_action": form_action_url,
                    "form_method": method,
                    "form_method_specified": method_specified,
                    "form_fields": dict(form_fields),
                })

    # Standalone fields outside any form block (common with JS-handled forms)
    for field_match in field_tag_re.finditer(html):
        pos = field_match.start()
        in_form = any(start <= pos < end for start, end in covered_ranges)
        if not in_form:
            attrs = field_match.group(2) or ""
            name_match = name_attr_re.search(attrs)
            if not name_match:
                continue
            name = name_match.group(1).strip()
            value_match = value_attr_re.search(attrs)
            value = value_match.group(1) if value_match else ""
            if name and (name, "body_form") not in seen:
                seen.add((name, "body_form"))
                params.append({
                    "location": "body_form",
                    "name": name,
                    "value": value,
                    "original_value": value,
                    "source": "form",
                    "form_action": base_url,
                    "form_method": "post",
                    "form_method_specified": False,
                    "form_fields": {name: value},
                })

    # Links: <a href="...?param1=&param2=value"> — extract query param names
    href_re = re.compile(r'<a\s[^>]*\bhref\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    for href_match in href_re.finditer(html):
        href = href_match.group(1).strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        if not parsed.query:
            continue
        for name in parse_qs(parsed.query, keep_blank_values=True).keys():
            if name and (name, "query") not in seen:
                seen.add((name, "query"))
                params.append({
                    "location": "query",
                    "name": name,
                    "value": "",
                    "original_value": "",
                    "source": "link",
                })

    return params


def parse_params_from_js(js_code: str) -> List[Dict[str, Any]]:
    """
    Discover parameter names from JavaScript code (e.g. SPA, dynamic forms, fetch/axios with query strings).
    Looks for: ?param= / &param= in strings, URLSearchParams.set/append, fetch/axios URLs with query params.
    Returns list of { 'location': 'query', 'name': str, 'value': '', 'original_value': '', 'source': 'js' }.
    """
    params: List[Dict[str, Any]] = []
    if not js_code:
        return params
    seen: set = set()

    # Query string in URLs: "?paramName=" or "&paramName=" (param name = identifier)
    # Matches in double/single quoted strings and template literals
    for pattern in (
        r'[\"\'`]\s*\?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
        r'[\"\'`]\s*&\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
        r'\?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[\"\'`]',
        r'&\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[\"\'`]',
        r'[\"\'`][^\"\'`]*\?([a-zA-Z_][a-zA-Z0-9_]*)=[^\"\'`]*[\"\'`]',
        r'[\"\'`][^\"\'`]*&([a-zA-Z_][a-zA-Z0-9_]*)=[^\"\'`]*[\"\'`]',
    ):
        for m in re.finditer(pattern, js_code):
            name = m.group(1)
            if name and name not in seen and len(name) < 80:
                seen.add(name)
                params.append({
                    "location": "query",
                    "name": name,
                    "value": "",
                    "original_value": "",
                    "source": "js",
                })

    # URLSearchParams: .set("paramName", ...) or .append("paramName", ...)
    for m in re.finditer(
        r'\.(?:set|append)\s*\(\s*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
        js_code,
    ):
        name = m.group(1)
        if name and name not in seen:
            seen.add(name)
            params.append({
                "location": "query",
                "name": name,
                "value": "",
                "original_value": "",
                "source": "js",
            })

    # fetch/axios/$.get etc: first argument URL with ? or & then param name
    # e.g. fetch("/api?q=" + ...), axios.get(`/api?limit=${n}`)
    url_like = re.compile(
        r'(?:fetch|axios\.(?:get|post)|\.(?:get|post|ajax))\s*\(\s*["\']([^"\']*\?[^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in url_like.finditer(js_code):
        query_part = urlparse(m.group(1)).query or m.group(1).split("?")[-1].split("#")[0]
        for name in parse_qs(query_part, keep_blank_values=True).keys():
            if name and name not in seen and len(name) < 80:
                seen.add(name)
                params.append({
                    "location": "query",
                    "name": name,
                    "value": "",
                    "original_value": "",
                    "source": "js",
                })

    # Template literal URLs: `...?param=${...}` or `...&param=`
    for m in re.finditer(r'`[^`]*\?([a-zA-Z_][a-zA-Z0-9_]*)=', js_code):
        name = m.group(1)
        if name and name not in seen:
            seen.add(name)
            params.append({
                "location": "query",
                "name": name,
                "value": "",
                "original_value": "",
                "source": "js",
            })
    for m in re.finditer(r'`[^`]*&([a-zA-Z_][a-zA-Z0-9_]*)=', js_code):
        name = m.group(1)
        if name and name not in seen:
            seen.add(name)
            params.append({
                "location": "query",
                "name": name,
                "value": "",
                "original_value": "",
                "source": "js",
            })

    return params


def get_all_fuzzable_params(
    url: str,
    method: str,
    headers: Dict,
    body_b64: Optional[str],
    response_body_b64: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Merge params from the request (query + body) and params discovered from response HTML (forms, links).
    Deduplicates by (name, location). Request params come first; then response-discovered params with same (name, location) are skipped.
    """
    from_request = parse_request_params(url, method, headers, body_b64)
    seen = {(p.get("name"), p.get("location")) for p in from_request}
    result = list(from_request)
    for p in from_request:
        if "source" not in p:
            p["source"] = "request"
    if not response_body_b64:
        return result
    try:
        body_raw = base64.b64decode(response_body_b64)
        body_str = body_raw.decode("utf-8", errors="replace")
    except Exception:
        return result
    # Discover from HTML (forms, links)
    from_html = parse_params_from_response_html(body_str, url)
    for p in from_html:
        key = (p.get("name"), p.get("location"))
        if key not in seen:
            seen.add(key)
            result.append(p)

    # Discover from JavaScript (SPA / dynamic: inline scripts and full body if JS)
    script_blocks = re.findall(r"<script(?:\s[^>]*)?>([^<]*(?:<(?!\/script>)[^<]*)*)</script>", body_str, re.IGNORECASE | re.DOTALL)
    if script_blocks:
        for block in script_blocks:
            for p in parse_params_from_js(block):
                key = (p.get("name"), p.get("location"))
                if key not in seen:
                    seen.add(key)
                    result.append(p)
    else:
        # Response might be a standalone JS file (e.g. SPA bundle or chunk)
        if "?" in body_str or "URLSearchParams" in body_str or "fetch(" in body_str or "axios" in body_str:
            for p in parse_params_from_js(body_str):
                key = (p.get("name"), p.get("location"))
                if key not in seen:
                    seen.add(key)
                    result.append(p)

    return result


def build_request_with_canary(
    url: str,
    method: str,
    headers: Dict,
    body_b64: Optional[str],
    param_location: str,
    param_name: str,
    canary: str,
) -> tuple:
    """
    Build (new_url, new_headers, new_body_bytes) with param set to canary.
    """
    new_headers = {}
    for k, v in (headers or {}).items():
        key = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
        val = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
        new_headers[key] = val

    body_raw = b""
    if body_b64:
        try:
            body_raw = base64.b64decode(body_b64)
        except Exception:
            pass

    if param_location == "query":
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [canary]
        new_query = urlencode(qs, doseq=True)
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))
        return new_url, new_headers, body_raw

    if param_location == "body_form":
        body_str = body_raw.decode("utf-8", errors="replace") if body_raw else ""
        existing_parts = [p for p in body_str.split("&") if p.strip()] if body_str.strip() else []
        found = False
        new_parts = []
        for part in existing_parts:
            if part.strip().startswith(param_name + "="):
                new_parts.append(f"{param_name}={canary}")
                found = True
            else:
                new_parts.append(part)
        if not found:
            new_parts.append(f"{param_name}={canary}")
        new_body = "&".join(new_parts).encode("utf-8", errors="replace")
        if "content-type" not in {k.lower() for k in new_headers}:
            new_headers["Content-Type"] = "application/x-www-form-urlencoded"
        return url, new_headers, new_body

    if param_location == "body_json":
        try:
            body_str = body_raw.decode("utf-8", errors="replace")
            data = json.loads(body_str)
        except Exception:
            return url, new_headers, body_raw
        if isinstance(data, dict) and param_name in data:
            data[param_name] = canary
            new_body = json.dumps(data).encode("utf-8", errors="replace")
            return url, new_headers, new_body

    return url, new_headers, body_raw


def check_reflection(
    flow_data: Dict,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
    timeout: int = 15,
) -> Dict[str, Any]:
    """
    For each request parameter, inject canary, send request through proxy, check if canary appears in response.
    flow_data: dict with request.url, request.method, request.headers, request.content_bs64 (optional),
               response.content_bs64 (optional) - if provided, we only check reflection in that response without re-sending.
    If response is provided we do not re-send; we only vary the request and need the actual response. So we must re-send.
    So we ignore response in flow_data and always re-send with canary to get the live response.
    """
    import requests

    req = flow_data.get("request") or {}
    url = req.get("url") or ""
    method = (req.get("method") or "GET").upper()
    headers = req.get("headers") or {}
    body_b64 = req.get("content")  # some APIs use content_bs64
    if body_b64 is None:
        body_b64 = req.get("content_bs64") or ""

    params_list = parse_request_params(url, method, headers, body_b64)
    if not params_list:
        return {
            "reflected": [],
            "not_reflected": [],
            "error": None,
            "message": "No injectable parameters found (query, form, or JSON body).",
        }

    proxies = {
        "http": f"http://{proxy_host}:{proxy_port}",
        "https": f"http://{proxy_host}:{proxy_port}",
    }
    reflected = []
    not_reflected = []

    for p in params_list:
        canary = _generate_canary()
        try:
            new_url, new_headers, new_body = build_request_with_canary(
                url, method, headers, body_b64,
                p["location"], p["name"], canary,
            )
        except Exception as e:
            not_reflected.append({"name": p["name"], "location": p["location"], "error": str(e)})
            continue

        try:
            if method == "GET":
                resp = requests.get(new_url, headers=new_headers, proxies=proxies, verify=False, timeout=timeout)
            elif method == "POST":
                resp = requests.post(new_url, headers=new_headers, data=new_body, proxies=proxies, verify=False, timeout=timeout)
            elif method == "PUT":
                resp = requests.put(new_url, headers=new_headers, data=new_body, proxies=proxies, verify=False, timeout=timeout)
            elif method == "PATCH":
                resp = requests.patch(new_url, headers=new_headers, data=new_body, proxies=proxies, verify=False, timeout=timeout)
            else:
                resp = requests.request(method, new_url, headers=new_headers, data=new_body, proxies=proxies, verify=False, timeout=timeout)

            resp_body = (resp.content or b"").decode("utf-8", errors="replace")
            resp_headers_str = str(resp.headers).lower() if resp.headers else ""

            in_body = canary in resp_body
            in_headers = canary in resp_headers_str

            if in_body or in_headers:
                reflected_in = []
                if in_body:
                    reflected_in.append("body")
                if in_headers:
                    reflected_in.append("headers")
                reflected.append({
                    "name": p["name"],
                    "location": p["location"],
                    "reflected_in": reflected_in,
                })
            else:
                not_reflected.append({"name": p["name"], "location": p["location"]})
        except Exception as e:
            not_reflected.append({"name": p["name"], "location": p["location"], "error": str(e)})

    return {
        "reflected": reflected,
        "not_reflected": not_reflected,
        "error": None,
        "message": f"Checked {len(params_list)} parameter(s). {len(reflected)} reflected.",
    }
