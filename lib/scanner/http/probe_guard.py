#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared guards for path-based HTTP probes (SPA catch-all rejection)."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple

from lib.scanner.http.response_validation import (
    is_html_response,
    looks_like_kubernetes_resource_list,
    looks_like_kubernetes_version,
    looks_like_spring_actuator_env,
    looks_like_spring_actuator_health,
    looks_like_spring_actuator_links,
    parse_json_response,
    response_content_type,
)


def response_signature(response) -> Dict[str, Any]:
    body = str(getattr(response, "text", "") or "")
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    return {"status": status, "length": len(body), "prefix": body[:256]}


def responses_similar(
    left,
    right,
    *,
    length_ratio: float = 0.08,
    min_abs: int = 64,
) -> bool:
    left_sig = response_signature(left)
    right_sig = response_signature(right)
    if left_sig["status"] != right_sig["status"]:
        return False
    delta = abs(int(left_sig["length"]) - int(right_sig["length"]))
    threshold = max(min_abs, int(max(left_sig["length"], right_sig["length"]) * length_ratio))
    if delta > threshold:
        return False
    return left_sig["prefix"] == right_sig["prefix"]


def is_spa_catchall(probe_response, home_response) -> bool:
    if not probe_response or not home_response:
        return False
    if is_html_response(probe_response) and responses_similar(probe_response, home_response):
        return True
    return False


def validate_json_probe(
    http_request: Callable[..., Any],
    path: str,
    validator: Callable[[Dict[str, Any]], bool],
    *,
    home_path: str = "/",
    method: str = "GET",
    **request_kwargs: Any,
) -> Tuple[Optional[Dict[str, Any]], Any]:
    home = http_request(method="GET", path=home_path, allow_redirects=False)
    probe = http_request(method=method, path=path, allow_redirects=False, **request_kwargs)
    if not probe or int(getattr(probe, "status_code", 0) or 0) != 200:
        return None, None
    if is_spa_catchall(probe, home):
        return None, None
    data, err = parse_json_response(probe)
    if err or not data or not validator(data):
        return None, None
    return data, probe


def looks_like_kubernetes_node_list(data: Dict[str, Any]) -> bool:
    if not looks_like_kubernetes_resource_list(data):
        return False
    if str(data.get("kind") or "") != "NodeList":
        return False
    items = data.get("items")
    if not isinstance(items, list):
        return False
    if not items:
        return True
    first = items[0]
    return isinstance(first, dict) and "metadata" in first and "status" in first


def looks_like_kubernetes_namespace_list(data: Dict[str, Any]) -> bool:
    if not looks_like_kubernetes_resource_list(data):
        return False
    return str(data.get("kind") or "") == "NamespaceList"


def looks_like_kubernetes_secret_list(data: Dict[str, Any]) -> bool:
    if not looks_like_kubernetes_resource_list(data):
        return False
    return str(data.get("kind") or "") == "SecretList"


def looks_like_kubernetes_service_list(data: Dict[str, Any]) -> bool:
    if not looks_like_kubernetes_resource_list(data):
        return False
    return str(data.get("kind") or "") == "ServiceList"


def looks_like_prometheus_config_api(data: Dict[str, Any]) -> bool:
    if str(data.get("status") or "").lower() != "success":
        return False
    payload = data.get("data")
    if not isinstance(payload, dict):
        return False
    yaml_text = str(payload.get("yaml") or "")
    return bool(yaml_text.strip()) and ("global:" in yaml_text or "scrape_configs:" in yaml_text)


def looks_like_apache_storm_summary(data: Dict[str, Any]) -> bool:
    return isinstance(data.get("totalMem"), (int, float)) and bool(str(data.get("stormVersion") or "").strip())


def looks_like_netdata_info(data: Dict[str, Any]) -> bool:
    version = str(data.get("version") or "")
    if not version:
        return False
    return any(key in data for key in ("cloud_enabled", "os_name", "mirrored_hosts", "hosts_available"))


def looks_like_localstack_health(data: Dict[str, Any]) -> bool:
    services = data.get("services")
    return isinstance(services, dict) and bool(services)


def looks_like_jolokia_version(data: Dict[str, Any]) -> bool:
    protocol = str(data.get("protocol") or "")
    agent = str(data.get("agent") or "")
    if protocol and agent:
        return True
    info = data.get("info")
    return isinstance(info, dict) and bool(info.get("agent"))


def looks_like_spring_loggers(data: Dict[str, Any]) -> bool:
    loggers = data.get("loggers")
    return isinstance(loggers, dict) and bool(loggers)


def is_spring_json_response(response) -> bool:
    ctype = response_content_type(response)
    return any(token in ctype for token in ("application/json", "application/vnd.spring-boot"))


def validate_spring_json_probe(
    http_request: Callable[..., Any],
    paths: Tuple[str, ...],
    validator: Callable[[Dict[str, Any]], bool],
) -> Tuple[Optional[str], Any]:
    home = http_request(method="GET", path="/", allow_redirects=False)
    for path in paths:
        probe = http_request(method="GET", path=path, allow_redirects=False)
        if not probe or int(getattr(probe, "status_code", 0) or 0) != 200:
            continue
        if not is_spring_json_response(probe):
            continue
        if is_spa_catchall(probe, home):
            continue
        data, err = parse_json_response(probe)
        if err or not data or not validator(data):
            continue
        return path, probe
    return None, None


__all__ = [
    "is_spa_catchall",
    "looks_like_apache_storm_summary",
    "looks_like_jolokia_version",
    "looks_like_kubernetes_namespace_list",
    "looks_like_kubernetes_node_list",
    "looks_like_kubernetes_secret_list",
    "looks_like_kubernetes_service_list",
    "looks_like_localstack_health",
    "looks_like_netdata_info",
    "looks_like_prometheus_config_api",
    "looks_like_spring_loggers",
    "responses_similar",
    "response_signature",
    "validate_json_probe",
    "validate_spring_json_probe",
]
