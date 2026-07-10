#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AWS Lambda Function URL and API Gateway detection helpers."""

from __future__ import annotations

from typing import Dict, List, Optional


def _lower_headers(headers) -> Dict[str, str]:
    if not headers:
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def detect_lambda_function_url(host: str, status_code: Optional[int], headers, body: str) -> Dict[str, object]:
    host_l = (host or "").lower()
    hdrs = _lower_headers(headers)
    text = (body or "").lower()
    signals: List[str] = []

    if "lambda-url" in host_l and host_l.endswith(".on.aws"):
        signals.append("lambda_url_hostname")
    for key in ("x-amzn-requestid", "x-amzn-trace-id", "x-amz-request-id"):
        if key in hdrs:
            signals.append(key)
    if "awslambda" in hdrs.get("x-amzn-remapped-content-length", "").lower():
        signals.append("lambda_remapped_header")
    if status_code in (200, 403) and "message" in text and "lambda" in text:
        signals.append("lambda_error_body")

    public_access = status_code in (200, 204) and bool(signals)
    return {
        "detected": bool(signals),
        "signals": signals,
        "public_access": public_access,
        "status_code": status_code,
    }


def detect_api_gateway(host: str, status_code: Optional[int], headers, body: str) -> Dict[str, object]:
    host_l = (host or "").lower()
    hdrs = _lower_headers(headers)
    text = (body or "").lower()
    signals: List[str] = []

    if "execute-api" in host_l and ".amazonaws.com" in host_l:
        signals.append("execute_api_hostname")
    for key in ("x-amzn-requestid", "x-amz-apigw-id", "x-amzn-remapped-content-length"):
        if key in hdrs:
            signals.append(key)
    if '{"message":' in text and status_code in (403, 401, 404):
        signals.append("apigw_message_json")

    return {
        "detected": bool(signals),
        "signals": signals,
        "status_code": status_code,
    }
