#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect publicly exposed AWS Lambda Function URLs and API Gateway endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.aws.public_endpoint_detect import detect_api_gateway, detect_lambda_function_url


class Module(Scanner, Http_client):
    __info__ = {
        "name": "AWS Public Endpoint Detection",
        "description": "Detects AWS Lambda Function URLs and API Gateway execute-api endpoints.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["cloud", "scanner", "aws", "lambda", "api-gateway", "public"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    def run(self):
        for path in ("/", "/prod", "/stage", "/dev"):
            resp = self.http_request(method="GET", path=path, allow_redirects=False)
            if not resp:
                continue
            host = str(self.target or "")
            lambda_info = detect_lambda_function_url(host, resp.status_code, resp.headers, resp.text or "")
            apigw_info = detect_api_gateway(host, resp.status_code, resp.headers, resp.text or "")

            if lambda_info.get("detected"):
                severity = "high" if lambda_info.get("public_access") else "medium"
                self.set_info(
                    severity=severity,
                    reason=f"AWS Lambda Function URL detected at {path}",
                    signals=lambda_info.get("signals", []),
                )
                print_warning(f"Lambda URL signals: {', '.join(lambda_info.get('signals', []))}")
                return True

            if apigw_info.get("detected"):
                self.set_info(
                    severity="medium",
                    reason=f"AWS API Gateway detected at {path}",
                    signals=apigw_info.get("signals", []),
                )
                print_info(f"API Gateway signals: {', '.join(apigw_info.get('signals', []))}")
                return True
        return False
