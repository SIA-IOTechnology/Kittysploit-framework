#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Zabbix monitoring UI and JSON-RPC API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response, parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Zabbix Detection",
        "description": "Detects Zabbix frontend and apiinfo.version JSON-RPC endpoint.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "zabbix", "monitoring", "panel"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        payload = {
            "jsonrpc": "2.0",
            "method": "apiinfo.version",
            "params": {},
            "id": 1,
        }
        rpc = self.http_request(
            method="POST",
            path="/api_jsonrpc.php",
            json=payload,
            headers={"Content-Type": "application/json-rpc"},
            allow_redirects=False,
        )
        if rpc and rpc.status_code == 200:
            data, err = parse_json_response(rpc)
            if not err and isinstance(data, dict) and data.get("result"):
                self.set_info(
                    severity="info",
                    reason=f"Zabbix JSON-RPC API detected (version={data.get('result')})",
                    version=str(data.get("result")),
                )
                return True

        for path in ("/zabbix/", "/index.php"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or not is_html_response(r):
                continue
            body = (r.text or "").lower()
            if "zabbix" in body and ("sign in" in body or "zabbix sia" in body):
                self.set_info(severity="info", reason="Zabbix login UI detected", path=path)
                return True
        return False
