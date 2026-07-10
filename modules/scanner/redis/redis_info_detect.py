#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Redis + récupération d'informations via INFO."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.redis.detectors import get_server_info, extract_server_details


class Module(Scanner, Tcp_scanner_client):

    __info__ = {
        "name": "Redis Info - Detect",
        "description": "Retrieves information such as version number, architecture, role, and resource usage from a Redis server.",
        "author": "DhiyaneshDK / KittySploit Team",
        "severity": "info",
        "references": [
            "https://nmap.org/nsedoc/scripts/redis-info.html",
        ],
        "metadata": {
            "max-request": 1,
            "product": "redis",
            "vendor": "redis",
        },
        "tags": ["redis", "network", "enum", "discovery"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
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
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(6379, "Target Redis port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False

        response = get_server_info(host=host, port=port, timeout=min(float(self._timeout()), 5.0))
        if not response:
            return False

        if response.startswith("-NOAUTH") or "authentication required" in response.lower():
            self.set_info(severity="info", reason="Redis detected but INFO requires authentication")
            return True

        if "redis_version:" not in response and not response.startswith("$"):
            return False

        extracted = extract_server_details(response)
        if not extracted:
            self.set_info(severity="info", reason="Redis responded to INFO")
            return True

        self.set_info(**extracted)
        return True
