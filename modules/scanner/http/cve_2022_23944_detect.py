#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache ShenYu suffers from an unauthorized access vulnerability where a user can access /plugin api without au."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache ShenYu Admin Unauth Access Detection',
        'description': 'Apache ShenYu suffers from an unauthorized access vulnerability where a user can access /plugin api without authentication. This issue affected Apache ShenYu 2.4.0 and 2.4.1.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'shenyu', 'unauth', 'apache', 'vuln'],
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
            'https://github.com/apache/incubator-shenyu/pull/2462',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-23944',
            'https://github.com/cckuailong/reapoc/blob/main/2022/CVE-2022-23944/vultarget/README.md',
            'https://lists.apache.org/thread/dbrjnnlrf80dr0f92k5r2ysfvf1kr67y',
            'http://www.openwall.com/lists/oss-security/2022/01/25/15',
        ],
        'cve': 'CVE-2022-23944',
    }

    def run(self):
        r = self.http_request(method="GET", path='/plugin', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"message":"query success"', '"code":200',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Apache ShenYu Admin Unauth Access detected",
                path='/plugin',
            )
            return True
        return False

