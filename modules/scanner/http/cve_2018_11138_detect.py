#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The '/common/download_agent_installer."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Quest KACE System Management Appliance 8.0.318 - Remote Code Execution Detection',
        'description': "The '/common/download_agent_installer.php' script in the Quest KACE System Management Appliance 8.0.318 is accessible by anonymous users and can be abused to execute arbitrary commands on the system.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'quest', 'kace', 'rce', 'kev', 'passive', 'vkev', 'vuln'],
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
            'https://www.coresecurity.com/advisories/quest-kace-system-management-appliance-multiple-vulnerabilities',
            'https://www.exploit-db.com/exploits/44950/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-11138',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-11138',
        ],
        'cve': 'CVE-2018-11138',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('kace', 'quest',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='Quest KACE System Management Appliance 8.0.318 - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

