#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The vRealize Log Insight contains a broken access control vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VMware vRealize Log Insight - Improper Access Control to RCE Detection',
        'description': 'The vRealize Log Insight contains a broken access control vulnerability. An unauthenticated malicious actor can remotely inject code into sensitive files of an impacted appliance which can result in remote code execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'vmware', 'vrealize', 'rce', 'lfi', 'passive', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'http://packetstormsecurity.com/files/174606/VMware-vRealize-Log-Insight-Unauthenticated-Remote-Code-Execution.html',
            'https://www.vmware.com/security/advisories/VMSA-2023-0001.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-31704',
        ],
        'cve': 'CVE-2022-31704',
    }

    def run(self):
        for path in ('/i18n/component/JS?locale=en-US', '/api/v1/version'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('logInsight', 'releaseName\\',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='critical',
                    reason='VMware vRealize Log Insight - Improper Access Control to RCE detected',
                    path=path,
                )
                return True
        return False

