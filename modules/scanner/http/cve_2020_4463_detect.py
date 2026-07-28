#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IBM Maximo Asset Management is vulnerable to an XML external entity injection (XXE) attack when processing XML."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IBM Maximo Asset Management Information Disclosure - XML External Entity Injection Detection',
        'description': 'IBM Maximo Asset Management is vulnerable to an XML external entity injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'ibm', 'xxe', 'disclosure', 'vkev', 'vuln'],
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
            'https://www.ibm.com/support/pages/security-bulletin-ibm-maximo-asset-management-vulnerable-information-disclosure-cve-2020-4463',
            'https://github.com/Ibonok/CVE-2020-4463',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/181484',
            'https://www.ibm.com/support/pages/node/6253953',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-4463',
        ],
        'cve': 'CVE-2020-4463',
    }

    def run(self):
        for path in ('/os/mxperson', '/meaweb/os/mxperson'):
            r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/xml'}, data="<?xml version='1.0' encoding='UTF-8'?>\n<max:QueryMXPERSON xmlns:max='http://www.ibm.com/maximo'>\n  <max:MXPERSONQuery></max:MXPERSONQuery>\n</max:QueryMXPERSON>\n")
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('QueryMXPERSONResponse', 'MXPERSONSet',)
            header_any = ('application/xml',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason='IBM Maximo Asset Management Information Disclosure - XML External Entity Injection detected',
                    path=path,
                )
                return True
        return False

