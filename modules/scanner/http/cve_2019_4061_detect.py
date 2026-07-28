#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IBM BigFix Platform 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IBM BigFix Platform - Information Disclosure Detection',
        'description': 'IBM BigFix Platform 9.2 and 9.5 contains an information disclosure vulnerability caused by not enabling authenticated access in relay, letting remote attackers query and gather update and fixlet information, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'ibm', 'bigfix', 'disclosure', 'vkev'],
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
            'https://www.atredis.com/blog/2019/3/18/harvesting-data-from-bigfix-relay-servers',
            'https://github.com/rapid7/metasploit-framework/blob/0fd8f0984e10a135c000d1fb8797d76d62fb24f7/modules/auxiliary/gather/ibm_bigfix_sites_packages_enum.rb',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-4061',
        ],
        'cve': 'CVE-2019-4061',
    }

    def run(self):
        path = '/masthead/masthead.axfm'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Organization:', '-URL:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/cgi-bin/bfenterprise/clientregister.exe?RequestType=FetchCommands'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('x-bes-command-hasiteversion:',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='IBM BigFix Platform - Information Disclosure detected', path=path)
            return True
        return False

