#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Red Hat JBoss Enterprise Application Platform 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Red Hat JBoss Enterprise Application Platform - Sensitive Information Disclosure Detection',
        'description': 'Red Hat JBoss Enterprise Application Platform 4.2 before 4.2.0.CP09 and 4.3 before 4.3.0.CP08 is susceptible to sensitive information disclosure. A remote attacker can obtain sensitive information about "deployed web contexts" via a request to the status servlet, as demonstrated by a full=true query string. NOTE: this issue exists because of a CVE-2008-3273 regression.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'jboss', 'eap', 'tomcat', 'exposure', 'redhat', 'vuln'],
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
            'https://rhn.redhat.com/errata/RHSA-2010-0377.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2010-1429',
            'https://nvd.nist.gov/vuln/detail/CVE-2008-3273',
            'http://marc.info/?l=bugtraq&m=132698550418872&w=2',
            'http://securitytracker.com/id?1023918',
        ],
        'cve': 'CVE-2010-1429',
    }

    def run(self):
        r = self.http_request(method="GET", path='/status?full=true', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('JVM', 'memory', 'localhost/',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Red Hat JBoss Enterprise Application Platform - Sensitive Information Disclosure detected",
                path='/status?full=true',
            )
            return True
        return False

