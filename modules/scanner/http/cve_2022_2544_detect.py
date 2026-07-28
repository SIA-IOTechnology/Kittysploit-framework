#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Ninja Job Board plugin prior to 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Ninja Job Board < 1.3.3 - Direct Request Detection',
        'description': 'WordPress Ninja Job Board plugin prior to 1.3.3 is susceptible to a direct request vulnerability. The plugin does not protect the directory where it stores uploaded resumes, making it vulnerable to unauthenticated directory listing which allows the download of uploaded resumes.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'ninja', 'exposure', 'wpscan', 'wordpress', 'wp-plugin', 'wp', 'wpmanageninja', 'vuln'],
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
            'https://plugins.trac.wordpress.org/changeset/2758420/ninja-job-board/trunk/includes/Classes/File/FileHandler.php?old=2126467&old_path=ninja-job-board%2Ftrunk%2Fincludes%2FClasses%2FFile%2FFileHandler.php',
            'https://wpscan.com/vulnerability/a9bcc68c-eeda-4647-8463-e7e136733053',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2544',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-2544',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-2544',
    }

    def run(self):
        for path in ('/wp/wp-content/uploads/wpjobboard/', '/wp-content/uploads/wpjobboard/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('Index of /wp/wp-content/uploads/wpjobboard', 'Index of /wp-content/uploads/wpjobboard',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="WordPress Ninja Job Board < 1.3.3 - Direct Request detected",
                    path=path,
                )
                return True
        return False

