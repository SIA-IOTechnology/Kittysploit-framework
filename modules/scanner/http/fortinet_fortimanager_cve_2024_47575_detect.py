#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fortinet FortiManager CVE-2024-47575 (FGFM missing auth) detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.fortimanager.detectors import probe_fgfm_cve_2024_47575
from lib.scanner.target_utils import normalize_scanner_target


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortinet FortiManager CVE-2024-47575 Detection',
        'description': (
            'Detects FortiManager and probes FGFM (TCP/541) for CVE-2024-47575 '
            'unauthenticated registration / file_exchange acceptance.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'fortinet', 'fortimanager',
            'fgfm', 'rce', 'kev', 'vkev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2024-47575',
            'https://fortiguard.fortinet.com/psirt/FG-IR-24-423',
            'https://github.com/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575',
        ],
        'cve': 'CVE-2024-47575',
    }

    fgfm_port = OptPort(541, "FGFM TCP port", False, advanced=True)

    def run(self):
        path = '/p/login/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if 'FortiManager' not in body:
            return False

        target = self.target.value if hasattr(self.target, 'value') else self.target
        host, _, _ = normalize_scanner_target(str(target or ''))
        if not host:
            return False

        timeout = self.timeout.value if hasattr(self.timeout, 'value') else self.timeout
        fgfm_port = self.fgfm_port.value if hasattr(self.fgfm_port, 'value') else self.fgfm_port
        info = probe_fgfm_cve_2024_47575(
            host=host,
            port=int(fgfm_port or 541),
            timeout=float(timeout or 8),
        )
        if not info.get('vulnerable'):
            # Panel confirmed but FGFM probe inconclusive — do not claim CVE.
            return False

        self.set_info(
            severity='critical',
            reason='FortiManager CVE-2024-47575 FGFM unauth file_exchange accepted',
            path=path,
            fgfm_port=int(fgfm_port or 541),
            remote_id=str(info.get('remote_id') or ''),
            evidence=f"FGFM remoteid={info.get('remote_id')}",
        )
        return True
