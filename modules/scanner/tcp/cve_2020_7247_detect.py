#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenSMTPD MAIL FROM command injection (CVE-2020-7247)."""

import secrets

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.smtp.detectors import probe_opensmtpd_cve_2020_7247


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        'name': 'OpenSMTPD - MAIL FROM Command Injection Detection (CVE-2020-7247)',
        'description': (
            'Detects OpenSMTPD CVE-2020-7247 by sending a crafted MAIL FROM address '
            'containing shell metacharacters (MAIL FROM:<;echo TOKEN;>) and checking '
            'whether the server accepts it with a 250 Ok response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'scanner', 'tcp', 'smtp', 'opensmtpd', 'cve', 'cve2020', 'rce',
            'cmdi', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/smtp/opensmtpd_cve_2020_7247_rce'],
            },
        },
        'references': [
            'https://www.qualys.com/2020/01/28/cve-2020-7247/lpe-rce-opensmtpd.txt',
            'https://www.opensmtpd.org/security.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-7247',
        ],
        'cve': 'CVE-2020-7247',
    }

    port = OptPort(25, 'SMTP port', True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_opensmtpd_cve_2020_7247(
            host=host,
            port=port,
            timeout=max(self._timeout(), 5.0),
            token=secrets.token_hex(4),
        )
        if not info.get('vulnerable'):
            return False
        self.set_info(
            severity='critical',
            reason='OpenSMTPD accepted crafted MAIL FROM (CVE-2020-7247 indicator)',
            banner=str(info.get('banner') or '')[:120],
        )
        return True
