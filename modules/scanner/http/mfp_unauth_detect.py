#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unauthorized access to MFP (Multi-function printer) using eSCL protocol allows attackers to scan documents lef."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Multi-function Printer - Unauthorized Access Detection',
        'description': 'Unauthorized access to MFP (Multi-function printer) using eSCL protocol allows attackers to scan documents left physically in the printer and send them to an arbitrary location. Furthermore, exposure of this endpoint allows attackers to gather information about the printer, serial number, model, and possibly pull documents scanned by legitimate users.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'network', 'iot', 'printer', 'misconfig', 'escl', 'vuln'],
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
            'https://wiki.debian.org/eSCL',
            'https://support.princh.com/en/the-onboarding-process-1',
            'https://mopria.org/spec-download',
            'https://github.com/xJonathanLEI/escl-rs',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/eSCL/ScannerCapabilities', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('xmlns:pwg=', '<scan:ScannerCapabilities',)
        header_any = ('application/xml', 'text/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Multi-function Printer - Unauthorized Access detected",
                path='/eSCL/ScannerCapabilities',
            )
            return True
        return False

