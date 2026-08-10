#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenMRS REST concept endpoint XStream RCE fingerprint (CVE-2018-19276)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenMRS - REST concept XStream RCE Fingerprint (CVE-2018-19276)',
        'description': (
            'Soft-detects CVE-2018-19276 by POSTing empty body with '
            'Content-Type: text/xml to /ws/rest/v1/concept and looking for XStream / '
            'unmarshal related errors (full RCE check needs outbound ICMP).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'openmrs', 'rce', 'xstream', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2018-19276'],
        'cve': 'CVE-2018-19276',
    }

    base_path = OptString('', 'Optional OpenMRS base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        path = f'{self._prefix()}/ws/rest/v1/concept'
        # Minimal XStream gadget probe without outbound callbacks: look for processing of XML map
        data = (
            '<map>\r\n  <entry>\r\n    <jdk.nashorn.internal.objects.NativeString>\r\n'
            '      <flags>0</flags>\r\n      <value>\r\n'
            '        <string>ksploit</string>\r\n      </value>\r\n'
            '    </jdk.nashorn.internal.objects.NativeString>\r\n'
            '    <string>test</string>\r\n  </entry>\r\n</map>'
        )
        r = self.http_request(
            method='POST',
            path=path,
            data=data,
            headers={'Content-Type': 'text/xml'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = (r.text or '').lower()
        # Vulnerable instances often return 500 with xstream / conversion hints
        markers = ('xstream', 'nativestring', 'cannot cast', 'conversionexception', 'unmarshall')
        if r.status_code in (500, 400) and any(m in body for m in markers):
            self.set_info(
                severity='critical',
                reason='OpenMRS REST XStream fingerprint (CVE-2018-19276)',
                path=path,
            )
            return True
        # Empty POST may also elicit distinctive errors on older builds
        r2 = self.http_request(
            method='POST',
            path=path,
            data='',
            headers={'Content-Type': 'text/xml'},
            allow_redirects=False,
        )
        if r2 and r2.status_code in (500, 400):
            b2 = (r2.text or '').lower()
            if any(m in b2 for m in ('xstream', 'unmarshall', 'xmldecoder')):
                self.set_info(
                    severity='high',
                    reason='OpenMRS REST XML deserialize surface (CVE-2018-19276 soft)',
                    path=path,
                )
                return True
        return False
