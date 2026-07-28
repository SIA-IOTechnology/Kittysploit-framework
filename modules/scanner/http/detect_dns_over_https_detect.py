#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""With DNS over HTTPS (DoH), DNS queries and responses are encrypted and sent via the HTTP or HTTP/2 protocols."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Detect DNS over HTTPS',
        'description': 'With DNS over HTTPS (DoH), DNS queries and responses are encrypted and sent via the HTTP or HTTP/2 protocols. DoH ensures that attackers cannot forge or alter DNS traffic. DoH uses port 443, which is the standard HTTPS traffic port, to wrap the DNS query in an HTTPS request. DNS queries and responses are camouflaged within other HTTPS traffic, since it all comes and goes from the same port.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misc', 'miscellaneous', 'dns', 'doh', 'vuln'],
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
            'https://developers.google.com/speed/public-dns/docs/doh/',
            'https://developers.cloudflare.com/1.1.1.1/dns-over-https/wireformat',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/dns-message',)
        header_regexes = ('(C|c)ontent-(L|l)ength: 49',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='info',
                reason="Detect DNS over HTTPS detected",
                path='/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB',
            )
            return True
        return False

