#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect mDNS UDP amplification (response significantly larger than request)."""

import socket

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.mdns.client import build_query


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        'name': 'mDNS Amplification Attack Vector Detection',
        'description': (
            'Sends a unicast mDNS PTR query for _services._dns-sd._udp.local and checks '
            'whether the response is more than twice the request size, indicating the '
            'service can be abused for UDP amplification / reflection.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'mdns', 'dns-sd', 'zeroconf', 'udp', 'scanner', 'amplification',
            'ddos', 'misconfig', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 0.8,
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
                'suggested_followups': ['scanner/udp/mdns_detect', 'scanner/udp/mdns_enum'],
            },
        },
        'references': [
            'https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks',
            'https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage/Reaktion/CERT-Bund/CERT-Bund-Reports/HowTo/Offene-mDNS-Dienste/Offene-mDNS-Dienste_node.html',
            'https://kb.cert.org/vuls/id/550620',
        ],
    }

    port = OptPort(5353, 'mDNS UDP port', True)

    def run(self):
        host = self._host()
        if not host:
            return False

        req = build_query('_services._dns-sd._udp.local', qtype=12)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self._timeout())
            sock.sendto(req, (host, self._port()))
            res, _addr = sock.recvfrom(8192)
        except (socket.timeout, OSError):
            return False
        finally:
            sock.close()

        if not res or len(res) < 8:
            return False

        # Basic mDNS/DNS-SD response sanity check
        text = res.decode('latin-1', errors='ignore').lower()
        markers = ('_services', '_dns-sd', '_udp', 'local', '_tcp', '_smb', '_ftp', '_http')
        if not any(m in text for m in markers):
            return False

        req_len = len(req)
        res_len = len(res)
        if res_len > (2 * req_len):
            factor = round(res_len / float(req_len), 2)
            self.set_info(
                severity='medium',
                reason=(
                    f'mDNS amplification possible '
                    f'(request={req_len}B, response={res_len}B, factor={factor}x)'
                ),
                request_bytes=req_len,
                response_bytes=res_len,
                amplification_factor=factor,
            )
            return True
        return False
